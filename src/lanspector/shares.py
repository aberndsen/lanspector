"""Windows SMB fileshare and Active Directory domain discovery utilities."""

from __future__ import annotations

import json
import pathlib
import socket
import sys
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from loguru import logger

from lanspector.constants import SID_TYPES, SMB_PORT
from lanspector.platform import HAS_WIN32, is_hostname, is_ip_address, smb_socket_connect

if sys.platform == "win32" and HAS_WIN32:  # pragma: no cover - Windows-only
    import win32com.client as _win32com_client
    import win32net as _win32net
    import win32netcon as _win32netcon
    import win32security as _win32security
else:
    _win32com_client: Any = None
    _win32net: Any = None
    _win32netcon: Any = None
    _win32security: Any = None


# ---------------------------------------------------------------------------
# Primary public routines
# ---------------------------------------------------------------------------


def list_all_shares_in_domain(
    domains: str | Sequence[str],
    test_connectivity: bool = False,
    get_share_permissions: bool = False,
    skip_admin_shares: bool = True,
    max_workers: int = 8,
) -> list[dict[str, Any]]:
    """Discover computers across *domains* and enumerate their SMB shares.

    Parameters
    ----------
    domains
        Single domain name (or comma-separated string) or sequence of domain names.
    test_connectivity
        Filter unreachable hosts using TCP port 445 probing before listing shares.
    get_share_permissions
        Include share-level ACL principals for each discovered share.
    skip_admin_shares
        Skip administrative shares containing ``$``.
    max_workers
        Maximum concurrent worker threads.

    Returns
    -------
    list[dict[str, Any]]
        List of discovered share records (empty on non-Windows platforms).
    """
    domain_list = (
        [d.strip() for d in domains.split(",") if d.strip()]
        if isinstance(domains, str)
        else [str(d).strip() for d in domains if str(d).strip()]
    )
    if not domain_list:
        return []

    records: list[dict[str, Any]] = []
    for dn in domain_list:
        records.extend(list_servers_in_domain(dn))

    if test_connectivity and records:
        alive: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=max(1, max_workers)) as pool:
            futures = [pool.submit(port_scan, rec) for rec in records]
            for fut in as_completed(futures):
                result = fut.result()
                if result.get("connection"):
                    alive.append(result)
        records = alive

    if not records:
        return []
    return list_shares(
        records=records,
        get_share_permissions=get_share_permissions,
        skip_admin_shares=skip_admin_shares,
        max_workers=max_workers,
    )


def list_shares(
    servers: str | Sequence[str] | None = None,
    domain: str | None = None,
    records: Sequence[dict[str, Any]] | None = None,
    sharetype: int | None = None,
    get_share_permissions: bool = True,
    skip_admin_shares: bool = True,
    max_workers: int = 8,
    checkpoint_file: str | pathlib.Path | None = None,
) -> list[dict[str, Any]]:
    """Enumerate SMB shares across one or more Windows fileservers.

    Parameters
    ----------
    servers
        Single server name (or comma-separated string) or sequence of server names.
    domain
        Optional domain label associated with *servers*.
    records
        Optional sequence of ``{"domain": ..., "server": ...}`` dicts.
    sharetype
        Optional Win32 share type filter (``0`` = disk share).
    get_share_permissions
        Query level-502 security descriptors and expand per-ACL rows when ``True``.
    skip_admin_shares
        Skip shares whose name contains ``$``.
    max_workers
        Maximum concurrent probing threads.
    checkpoint_file
        Optional JSON checkpoint path to resume interrupted multi-server scans.

    Returns
    -------
    list[dict[str, Any]]
        List of share metadata dicts (empty on non-Windows platforms).
    """
    to_probe: list[dict[str, Any]] = []
    if isinstance(servers, str):
        to_probe.extend(
            {"domain": domain or "", "server": s.strip()} for s in servers.split(",") if s.strip()
        )
    elif servers is not None:
        to_probe.extend({"domain": domain or "", "server": str(s)} for s in servers)
    if records is not None:
        to_probe.extend(dict(r) for r in records)

    if not to_probe:
        return []

    if not HAS_WIN32:
        logger.warning("SMB share enumeration requires Windows with pywin32 installed.")
        return []

    results: list[dict[str, Any]] = []
    scanned_keys: set[tuple[str, str]] = set()
    ckpt = pathlib.Path(checkpoint_file) if checkpoint_file is not None else None
    if ckpt is not None and ckpt.exists():
        results = json.loads(ckpt.read_text(encoding="utf-8"))
        scanned_keys = {(str(r.get("domain", "")), str(r.get("server", ""))) for r in results}

    pending = [
        rec
        for rec in to_probe
        if (str(rec.get("domain", "")), str(rec.get("server", ""))) not in scanned_keys
    ]
    info_level = 502 if get_share_permissions else 1

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(pending)))) as pool:
        futures = [
            pool.submit(
                _probe_server_shares,
                str(rec.get("server", "")),
                str(rec.get("domain", "")),
                info_level,
                get_share_permissions,
                sharetype,
                skip_admin_shares,
            )
            for rec in pending
        ]
        for idx, fut in enumerate(as_completed(futures), start=1):
            results.extend(fut.result())
            if ckpt is not None and idx % 25 == 0:
                ckpt.write_text(json.dumps(results), encoding="utf-8")

    if ckpt is not None:
        ckpt.write_text(json.dumps(results), encoding="utf-8")
    return results


# ---------------------------------------------------------------------------
# Supporting public routines (alphabetical)
# ---------------------------------------------------------------------------


def crawl_all_shares_on_fileserver(
    server: str,
    out_dir: str | pathlib.Path = ".",
    skip_admin_shares: bool = True,
    generate_summary: bool = True,
    limit: int = 500,
) -> list[pathlib.Path]:
    """Crawl every accessible share on *server* and save ``<server>_<share>.db``.

    Parameters
    ----------
    server
        Fileserver hostname or FQDN.
    out_dir
        Directory in which to store crawl databases and Excel summaries.
    skip_admin_shares
        Skip administrative shares ending in ``$``.
    generate_summary
        Generate a companion ``.xlsx`` audit report for each crawled share.
    limit
        Row limit forwarded to Excel report generation.

    Returns
    -------
    list[pathlib.Path]
        Paths to generated SQLite crawl databases.
    """
    from lanspector.crawler import crawl
    from lanspector.reporting import generate_fileshare_report

    dest = pathlib.Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    db_paths: list[pathlib.Path] = []
    for share in list_shares(
        servers=[server], get_share_permissions=False, skip_admin_shares=skip_admin_shares
    ):
        netname = str(share.get("netname", ""))
        if not netname or (skip_admin_shares and netname.endswith("$")):
            continue
        unc = f"\\\\{server}\\{netname}"
        db_file = dest / f"{server}_{netname}.db"
        try:
            crawl(unc, fout=db_file)
            db_paths.append(db_file)
            if generate_summary:
                generate_fileshare_report(db_file, dest / f"{server}_{netname}.xlsx", limit=limit)
        except Exception as exc:
            logger.error("Failed crawling {}: {}", unc, exc)
    return db_paths


def list_servers_in_domain(domain: str = "", server: str = "") -> list[dict[str, str]]:
    """List Windows computers registered in Active Directory *domain*.

    Parameters
    ----------
    domain
        Active Directory domain name (empty string uses the current domain).
    server
        Optional domain controller hostname.

    Returns
    -------
    list[dict[str, str]]
        List of ``{"domain": ..., "server": ...}`` dicts (empty on non-Windows).
    """
    if not HAS_WIN32:
        logger.warning("Domain server enumeration requires Windows with pywin32 installed.")
        return []
    return _win32_list_servers_in_domain(domain=domain, server=server)  # pragma: no cover


def port_scan(
    server: str | dict[str, Any], port: int = SMB_PORT, timeout: float = 2.0
) -> dict[str, Any]:
    """Probe TCP connectivity to *server* on SMB *port* and enrich its record.

    Parameters
    ----------
    server
        Hostname/IP string or record dict containing ``"server"`` and optional ``"domain"``.
    port
        TCP port to probe (default ``445``).
    timeout
        Connection timeout in seconds.

    Returns
    -------
    dict[str, Any]
        Record dictionary with ``server``, ``port``, ``fqdn``, and ``connection`` keys.
    """
    rec: dict[str, Any] = (
        {"server": server, "port": port} if isinstance(server, str) else dict(server)
    )
    rec.setdefault("port", port)
    host = str(rec.get("server", ""))
    fqdn = str(rec.get("fqdn") or _resolve_fqdn(host))
    rec["fqdn"] = fqdn
    rec["connection"] = smb_socket_connect(fqdn, port=int(rec["port"]), timeout=timeout)
    return rec


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _probe_server_shares(
    server: str,
    domain: str,
    info_level: int,
    get_share_permissions: bool,
    sharetype: int | None,
    skip_admin_shares: bool,
) -> list[dict[str, Any]]:  # pragma: no cover - Windows-only
    """Enumerate SMB shares on a single server via Win32 NetShareEnum."""
    fqdn = _resolve_fqdn(server)
    resume = 0
    collected: list[dict[str, Any]] = []
    while True:
        try:
            shares, _total, resume = _win32net.NetShareEnum(
                fqdn, info_level, resume, _win32netcon.MAX_PREFERRED_LENGTH
            )
        except Exception as exc:
            logger.error("NetShareEnum failed on {}\\{}: {}", domain, server, exc)
            break

        for share in shares:
            netname = str(share.get("netname", ""))
            if skip_admin_shares and "$" in netname:
                continue
            share["server"] = server
            share["domain"] = domain
            share["fqdn"] = fqdn
            sd = share.pop("security_descriptor", None)
            share.pop("permission", None)

            if get_share_permissions and sd is not None:
                dacl = sd.GetSecurityDescriptorDacl()
                if dacl is not None:
                    for idx in range(dacl.GetAceCount()):
                        ace = dacl.GetAce(idx)
                        try:
                            name, dom, sid_type = _win32security.LookupAccountSid(None, ace[2])
                            type_label = SID_TYPES.get(sid_type, str(sid_type))
                        except Exception:
                            name, dom, type_label = str(ace[2]).split("PySID:")[-1], "", "dead"
                        row = dict(share)
                        row["ACLName"] = name
                        row["ACLDomain"] = dom
                        row["ACLtype"] = type_label
                        collected.append(row)
                    continue
            collected.append(share)

        if not resume:
            break

    if sharetype is not None:
        return [s for s in collected if s.get("type") == sharetype]
    return collected


def _resolve_fqdn(host: str) -> str:
    """Resolve bare *host* to its FQDN when DNS lookup succeeds."""
    if not host or is_ip_address(host) or not is_hostname(host):
        return host
    try:
        return socket.gethostbyname_ex(host)[0]
    except OSError:
        return host


def _win32_list_servers_in_domain(
    domain: str, server: str
) -> list[dict[str, str]]:  # pragma: no cover
    """Enumerate domain-joined servers via NetServerEnum with ADSI fallback."""
    computers: list[dict[str, str]] = []
    resume = 0
    while True:
        try:
            objs, _total, resume = _win32net.NetServerEnum(
                server, 100, _win32netcon.SV_TYPE_ALL, domain, resume, -1
            )
        except Exception as exc:
            logger.debug("NetServerEnum failed for domain {}: {}", domain, exc)
            break
        computers.extend({"domain": domain, "server": str(o["name"])} for o in objs)
        if not resume:
            break

    if not computers and _win32com_client is not None:
        try:
            adsi = _win32com_client.Dispatch("ADsNameSpaces")
            nt = adsi.GetObject("", "WinNT:")
            result = nt.OpenDSObject(f"WinNT://{domain}", "", "", 0)
            result.Filter = ["computer"]
            computers.extend({"domain": domain, "server": str(item.Name)} for item in result)
        except Exception as exc:
            logger.warning("ADSI fallback failed for domain {}: {}", domain, exc)
    return computers
