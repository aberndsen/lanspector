"""OS-abstracted ownership, ACL harvesting, NTFS bitmasks, and path/network helpers.

On Windows (when ``pywin32`` is installed), LANspector uses the Win32 Security and
NetAPI interfaces for full NTFS DACL, SMB share, and Active Directory group
harvesting. On POSIX platforms (Linux and macOS), LANspector provides a consistent
fallback built on :func:`os.lstat`, :mod:`pwd`, and :mod:`grp` so local crawling,
SOX permission-diff analysis, Excel reporting, and testing run identically everywhere.
"""

from __future__ import annotations

import contextlib
import datetime
import os
import pathlib
import re
import socket
import stat
import sys
from typing import IO, Any

import numpy as np
import pandas as pd
from loguru import logger

from lanspector.constants import (
    DACL_ACCESS_MASKS,
    IP_REGEX,
    MAX_WIN32_PATH,
    NTFS_BITMASK_MAP,
    PERM_BIT_ADD_READ,
    PERM_BIT_CHANGE,
    PERM_BIT_FULL,
    PERM_BIT_OTHER,
    PERM_BIT_READ,
    PERM_BIT_SPECIAL,
    SID_TYPES,
    SMB_PORT,
)
from lanspector.datatypes import PermissionEntry, SharePermissionEntry

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - Windows
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

HAS_WIN32 = False
_win32security: Any = None
_win32net: Any = None
_win32netcon: Any = None
_pywintypes: Any = None

if sys.platform == "win32":  # pragma: no cover - Windows-only bindings
    try:
        import pywintypes as _pywintypes
        import win32net as _win32net
        import win32netcon as _win32netcon
        import win32security as _win32security

        HAS_WIN32 = True
    except ImportError:
        HAS_WIN32 = False


# ---------------------------------------------------------------------------
# Primary public routines
# ---------------------------------------------------------------------------


def get_path_owner(path: str) -> str:
    """Return the account name owning *path*.

    Parameters
    ----------
    path
        Filesystem path to inspect.

    Returns
    -------
    str
        Owner account name, ``"Dead:<SID>"`` for unresolved Windows SIDs, or
        ``"AccessDenied"`` when permissions prevent inspection.
    """
    if HAS_WIN32:  # pragma: no cover - Windows-only
        return _win32_owner(path)
    return _posix_owner(path)


def get_effective_permissions(path: str, domain: str | None = None) -> list[PermissionEntry]:
    """Return normalized effective permissions on *path*.

    Parameters
    ----------
    path
        Filesystem path (file or directory) to inspect.
    domain
        Optional Windows domain hint passed to ``LookupAccountSid``.

    Returns
    -------
    list[PermissionEntry]
        Normalized ACL entries for the object (empty list on error).
    """
    if HAS_WIN32:  # pragma: no cover - Windows-only
        return _win32_effective_permissions(path, domain=domain)
    return _posix_effective_permissions(path)


def get_fileshare_permissions(path: str) -> list[SharePermissionEntry]:
    """Harvest SMB share-level permissions for a UNC path.

    Parameters
    ----------
    path
        Local or UNC path (e.g. ``\\\\server\\share\\subdir``).

    Returns
    -------
    list[SharePermissionEntry]
        Share-level ACL entries on Windows UNC paths; empty list on POSIX or local paths.
    """
    if not HAS_WIN32:
        return []
    return _win32_fileshare_permissions(path)  # pragma: no cover - Windows-only


def get_group_membership(
    domain: str,
    group: str,
    acl_type: str = "Group",
    resolve_nests: bool = True,
    nest_name: str = "",
    scan_date: datetime.datetime | None = None,
) -> pd.DataFrame:
    """Resolve Active Directory group membership for *group* in *domain*.

    Parameters
    ----------
    domain
        Active Directory domain or NetBIOS name.
    group
        Security group or local alias name.
    acl_type
        Account category (``"Group"`` or ``"Alias"``).
    resolve_nests
        Recursively expand nested groups when ``True``.
    nest_name
        Internal prefix tracking nested group ancestry.
    scan_date
        Optional timestamp recorded alongside membership rows.

    Returns
    -------
    pandas.DataFrame
        Membership table (empty DataFrame on POSIX or when Win32 APIs are unavailable).
    """
    if not HAS_WIN32:
        logger.debug(
            "Skipping Active Directory group lookup for {}\\{} (non-Windows).", domain, group
        )
        return pd.DataFrame()
    return _win32_group_membership(  # pragma: no cover - Windows-only
        domain=domain,
        group=group,
        acl_type=acl_type,
        resolve_nests=resolve_nests,
        nest_name=nest_name,
        scan_date=scan_date,
    )


def ntfs_to_bitmask(permission: object) -> int:
    """Map a human-readable NTFS or POSIX permission string to a power-of-two bitmask.

    Parameters
    ----------
    permission
        Permission label (e.g. ``"Read(RX)"``, ``"Change"``, ``"Full Control(All)"``).

    Returns
    -------
    int
        Bitmask integer enabling additive/bitwise aggregation in pivot tables.
    """
    if permission is None or (isinstance(permission, float) and np.isnan(permission)):
        return 0
    return NTFS_BITMASK_MAP.get(str(permission), PERM_BIT_OTHER)


def bitmask_to_code(mask: object) -> str | None:
    """Decode an aggregated permission bitmask back into compact audit codes.

    Codes follow standard LANspector notation:
    ``R`` (Read), ``A`` (Add), ``M`` (Modify/Change), ``S`` (Special), ``F`` (Full Control).

    Parameters
    ----------
    mask
        Aggregated integer bitmask produced by :func:`ntfs_to_bitmask`.

    Returns
    -------
    str or None
        Compact permission string, or ``None`` when no permission bits are set.
    """
    if mask is None or pd.isna(mask):
        return None
    if not isinstance(mask, (int, float, str, np.integer, np.floating)):
        return None
    val = int(mask)
    if val <= 0:
        return None
    codes: list[str] = []
    if val & PERM_BIT_READ:
        codes.append("R")
    if val & PERM_BIT_ADD_READ:
        codes.append("A")
        if "R" not in codes:
            codes.append("R")
    if val & PERM_BIT_CHANGE:
        codes.append("M")
    if val & PERM_BIT_SPECIAL:
        codes.append("S")
    if val & PERM_BIT_FULL:
        codes.append("F")
    if not codes or (val & PERM_BIT_OTHER):
        return "S"
    return "".join(codes)


def reduce_permission_hierarchy(series: pd.Series) -> pd.Series:
    """Collapse subordinate permission bits so only the highest effective bit remains.

    Parameters
    ----------
    series
        Numeric permission bitmask column.

    Returns
    -------
    pandas.Series
        Integer Series where each non-zero entry is reduced to its highest power-of-two bit
        (capped at :data:`~lanspector.constants.PERM_BIT_FULL`).
    """
    values = series.to_numpy(dtype=np.int64, copy=True)
    values = np.minimum(values, PERM_BIT_FULL)
    out = np.zeros_like(values)
    positive = values > 0
    if np.any(positive):
        out[positive] = np.power(2, np.floor(np.log2(values[positive]))).astype(np.int64)
    return pd.Series(out, index=series.index, dtype="int64")


# ---------------------------------------------------------------------------
# Supporting utilities (alphabetical)
# ---------------------------------------------------------------------------


def clean_long_path(path: str) -> str:
    """Prefix long Windows paths (>255 chars) with ``\\\\?\\`` or ``\\\\?\\UNC\\``.

    Parameters
    ----------
    path
        Filesystem path to normalize.

    Returns
    -------
    str
        Long-path-safe path string on Windows, or unchanged *path* if already short/prefixed.
    """
    if path.startswith("\\\\?\\"):
        return path
    if len(path) <= MAX_WIN32_PATH:
        return path
    if re.match(r"^[A-Za-z]:[\\/]", path):
        return "\\\\?\\" + path
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path.lstrip("\\")
    return path


def extract_domain_host_share_subdir(path: str) -> tuple[str, str, str, str]:
    """Parse a UNC or local path into ``(domain, host, share, subdir)`` components.

    Parameters
    ----------
    path
        UNC path (e.g. ``\\\\host.domain.local\\share\\folder``) or local path.

    Returns
    -------
    tuple[str, str, str, str]
        Four-tuple of ``(domain, host, share, subdir)``.
    """
    normalized = path.replace("/", "\\").strip()
    if normalized.startswith("\\\\"):
        parts = [p for p in normalized.lstrip("\\").split("\\") if p]
        server = parts[0] if parts else "local"
        share = parts[1] if len(parts) > 1 else ""
        subdir = "\\".join(parts[2:]) if len(parts) > 2 else ""
        if "." in server and not is_ip_address(server):
            host, domain = server.split(".", 1)
        else:
            host, domain = server, "LOCAL"
        return domain, host, share, subdir

    parts = [p for p in path.replace("\\", "/").split("/") if p]
    share = parts[0] if parts else "root"
    subdir = "/".join(parts[1:]) if len(parts) > 1 else ""
    return "LOCAL", socket.gethostname(), share, subdir


def is_hostname(host: str) -> bool:
    """Return ``True`` if *host* is a bare hostname without domain dots.

    Parameters
    ----------
    host
        Hostname or FQDN string.

    Returns
    -------
    bool
        ``True`` when *host* contains no internal dot separator.
    """
    cleaned = host[:-1] if host.endswith(".") else host
    return "." not in cleaned


def is_ip_address(address: str) -> bool:
    """Return ``True`` if *address* is a valid IPv4 address string.

    Parameters
    ----------
    address
        Candidate IPv4 address.

    Returns
    -------
    bool
        ``True`` when *address* matches dotted-quad IPv4 format.
    """
    return IP_REGEX.match(address) is not None


def open_read_noatime(
    path: str | pathlib.Path,
    *,
    binary: bool = True,
    encoding: str | None = None,
    errors: str | None = None,
) -> IO[Any]:
    """Open *path* for reading without updating ``atime`` when the OS supports ``O_NOATIME``.

    On Linux filesystems mounted with ``relatime`` or ``strictatime``, reading files
    for MD5 hashing or PII scanning with plain :func:`open` updates ``atime`` on disk.
    Using ``os.O_NOATIME`` preserves original access timestamps when permitted, falling
    back gracefully to :func:`open` if ``O_NOATIME`` is unavailable or disallowed.

    Parameters
    ----------
    path
        Filesystem path to open for reading.
    binary
        Open in binary mode (``"rb"``) when ``True``, otherwise text mode (``"r"``).
    encoding
        Optional text encoding used when ``binary=False``.
    errors
        Optional error handler used when ``binary=False``.

    Returns
    -------
    typing.IO[typing.Any]
        Open readable file object.
    """
    noatime_flag = getattr(os, "O_NOATIME", 0)
    if noatime_flag:
        try:
            fd = os.open(path, os.O_RDONLY | noatime_flag)
            if binary:
                return os.fdopen(fd, "rb")
            return os.fdopen(fd, "r", encoding=encoding, errors=errors)
        except OSError:
            pass
    if binary:
        return open(path, "rb")
    return open(path, encoding=encoding, errors=errors)


def smb_socket_connect(server: str, port: int = SMB_PORT, timeout: float = 2.0) -> bool:
    """Test TCP connectivity to *server* on SMB *port* (default 445).

    Parameters
    ----------
    server
        Hostname, FQDN, or IPv4 address.
    port
        TCP port to probe (defaults to ``445``).
    timeout
        Socket connection timeout in seconds.

    Returns
    -------
    bool
        ``True`` if the TCP handshake succeeded, ``False`` otherwise.
    """
    try:
        with socket.create_connection((server, port), timeout=timeout):
            return True
    except OSError:
        return False


def strip_long_path_prefix(path: str) -> str:
    """Remove Win32 ``\\\\?\\UNC\\`` or ``\\\\?\\`` prefixes from *path*.

    Parameters
    ----------
    path
        Path potentially starting with a Win32 extended-length prefix.

    Returns
    -------
    str
        Standard path without extended-length prefix.
    """
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[len("\\\\?\\UNC\\") :]
    if path.startswith("\\\\?\\"):
        return path[len("\\\\?\\") :]
    return path


def subdir_fqdn_to_hostname(subdir: str) -> tuple[bool, str]:
    """Strip the domain suffix from the server portion of a UNC path if present.

    Parameters
    ----------
    subdir
        UNC path such as ``\\\\filesrv01.corp.example\\data\\reports``.

    Returns
    -------
    tuple[bool, str]
        ``(was_fqdn, updated_path)`` indicating whether an FQDN was shortened.
    """
    normalized = subdir.replace("/", "\\")
    match = re.match(r"^\\\\([^\\]+)(.*)$", normalized)
    if not match:
        return False, subdir
    server, remainder = match.group(1), match.group(2)
    if "." in server and not is_ip_address(server):
        hostname = server.split(".", 1)[0]
        return True, f"\\\\{hostname}{remainder}"
    return False, subdir


# ---------------------------------------------------------------------------
# Internal OS backends
# ---------------------------------------------------------------------------


def _posix_mode_to_permission(
    mode: int, read_bit: int, write_bit: int, exec_bit: int
) -> str | None:
    """Convert POSIX rwx mode bits for one principal class into a normalized permission string."""
    can_read = bool(mode & read_bit)
    can_write = bool(mode & write_bit)
    can_exec = bool(mode & exec_bit)
    if not (can_read or can_write or can_exec):
        return None
    if can_read and can_write and can_exec:
        return "Full Control(All)"
    if can_read and can_write:
        return "Change"
    if can_write:
        return "Add"
    if can_read:
        return "Read(RX)"
    return "Special"


def _posix_owner(path: str) -> str:
    """Resolve owner username via POSIX lstat/pwd."""
    try:
        st = os.lstat(path)
    except OSError:
        return "AccessDenied"
    if pwd is not None:
        try:
            return pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            pass
    return str(st.st_uid)


def _posix_effective_permissions(path: str) -> list[PermissionEntry]:
    """Build normalized PermissionEntry records from POSIX mode bits."""
    try:
        st = os.lstat(path)
    except OSError:
        return []

    owner_name = str(st.st_uid)
    if pwd is not None:
        with contextlib.suppress(KeyError):
            owner_name = pwd.getpwuid(st.st_uid).pw_name

    group_name = str(st.st_gid)
    if grp is not None:
        with contextlib.suppress(KeyError):
            group_name = grp.getgrgid(st.st_gid).gr_name

    mode = stat.S_IMODE(st.st_mode)
    entries: list[PermissionEntry] = []

    owner_perm = _posix_mode_to_permission(mode, stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR)
    if owner_perm:
        entries.append(
            PermissionEntry(
                domain="POSIX",
                name=owner_name,
                permission=owner_perm,
                object_type="User",
            )
        )

    group_perm = _posix_mode_to_permission(mode, stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP)
    if group_perm:
        entries.append(
            PermissionEntry(
                domain="POSIX",
                name=group_name,
                permission=group_perm,
                object_type="Group",
            )
        )

    other_perm = _posix_mode_to_permission(mode, stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH)
    if other_perm:
        entries.append(
            PermissionEntry(
                domain="BUILTIN",
                name="Everyone",
                permission=other_perm,
                object_type="WellKnownGroup",
            )
        )

    return entries


def _win32_owner(path: str) -> str:  # pragma: no cover - Windows-only
    """Resolve NTFS object owner via Win32 GetFileSecurity."""
    target = clean_long_path(os.path.abspath(path))
    try:
        sd = _win32security.GetFileSecurity(target, _win32security.OWNER_SECURITY_INFORMATION)
        owner_sid = sd.GetSecurityDescriptorOwner()
        try:
            name, _domain, _otype = _win32security.LookupAccountSid(None, owner_sid)
            return str(name)
        except _pywintypes.error as exc:
            if getattr(exc, "winerror", None) == 1332:
                return f"Dead{str(owner_sid).removeprefix('PySID')}"
            return "AccessDenied"
    except Exception:
        return "AccessDenied"


def _win32_effective_permissions(
    path: str,
    domain: str | None = None,
) -> list[PermissionEntry]:  # pragma: no cover - Windows-only
    """Resolve NTFS DACL effective permissions via Win32 GetFileSecurity."""
    target = clean_long_path(os.path.abspath(path))
    try:
        sd = _win32security.GetFileSecurity(target, _win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return []
        aces = [dacl.GetAce(i) for i in range(dacl.GetAceCount())]
    except Exception:
        return []

    entries: list[PermissionEntry] = []
    for ace in aces:
        mask = ace[1]
        sid = ace[2]
        try:
            name, dom, sid_type = _win32security.LookupAccountSid(domain, sid)
            obj_type = SID_TYPES.get(sid_type, str(sid_type))
        except Exception:
            name = str(sid).split("PySID:")[-1]
            dom = domain or ""
            obj_type = "dead"
        perm_label = DACL_ACCESS_MASKS.get(mask, str(mask))
        entries.append(
            PermissionEntry(
                domain=str(dom or ""),
                name=str(name),
                permission=perm_label,
                object_type=obj_type,
            )
        )
    return entries


def _win32_fileshare_permissions(path: str) -> list[SharePermissionEntry]:  # pragma: no cover
    """Query SMB share-level DACL via Win32 NetShareGetInfo (level 502)."""
    normalized = path.replace("/", "\\")
    if not normalized.startswith("\\\\"):
        return []
    parts = [p for p in normalized.lstrip("\\").split("\\") if p]
    if len(parts) < 2:
        return []
    server, sharename = parts[0], parts[1]
    try:
        fqdn = socket.gethostbyname_ex(server)[0] if is_hostname(server) else server
    except OSError:
        fqdn = server
    try:
        info = _win32net.NetShareGetInfo(fqdn, sharename, 502)
    except Exception as exc:
        logger.debug("NetShareGetInfo failed for \\\\{}\\{}: {}", fqdn, sharename, exc)
        return []
    sd = info.get("security_descriptor")
    if sd is None:
        return []
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        return []
    out: list[SharePermissionEntry] = []
    for idx in range(dacl.GetAceCount()):
        ace = dacl.GetAce(idx)
        mask, sid = ace[1], ace[2]
        try:
            name, dom, sid_type = _win32security.LookupAccountSid(None, sid)
            obj_type = SID_TYPES.get(sid_type, str(sid_type))
        except Exception:
            name, dom, obj_type = str(sid).split("PySID:")[-1], "", "dead"
        out.append(
            SharePermissionEntry(
                server=server,
                fqdn=fqdn,
                sharename=sharename,
                acl_domain=str(dom or ""),
                acl_name=str(name),
                acl_type=obj_type,
                permission=DACL_ACCESS_MASKS.get(mask, str(mask)),
            )
        )
    return out


def _win32_group_membership(
    domain: str,
    group: str,
    acl_type: str = "Group",
    resolve_nests: bool = True,
    nest_name: str = "",
    scan_date: datetime.datetime | None = None,
) -> pd.DataFrame:  # pragma: no cover - Windows-only
    """Query Active Directory group members via Win32 NetGroupGetUsers / NetLocalGroupGetMembers."""
    if scan_date is None:
        scan_date = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    try:
        dc_info = _win32security.DsGetDcName(domainName=domain)
        server = dc_info["DomainControllerName"]
    except Exception:
        server = None

    records: list[dict[str, Any]] = []
    resume = 0
    while True:
        try:
            if acl_type.lower() == "alias":
                members, _total, resume = _win32net.NetLocalGroupGetMembers(
                    server, group, 2, resume, _win32netcon.MAX_PREFERRED_LENGTH
                )
            else:
                members, _total, resume = _win32net.NetGroupGetUsers(
                    server, group, 0, resume, _win32netcon.MAX_PREFERRED_LENGTH
                )
        except Exception as exc:
            logger.debug("AD lookup failed for {}\\{}: {}", domain, group, exc)
            break

        for member in members:
            member_name = member.get("domainandname") or member.get("name", "")
            records.append(
                {
                    "Domain": domain,
                    "ACL": group,
                    "member.logon": member_name,
                    "member.nestedACL": nest_name,
                    "scan_date": scan_date,
                }
            )
        if not resume:
            break

    return pd.DataFrame.from_records(records)
