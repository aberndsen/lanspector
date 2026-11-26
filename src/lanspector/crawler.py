"""Filesystem crawler and SQLite/CSV/Excel persistence engine for LANspector."""

from __future__ import annotations

import datetime
import hashlib
import os
import pathlib
import subprocess
import sys
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib.metadata import PackageNotFoundError, version
from typing import Any

import pandas as pd
from loguru import logger
from sqlalchemy import (
    DATETIME,
    TEXT,
    Column,
    Engine,
    ForeignKey,
    Integer,
    MetaData,
    Table,
    create_engine,
    inspect,
    text,
)
from sqlalchemy.pool import StaticPool
from tqdm import tqdm

from lanspector.constants import (
    CRAWL_DATA_COLUMNS,
    CRAWL_INFO_TABLE,
    DEFAULT_CHUNKSIZE,
    PERM_DATA_COLUMNS,
    PERM_TABLE_SUFFIX,
    PII_DATA_COLUMNS,
    PII_KEYWORDS,
    PII_TABLE_SUFFIX,
    PII_WORDS_TABLE_SUFFIX,
    PROGRESS_LOG_INTERVAL,
    SHARE_PERM_TABLE_SUFFIX,
    SUPPORTED_DB_EXTENSIONS,
    SUPPORTED_OUTPUT_EXTENSIONS,
    TIMESTAMP_FORMAT,
)
from lanspector.datatypes import CrawlEntry, CrawlResult, PermissionEntry, PiiFinding, ScanType
from lanspector.pii import scan_file_for_pii
from lanspector.platform import (
    clean_long_path,
    get_effective_permissions,
    get_fileshare_permissions,
    get_path_owner,
    strip_long_path_prefix,
)
from lanspector.settings import CrawlSettings


def _package_version() -> str:
    """Return installed lanspector version string without circular imports."""
    try:
        return version("lanspector")
    except PackageNotFoundError:
        return "0.0.0.dev0"


# ---------------------------------------------------------------------------
# Primary public routines
# ---------------------------------------------------------------------------


def crawl(
    path: str | pathlib.Path,
    scantype: ScanType = "fd",
    permissions: bool = True,
    fout: str | pathlib.Path | None = None,
    tablename: str | None = None,
    max_md5: int | None = None,
    skip_size: bool = False,
    chunksize: int = DEFAULT_CHUNKSIZE,
    crawl_acls: bool = True,
    summarize: bool = False,
    sunburst_html: str | pathlib.Path | None = None,
    limit: int = 0,
    max_depth: int = 0,
    detect_pii_content: bool = False,
    use_ner: bool = False,
    resume: bool = False,
    show_progress: bool | None = None,
) -> CrawlResult:
    """Crawl *path*, harvesting filesystem metadata, ACLs, and optional PII findings.

    Parameters
    ----------
    path
        Root directory or UNC fileshare path to crawl.
    scantype
        Objects to yield: ``"d"`` (directories only), ``"f"`` (files only),
        or ``"fd"`` (both directories and files).
    permissions
        When ``True``, harvest effective NTFS or POSIX permissions for each object.
    fout
        Destination output path (``.db``, ``.sqlite``, ``.sqlite3``, ``.csv``, ``.xlsx``).
        When ``None``, results are returned in-memory on :class:`~lanspector.datatypes.CrawlResult`.
    tablename
        Timestamp table name for SQLite output (defaults to UTC ``YYYYMMDDTHHMMSS``).
    max_md5
        Compute MD5 digests for files smaller than this size in bytes (``None`` disables).
    skip_size
        When ``True`` and ``scantype="d"``, skip summing file sizes inside directories.
    chunksize
        Number of objects buffered per database write batch (defaults to
        :data:`~lanspector.constants.DEFAULT_CHUNKSIZE`).
    crawl_acls
        When writing to SQLite on Windows, also resolve Active Directory group membership.
    summarize
        When writing to SQLite, generate a formatted Excel audit workbook after crawling.
    sunburst_html
        Optional path to export an interactive Plotly HTML storage sunburst chart.
    limit
        Stop crawling after harvesting this many objects (``0`` means unlimited).
    max_depth
        Maximum directory depth below *path* to traverse (``0`` means unlimited).
    detect_pii_content
        Inspect supported files (``.txt``, ``.csv``, ``.xlsx``) for PII keywords.
    use_ner
        Enable optional NLTK proper-name detection when ``detect_pii_content=True``.
    resume
        When ``True`` and writing to an existing SQLite database, resume the latest
        incomplete crawl (``scan_end IS NULL`` in ``CRAWL_INFO``) for *path* — or
        explicitly resume *tablename* — skipping already-persisted directories and files.
    show_progress
        Show a single-line ``tqdm`` progress bar on stderr. Defaults to ``None``
        (automatically enabled on interactive TTY terminals and disabled in piped/CI logs).

    Returns
    -------
    CrawlResult
        Structured crawl outcome including table name, output paths, and in-memory
        DataFrames when ``fout`` is ``None``.
    """
    if scantype not in ("d", "f", "fd"):
        raise ValueError(f"Unsupported scantype {scantype!r}; expected 'd', 'f', or 'fd'.")

    root_str = str(path)
    if not os.path.exists(root_str):
        raise FileNotFoundError(f"Crawl target path does not exist: {root_str}")

    ret_dirs = "d" in scantype
    ret_files = "f" in scantype
    t_start = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    table = tablename or t_start.strftime(TIMESTAMP_FORMAT)

    out_path = pathlib.Path(fout) if fout is not None else None
    engine: Engine | None = None
    out_ext = out_path.suffix.lower() if out_path is not None else ""
    resuming = False
    next_entry_id = 0
    skip_entries: set[tuple[str, str | None]] = set()

    if out_path is not None:
        if out_ext not in SUPPORTED_OUTPUT_EXTENSIONS:
            raise ValueError(
                f"Unsupported output extension {out_ext!r}; supported: {SUPPORTED_OUTPUT_EXTENSIONS}"
            )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if out_ext in SUPPORTED_DB_EXTENSIONS:
            engine = create_crawl_engine(out_path)
            existing_tables = inspect(engine).get_table_names()

            if resume:
                resumable = _find_resumable_table(engine, root_str, requested_table=tablename)
                if resumable is not None:
                    table = resumable
                    resuming = True
                    next_entry_id, skip_entries = _load_existing_crawl_state(engine, table)
                    logger.info(
                        "Resuming incomplete crawl '{}' in {} ({} entries already persisted).",
                        table,
                        out_path,
                        len(skip_entries),
                    )
                elif tablename is not None and tablename in existing_tables:
                    resuming = True
                    next_entry_id, skip_entries = _load_existing_crawl_state(engine, table)
                    logger.info(
                        "Resuming existing crawl '{}' in {} ({} entries already persisted).",
                        table,
                        out_path,
                        len(skip_entries),
                    )

            if not resuming:
                if table in existing_tables:
                    engine.dispose()
                    raise ValueError(
                        f"Crawl table {table!r} already exists in {out_path}. "
                        "Choose a new tablename or pass resume=True."
                    )
                _write_share_permissions_and_metadata(
                    engine=engine,
                    root_path=root_str,
                    tablename=table,
                    ret_files=ret_files,
                    ret_dirs=ret_dirs,
                    permissions=permissions,
                    max_md5=max_md5,
                    skip_size=skip_size,
                    limit=limit,
                    max_depth=max_depth,
                    detect_pii_content=detect_pii_content,
                    scan_start=t_start,
                )
        elif resume:
            logger.warning("resume=True is only supported for SQLite outputs; starting fresh.")

    all_info: list[dict[str, Any]] = []
    all_perms: list[dict[str, Any]] = []
    all_pii: list[dict[str, Any]] = []

    buf_info: list[dict[str, Any]] = []
    buf_perms: list[dict[str, Any]] = []
    buf_pii: list[dict[str, Any]] = []
    chunk_idx = 0
    processed = 0

    use_progress = sys.stderr.isatty() if show_progress is None else show_progress

    try:
        yielder = yield_filesystem(
            root_str,
            ret_files=ret_files,
            ret_dirs=ret_dirs,
            permissions=permissions,
            detect_pii_content=detect_pii_content,
            use_ner=use_ner,
            max_md5=max_md5,
            skip_size=skip_size,
            max_depth=max_depth,
            skip_entries=skip_entries if resuming else None,
        )

        with tqdm(
            total=limit if limit > 0 else None,
            desc=f"Crawling {root_str}",
            unit=" obj",
            leave=False,
            disable=not use_progress,
        ) as pbar:
            for entry_id, (entry, entry_perms, entry_pii) in enumerate(
                yielder, start=next_entry_id
            ):
                entry.entry_id = entry_id
                info_rec = entry.to_record()
                perm_recs: list[dict[str, Any]] = []
                if permissions and entry_perms:
                    for perm in entry_perms:
                        perm.entry_id = entry_id
                        perm_recs.append(perm.to_record())

                pii_recs: list[dict[str, Any]] = []
                if detect_pii_content and entry_pii:
                    for finding in entry_pii:
                        finding.entry_id = entry_id
                        pii_recs.append(finding.to_record())

                processed += 1
                pbar.update(1)
                if out_path is None or out_ext not in SUPPORTED_DB_EXTENSIONS:
                    all_info.append(info_rec)
                    all_perms.extend(perm_recs)
                    all_pii.extend(pii_recs)
                else:
                    buf_info.append(info_rec)
                    buf_perms.extend(perm_recs)
                    buf_pii.extend(pii_recs)
                    if len(buf_info) >= chunksize:
                        assert engine is not None
                        _flush_sqlite_chunk(
                            engine,
                            table,
                            buf_info,
                            buf_perms,
                            buf_pii,
                            is_first=(chunk_idx == 0 and not resuming),
                        )
                        buf_info.clear()
                        buf_perms.clear()
                        buf_pii.clear()
                        chunk_idx += 1

                if not use_progress and processed % PROGRESS_LOG_INTERVAL == 0:
                    logger.info("Processed {} objects below {}", processed, root_str)

                if limit > 0 and processed >= limit:
                    logger.warning("Reached crawl limit of {} objects; stopping.", limit)
                    break

        if engine is not None:
            if buf_info or (chunk_idx == 0 and not resuming):
                _flush_sqlite_chunk(
                    engine,
                    table,
                    buf_info,
                    buf_perms,
                    buf_pii,
                    is_first=(chunk_idx == 0 and not resuming),
                )
            t_end = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
            with engine.begin() as conn:
                conn.execute(
                    text(f"UPDATE [{CRAWL_INFO_TABLE}] SET [scan_end] = :end WHERE [table] = :tbl"),
                    {"end": t_end.isoformat(sep=" "), "tbl": table},
                )
    finally:
        if engine is not None:
            engine.dispose()

    files_df = (
        _records_to_df(all_info, CRAWL_DATA_COLUMNS)
        if all_info
        else pd.DataFrame(columns=list(CRAWL_DATA_COLUMNS))
    )
    perms_df = (
        _records_to_df(all_perms, PERM_DATA_COLUMNS)
        if all_perms
        else pd.DataFrame(columns=list(PERM_DATA_COLUMNS))
    )
    pii_df = (
        _records_to_df(all_pii, PII_DATA_COLUMNS)
        if all_pii
        else pd.DataFrame(columns=list(PII_DATA_COLUMNS))
    )

    if out_path is not None and out_ext == ".csv":
        files_df.to_csv(out_path, index=False)
    elif out_path is not None and out_ext == ".xlsx":
        files_df.to_excel(out_path, index=False)

    report_path: pathlib.Path | None = None
    sunburst_out: pathlib.Path | None = None

    if out_path is not None and out_ext in SUPPORTED_DB_EXTENSIONS:
        from lanspector.reader import CrawlReader
        from lanspector.reporting import generate_fileshare_report
        from lanspector.sunburst import export_sunburst_html

        with CrawlReader(out_path) as reader:
            if crawl_acls:
                reader.crawl_acls(table=table)
            if summarize:
                report_target = out_path.with_name(f"{out_path.stem}_{table}.xlsx")
                report_path = generate_fileshare_report(reader, report_target, table=table)
            if sunburst_html is not None:
                sunburst_out = export_sunburst_html(reader, sunburst_html, table=table)

    duration = datetime.datetime.now(datetime.UTC).replace(tzinfo=None) - t_start
    if out_path is not None:
        logger.info(
            "Crawl finished ({} objects, table='{}') in {} -> {}",
            processed,
            table,
            duration,
            out_path.resolve(),
        )
    else:
        logger.info("Crawl finished ({} objects, table='{}') in {}", processed, table, duration)

    return CrawlResult(
        tablename=table,
        output_path=out_path,
        files_df=files_df if out_path is None else pd.DataFrame(),
        perms_df=perms_df if out_path is None else pd.DataFrame(),
        pii_df=pii_df if out_path is None else pd.DataFrame(),
        objects_processed=processed,
        report_path=report_path,
        sunburst_path=sunburst_out,
    )


def crawl_driver(settings: CrawlSettings) -> list[pathlib.Path]:
    """Execute parallel crawls for every target listed in ``settings.driver``.

    Each non-blank, non-comment line in the driver file may be:
    - A local directory or UNC fileshare path
    - A fileserver hostname (Windows: crawls all non-admin shares on that host)
    - ``DN: <DomainName>`` (Windows: discovers domain servers and crawls their shares)

    Parameters
    ----------
    settings
        Crawl configuration with ``driver`` set to a readable text file path.

    Returns
    -------
    list[pathlib.Path]
        List of target database paths discovered (and crawled unless ``dryrun=True``).
    """
    if settings.driver is None or not settings.driver.exists():
        raise FileNotFoundError(f"Driver file not found: {settings.driver}")

    out_dir = settings.driver_out or pathlib.Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    table = settings.tablename or datetime.datetime.now(datetime.UTC).strftime(TIMESTAMP_FORMAT)

    targets: list[tuple[str, pathlib.Path]] = []
    from lanspector.shares import list_all_shares_in_domain, list_shares

    for raw_line in settings.driver.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.upper().startswith("DN:"):
            domain = line[3:].strip()
            for share in list_all_shares_in_domain(domain):
                fqdn = share.get("fqdn") or share.get("server")
                netname = share.get("netname")
                if fqdn and netname:
                    unc = f"\\\\{fqdn}\\{netname}"
                    if os.path.exists(unc):
                        targets.append((unc, out_dir / _path_to_db_name(unc)))
        elif os.path.exists(line):
            targets.append((line, out_dir / _path_to_db_name(line)))
        elif os.sep not in line and "/" not in line and "\\" not in line:
            for share in list_shares(servers=[line]):
                fqdn = share.get("fqdn") or share.get("server")
                netname = share.get("netname")
                if fqdn and netname:
                    unc = f"\\\\{fqdn}\\{netname}"
                    if os.path.exists(unc):
                        targets.append((unc, out_dir / _path_to_db_name(unc)))
        else:
            logger.warning("Skipping inaccessible or missing driver target: {}", line)

    db_paths = [db for _, db in targets]
    if settings.dryrun or not targets:
        logger.info("Driver dry-run discovered {} target(s).", len(targets))
        return db_paths

    max_workers = settings.n_procs or max(1, min(len(targets), (os.cpu_count() or 2)))

    def _run_one(target_path: str, db_path: pathlib.Path) -> pathlib.Path:
        crawl(
            path=target_path,
            scantype=settings.scantype,
            permissions=settings.permissions,
            fout=db_path,
            tablename=table,
            max_md5=settings.max_md5,
            skip_size=settings.skip_size,
            crawl_acls=settings.crawl_acls,
            summarize=settings.summarize,
            limit=settings.limit,
            max_depth=settings.max_depth,
            detect_pii_content=settings.detect_pii,
            use_ner=settings.use_ner,
            resume=settings.resume,
        )
        return db_path

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_run_one, t_path, db_path) for t_path, db_path in targets]
        for fut in as_completed(futures):
            fut.result()

    if db_paths:
        from lanspector.reporting import generate_open_shares_summary_report

        generate_open_shares_summary_report(db_paths, out_dir / "open_shares_report.xlsx")

    return db_paths


def yield_filesystem(
    path: str,
    ret_files: bool = True,
    ret_dirs: bool = True,
    permissions: bool = True,
    detect_pii_content: bool = False,
    use_ner: bool = False,
    max_md5: int | None = None,
    skip_size: bool = False,
    max_depth: int = 0,
    skip_entries: set[tuple[str, str | None]] | None = None,
    _depth: int = 0,
) -> Iterator[tuple[CrawlEntry, list[PermissionEntry] | None, list[PiiFinding]]]:
    """Recursively yield metadata, permissions, and PII findings below *path*.

    Parameters
    ----------
    path
        Directory path to traverse.
    ret_files
        Yield individual file entries when ``True``.
    ret_dirs
        Yield directory entries when ``True``.
    permissions
        Harvest effective NTFS/POSIX permissions when ``True``.
    detect_pii_content
        Inspect supported files for PII indicators when ``True``.
    use_ner
        Enable optional NLTK proper-name NER during PII scanning.
    max_md5
        Maximum file size in bytes for computing MD5 digests (``None`` disables).
    skip_size
        Skip aggregating contained file sizes onto directory entries when ``ret_files=False``.
    max_depth
        Maximum recursion depth below the root (``0`` means unlimited).
    skip_entries
        Optional set of ``(normalized_dir_path, fname_or_none)`` pairs already persisted
        in an interrupted crawl; matching objects are skipped without re-reading ACLs/MD5/PII
        while subdirectories are still traversed to finish any unvisited paths.
    _depth
        Internal current recursion depth counter.

    Yields
    ------
    tuple[CrawlEntry, list[PermissionEntry] | None, list[PiiFinding]]
        Three-tuple of ``(entry, permissions, pii_findings)`` for each visited object.
    """
    clean_root = strip_long_path_prefix(path)
    norm_root = os.path.normcase(os.path.normpath(os.path.abspath(clean_root)))
    dir_already_done = skip_entries is not None and (norm_root, None) in skip_entries

    parent_entry: CrawlEntry | None = None
    parent_perms: list[PermissionEntry] | None = None
    if ret_dirs and not dir_already_done:
        parent_entry, parent_perms = _inspect_directory(path, permissions=permissions)

    subdirs: list[str] = []
    file_entries: list[tuple[CrawlEntry, list[PermissionEntry] | None, list[PiiFinding]]] = []
    dir_size = 0
    dir_md5_hash = (
        hashlib.md5() if (not ret_files and max_md5 is not None and not dir_already_done) else None
    )
    dir_pii: list[PiiFinding] = []

    scan_target = clean_long_path(os.path.abspath(clean_root))
    try:
        with os.scandir(scan_target) as iterator:
            for item in iterator:
                try:
                    is_symlink = item.is_symlink()
                    is_dir = item.is_dir(follow_symlinks=False)
                except OSError:
                    continue

                if is_dir:
                    if not is_symlink:
                        subdirs.append(item.path)
                    continue

                if not ret_files:
                    if dir_already_done:
                        continue
                    try:
                        st = item.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    file_size = st.st_size
                    if not skip_size:
                        dir_size += file_size
                    if dir_md5_hash is not None and max_md5 is not None and file_size <= max_md5:
                        digest = md5sum(item.path)
                        if digest:
                            dir_md5_hash.update(digest.encode("ascii"))
                    if detect_pii_content:
                        dir_pii.extend(scan_file_for_pii(item.path, use_ner=use_ner))
                    continue

                if skip_entries is not None and (norm_root, item.name) in skip_entries:
                    continue

                try:
                    st = item.stat(follow_symlinks=False)
                except OSError:
                    continue

                file_size = st.st_size
                file_md5: str | None = None
                if max_md5 is not None and file_size <= max_md5:
                    file_md5 = md5sum(item.path)

                file_entry = CrawlEntry(
                    path=norm_root,
                    fname=item.name,
                    bytes=file_size,
                    owner=get_path_owner(item.path),
                    ctime=_epoch_to_dt(st.st_ctime),
                    atime=_epoch_to_dt(st.st_atime),
                    mtime=_epoch_to_dt(st.st_mtime),
                    md5=file_md5,
                    is_symlink=is_symlink,
                )
                file_perms = get_effective_permissions(item.path) if permissions else None
                file_pii = (
                    scan_file_for_pii(item.path, use_ner=use_ner) if detect_pii_content else []
                )
                file_entries.append((file_entry, file_perms, file_pii))
    except OSError as exc:
        logger.debug("Unable to scan directory {}: {}", path, exc)
        if parent_entry is not None:
            parent_entry.owner = "AccessDenied"

    if ret_dirs and parent_entry is not None:
        if not ret_files:
            parent_entry.bytes = dir_size
            if dir_md5_hash is not None:
                parent_entry.md5 = dir_md5_hash.hexdigest()
        yield (parent_entry, parent_perms, dir_pii if not ret_files else [])

    if ret_files:
        yield from file_entries

    if max_depth == 0 or _depth < max_depth:
        for subdir in sorted(subdirs):
            yield from yield_filesystem(
                subdir,
                ret_files=ret_files,
                ret_dirs=ret_dirs,
                permissions=permissions,
                detect_pii_content=detect_pii_content,
                use_ner=use_ner,
                max_md5=max_md5,
                skip_size=skip_size,
                max_depth=max_depth,
                skip_entries=skip_entries,
                _depth=_depth + 1,
            )


# ---------------------------------------------------------------------------
# Supporting public routines (alphabetical)
# ---------------------------------------------------------------------------


def convert_to_sqlite(
    fin: str | pathlib.Path,
    fout: str | pathlib.Path | None = None,
    crawldate: str | None = None,
    overwrite: bool = False,
) -> pathlib.Path:
    """Convert a CSV or Excel crawl file into a LANspector SQLite database.

    Parameters
    ----------
    fin
        Input ``.csv`` or ``.xlsx`` crawl file.
    fout
        Destination ``.db`` / ``.sqlite`` path (defaults to *fin* with ``.db`` suffix).
    crawldate
        Table name in ``YYYYMMDDTHHMMSS`` format (defaults to current UTC timestamp).
    overwrite
        Replace existing table if already present in *fout*.

    Returns
    -------
    pathlib.Path
        Path to the created or updated SQLite database.
    """
    src = pathlib.Path(fin)
    if not src.exists():
        raise FileNotFoundError(f"Input file not found: {src}")

    dst = pathlib.Path(fout) if fout is not None else src.with_suffix(".db")
    table = crawldate or datetime.datetime.now(datetime.UTC).strftime(TIMESTAMP_FORMAT)

    ext = src.suffix.lower()
    if ext == ".csv":
        df = pd.read_csv(src)
    elif ext in (".xlsx", ".xlsm"):
        df = pd.read_excel(src)
    else:
        raise ValueError(f"Cannot convert unsupported file type {ext!r} to SQLite.")

    if "Id" not in df.columns:
        df.insert(0, "Id", range(len(df)))

    engine = create_crawl_engine(dst)
    try:
        if_exists = "replace" if overwrite else "fail"
        df.to_sql(table, engine, if_exists=if_exists, index=False, chunksize=500)
    finally:
        engine.dispose()
    return dst


def crawl_by_existing_dbs(
    location: str | pathlib.Path,
    mindate: str | datetime.datetime,
    cmd_base: list[str] | None = None,
    dryrun: bool = False,
) -> list[list[str]]:
    """Find crawl databases older than *mindate* and optionally re-crawl them.

    Parameters
    ----------
    location
        Directory containing existing ``<server>_<share>.db`` crawl databases.
    mindate
        Minimum acceptable latest-crawl timestamp (datetime or ``YYYYMMDDTHHMMSS`` string).
    cmd_base
        Base CLI command list (defaults to ``[sys.executable, "-m", "lanspector", "crawl"]``).
    dryrun
        When ``True``, return the planned commands without launching subprocesses.

    Returns
    -------
    list[list[str]]
        Subprocess command lists for stale databases.
    """
    from lanspector.reader import CrawlReader

    cutoff = (
        datetime.datetime.strptime(mindate, TIMESTAMP_FORMAT)
        if isinstance(mindate, str)
        else mindate
    )
    base = cmd_base or [sys.executable, "-m", "lanspector", "crawl"]
    db_files = sorted(pathlib.Path(location).glob("*_*.db"))

    commands: list[list[str]] = []
    for db_file in db_files:
        with CrawlReader(db_file) as reader:
            latest = reader.latest_crawl
        is_stale = latest is None
        if latest is not None:
            try:
                latest_dt = datetime.datetime.strptime(latest, TIMESTAMP_FORMAT)
                is_stale = latest_dt < cutoff
            except ValueError:
                is_stale = False
        if not is_stale:
            continue

        parts = db_file.stem.split("_")
        server = parts[0]
        share = "_".join(parts[1:])
        unc = f"\\\\{server}\\{share}"
        commands.append([*base, "--path", unc, "--fout", str(db_file)])

    if not dryrun:
        for cmd in commands:
            logger.info("Re-crawling stale target: {}", " ".join(cmd))
            subprocess.run(cmd, check=False)

    return commands


def create_crawl_engine(db_path: str | pathlib.Path) -> Engine:
    """Create a SQLAlchemy 2.x SQLite engine configured for LANspector crawls.

    Parameters
    ----------
    db_path
        Path to the SQLite database file.

    Returns
    -------
    sqlalchemy.Engine
        Configured SQLAlchemy engine.
    """
    resolved = pathlib.Path(db_path).resolve()
    return create_engine(
        f"sqlite:///{resolved}",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )


def md5sum(
    filename: str | pathlib.Path,
    blocksize: int = 2**20,
    max_block: int | None = None,
) -> str:
    """Calculate the MD5 hex digest of *filename*.

    Parameters
    ----------
    filename
        Path to the file to hash.
    blocksize
        Read buffer size in bytes.
    max_block
        Optional cap on the number of blocks read.

    Returns
    -------
    str
        Lowercase hexadecimal MD5 digest (or empty string if unreadable).
    """
    digest = hashlib.md5()
    try:
        with open(filename, "rb") as handle:
            blocks = 0
            while True:
                chunk = handle.read(blocksize)
                if not chunk:
                    break
                digest.update(chunk)
                blocks += 1
                if max_block is not None and blocks >= max_block:
                    break
    except OSError:
        return ""
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _create_crawl_tables(engine: Engine, tablename: str) -> None:
    """Create primary crawl, permissions, PII, and PII-keyword tables if absent."""
    existing = set(inspect(engine).get_table_names())
    perm_table = f"{tablename}{PERM_TABLE_SUFFIX}"
    pii_word_table = f"{tablename}{PII_WORDS_TABLE_SUFFIX}"
    pii_table = f"{tablename}{PII_TABLE_SUFFIX}"

    metadata = MetaData()
    created_any = False

    if tablename not in existing:
        Table(
            tablename,
            metadata,
            Column("Id", Integer, primary_key=True),
            Column("path", TEXT),
            Column("fname", TEXT),
            Column("bytes", Integer),
            Column("owner", TEXT),
            Column("ctime", DATETIME),
            Column("atime", DATETIME),
            Column("mtime", DATETIME),
            Column("md5", TEXT),
        )
        created_any = True

    if perm_table not in existing:
        Table(
            perm_table,
            metadata,
            Column("permId", Integer, primary_key=True),
            Column("Id", Integer, ForeignKey(f"{tablename}.Id"), nullable=False),
            Column("Domain", TEXT),
            Column("Name", TEXT),
            Column("Permission", TEXT),
            Column("ObjectType", TEXT),
        )
        created_any = True

    if pii_word_table not in existing:
        Table(
            pii_word_table,
            metadata,
            Column("pii_wordId", Integer, primary_key=True),
            Column("keyword", TEXT),
        )
        created_any = True

    if pii_table not in existing:
        Table(
            pii_table,
            metadata,
            Column("piiId", Integer, primary_key=True),
            Column("Id", Integer, ForeignKey(f"{tablename}.Id"), nullable=False),
            Column(
                "pii_wordId", Integer, ForeignKey(f"{pii_word_table}.pii_wordId"), nullable=False
            ),
            Column("snippet", TEXT),
        )
        created_any = True

    if created_any:
        metadata.create_all(engine)

    pii_words_df = pd.DataFrame({"keyword": list(PII_KEYWORDS)})
    pii_words_df.index.name = "pii_wordId"
    pii_words_df.to_sql(pii_word_table, engine, if_exists="replace", index=True)


def _epoch_to_dt(timestamp: float) -> datetime.datetime:
    """Convert a POSIX epoch float to a naive local datetime."""
    return datetime.datetime.fromtimestamp(timestamp)


def _find_resumable_table(
    engine: Engine,
    root_path: str,
    requested_table: str | None = None,
) -> str | None:
    """Find the most recent incomplete crawl table (scan_end IS NULL) for *root_path*."""
    existing = set(inspect(engine).get_table_names())
    if CRAWL_INFO_TABLE not in existing:
        return None
    norm_root = os.path.normcase(os.path.abspath(root_path))
    info_df = pd.read_sql_table(CRAWL_INFO_TABLE, engine)
    if info_df.empty or "table" not in info_df.columns:
        return None
    incomplete = info_df[info_df["scan_end"].isna()]
    if requested_table is not None:
        incomplete = incomplete[incomplete["table"].astype(str) == requested_table]
    elif "path" in incomplete.columns:
        incomplete = incomplete[incomplete["path"].astype(str) == norm_root]
    candidates = [str(t) for t in incomplete["table"].tolist() if str(t) in existing]
    return candidates[-1] if candidates else None


def _load_existing_crawl_state(
    engine: Engine,
    tablename: str,
) -> tuple[int, set[tuple[str, str | None]]]:
    """Load the next primary-key Id and set of already-persisted (path, fname) pairs."""
    with engine.connect() as conn:
        max_id = conn.execute(text(f"SELECT COALESCE(MAX(Id), -1) FROM [{tablename}]")).scalar()
        rows = conn.execute(text(f"SELECT path, fname FROM [{tablename}]")).fetchall()
    next_id = int(max_id) + 1 if max_id is not None else 0
    existing_keys = {(str(row[0]), None if row[1] is None else str(row[1])) for row in rows}
    return next_id, existing_keys


def _flush_sqlite_chunk(
    engine: Engine,
    tablename: str,
    info_rows: list[dict[str, Any]],
    perm_rows: list[dict[str, Any]],
    pii_rows: list[dict[str, Any]],
    is_first: bool,
) -> None:
    """Persist one buffered chunk of crawl, permission, and PII rows to SQLite."""
    if is_first:
        _create_crawl_tables(engine, tablename)

    if info_rows:
        df_info = _records_to_df(info_rows, CRAWL_DATA_COLUMNS)
        df_info.to_sql(tablename, engine, if_exists="append", index=False, chunksize=100)
    if perm_rows:
        df_perms = _records_to_df(perm_rows, PERM_DATA_COLUMNS)
        df_perms.to_sql(
            f"{tablename}{PERM_TABLE_SUFFIX}",
            engine,
            if_exists="append",
            index=False,
            chunksize=100,
        )
    if pii_rows:
        df_pii = _records_to_df(pii_rows, PII_DATA_COLUMNS)
        df_pii.to_sql(
            f"{tablename}{PII_TABLE_SUFFIX}",
            engine,
            if_exists="append",
            index=False,
            chunksize=100,
        )


def _inspect_directory(
    path: str,
    permissions: bool,
) -> tuple[CrawlEntry, list[PermissionEntry] | None]:
    """Gather stat metadata, owner, and effective permissions for a single directory."""
    clean_root = strip_long_path_prefix(path)
    norm_root = os.path.normcase(os.path.normpath(os.path.abspath(clean_root)))
    target = clean_long_path(os.path.abspath(clean_root))

    try:
        st = os.lstat(target)
    except OSError:
        return CrawlEntry(path=norm_root, fname=None, owner="AccessDenied"), None

    entry = CrawlEntry(
        path=norm_root,
        fname=None,
        bytes=st.st_size,
        owner=get_path_owner(target),
        ctime=_epoch_to_dt(st.st_ctime),
        atime=_epoch_to_dt(st.st_atime),
        mtime=_epoch_to_dt(st.st_mtime),
        md5=None,
        is_symlink=False,
    )
    perms = get_effective_permissions(target) if permissions else None
    return entry, perms


def _path_to_db_name(path: str) -> str:
    """Convert a local or UNC target path into a safe SQLite filename."""
    cleaned = os.path.normpath(path).replace(" ", "_").replace("\\", "_").replace("/", "_")
    cleaned = cleaned.replace(":", "").strip("_")
    return f"{cleaned or 'crawl'}.db"


def _records_to_df(records: list[dict[str, Any]], columns: tuple[str, ...]) -> pd.DataFrame:
    """Build a DataFrame ordered to *columns* from a list of record dicts."""
    df = pd.DataFrame.from_records(records)
    ordered = [c for c in columns if c in df.columns]
    return df[ordered]


def _write_share_permissions_and_metadata(
    engine: Engine,
    root_path: str,
    tablename: str,
    ret_files: bool,
    ret_dirs: bool,
    permissions: bool,
    max_md5: int | None,
    skip_size: bool,
    limit: int,
    max_depth: int,
    detect_pii_content: bool,
    scan_start: datetime.datetime,
) -> None:
    """Persist share-level permissions and CRAWL_INFO metadata row for a crawl."""
    share_perms = get_fileshare_permissions(root_path)
    sp_cols = ["server", "fqdn", "sharename", "ACLDomain", "ACLName", "ACLtype", "permission"]
    sp_df = (
        pd.DataFrame.from_records([sp.to_record() for sp in share_perms])
        if share_perms
        else pd.DataFrame(columns=sp_cols)
    )
    sp_df.to_sql(
        f"{tablename}{SHARE_PERM_TABLE_SUFFIX}",
        engine,
        chunksize=50,
        if_exists="replace",
        index=False,
    )

    info_row = pd.DataFrame(
        [
            {
                "path": os.path.normcase(os.path.abspath(root_path)),
                "table": tablename,
                "scan_files": ret_files,
                "scan_directories": ret_dirs,
                "scan_permissions": permissions,
                "scan_md5": max_md5,
                "skip_size": skip_size,
                "limit": limit,
                "max_depth": max_depth,
                "scan_start": scan_start,
                "scan_end": None,
                "lanspector_version": _package_version(),
                "detect_pii_content": detect_pii_content,
            }
        ]
    )

    existing = inspect(engine).get_table_names()
    if CRAWL_INFO_TABLE in existing:
        prev = pd.read_sql_table(CRAWL_INFO_TABLE, engine)
        combined = pd.concat([prev, info_row], ignore_index=True)
        combined.to_sql(CRAWL_INFO_TABLE, engine, chunksize=50, if_exists="replace", index=False)
    else:
        info_row.to_sql(CRAWL_INFO_TABLE, engine, chunksize=50, if_exists="replace", index=False)
