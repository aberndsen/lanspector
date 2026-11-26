"""Automated Excel SOX/audit report generation for LANspector crawls."""

from __future__ import annotations

import datetime
import pathlib
from collections.abc import Sequence
from importlib.metadata import PackageNotFoundError, version
from typing import Any

import numpy as np
import pandas as pd
from loguru import logger
from xlsxwriter.utility import xl_rowcol_to_cell

from lanspector.constants import BYTE_UNIT_PREFIXES, PII_KEYWORDS, TIMESTAMP_FORMAT
from lanspector.datatypes import ExecutiveSummary
from lanspector.reader import CrawlReader, MultiDB


def _package_version() -> str:
    """Return installed lanspector version string without circular imports."""
    try:
        return version("lanspector")
    except PackageNotFoundError:
        return "0.0.0.dev0"


# ---------------------------------------------------------------------------
# Primary public routines
# ---------------------------------------------------------------------------


def generate_fileshare_report(
    db: CrawlReader | MultiDB | str | pathlib.Path | Sequence[str | pathlib.Path],
    fout: str | pathlib.Path,
    table: str | None = None,
    limit: int | None = 500,
    owner: str | None = None,
    subdir: str | None = None,
    per_user: bool = False,
    acl_skip: Sequence[tuple[str, str]] | None = None,
    use_permission_hierarchy: bool = False,
    skip_files_report: bool = False,
    skip_old_acl_report: bool = True,
    skip_user_owner_report: bool = False,
    strip_pathprefix: str | None = None,
    report_pii: bool = True,
) -> pathlib.Path:
    """Generate a multi-sheet Excel SOX/audit and storage-cleanup report.

    Produces formatted Excel tables across dedicated worksheets:
    ``Summary``, ``No Access to Crawl``, ``ACL membership``, ``parent_vs_child``,
    ``file_vs_folderACL``, ``Possible PII Locations``, ``Largest Directories``,
    ``Largest Files``, ``Duplicate Files``, ``Access Time Distribution``,
    ``Oldest Objects``, ``Largest Users``, ``Backup Files``, ``Backup Paths``,
    and ``Objects Owned by User``. Empty sheets are omitted automatically.

    Parameters
    ----------
    db
        A :class:`~lanspector.reader.CrawlReader`, :class:`~lanspector.reader.MultiDB`,
        single database path, or sequence of database paths.
    fout
        Destination ``.xlsx`` workbook path.
    table
        Crawl timestamp table name (defaults to latest crawl).
    limit
        Maximum rows written per detail sheet (``None`` or ``0`` means unlimited).
    owner
        Optional owner filter for single-user reports.
    subdir
        Optional subdirectory prefix filter.
    per_user
        When ``True``, also write one workbook per discovered owner alongside *fout*.
    acl_skip
        Optional sequence of ``(Domain, Name)`` ACL tuples excluded from permission diffs.
    use_permission_hierarchy
        Collapse subordinate permissions (``MR`` -> ``M``, ``F`` dominates all).
    skip_files_report
        Omit the ``file_vs_folderACL`` sheet when ``True``.
    skip_old_acl_report
        Omit legacy ``new perms at child`` / ``dropped perms at child`` sheets when ``True``.
    skip_user_owner_report
        Omit the ``Objects Owned by User`` sheet when ``True``.
    strip_pathprefix
        Optional prefix stripped from displayed paths.
    report_pii
        Include the ``Possible PII Locations`` worksheet when ``True``.

    Returns
    -------
    pathlib.Path
        Resolved path to the generated Excel workbook.
    """
    reader_obj, should_close = _coerce_reader(db)
    out_path = pathlib.Path(fout)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    row_limit = limit if (limit is not None and limit > 0) else None

    try:
        tbl = table or reader_obj.latest_crawl
        if tbl is None:
            raise ValueError("Cannot generate report: database contains no crawls.")

        if per_user and owner is None:
            users_df = _call_reader(reader_obj, "users", table=tbl, subdir=subdir)
            if isinstance(users_df, pd.DataFrame) and "owner" in users_df.columns:
                for user_name in users_df["owner"].dropna().unique().tolist():
                    safe_user = str(user_name).replace("/", "_").replace("\\", "_")
                    user_fout = out_path.with_name(f"{out_path.stem}_{safe_user}{out_path.suffix}")
                    generate_fileshare_report(
                        reader_obj,
                        user_fout,
                        table=tbl,
                        limit=row_limit,
                        owner=str(user_name),
                        subdir=subdir,
                        per_user=False,
                        acl_skip=acl_skip,
                        use_permission_hierarchy=use_permission_hierarchy,
                        skip_files_report=skip_files_report,
                        skip_old_acl_report=skip_old_acl_report,
                        skip_user_owner_report=skip_user_owner_report,
                        strip_pathprefix=strip_pathprefix,
                        report_pii=report_pii,
                    )

        with pd.ExcelWriter(out_path, engine="xlsxwriter") as writer:
            book = writer.book
            rotated_header = book.add_format({"rotation": 45, "bold": True})
            bold_title = book.add_format({"bold": True, "font_size": 12})

            # 1. Executive Summary sheet
            _write_summary_sheet(
                book=book,
                reader_obj=reader_obj,
                table=tbl,
                owner=owner,
                subdir=subdir,
                limit=row_limit,
                title_format=bold_title,
            )

            # 2. Access Denied sheet
            if owner is None:
                denied = _call_reader(
                    reader_obj,
                    "find_where_access_is_denied",
                    table=tbl,
                    subdir=subdir,
                    dirs_only=True,
                )
                if isinstance(denied, pd.DataFrame) and not denied.empty:
                    denied = scale_bytes_cols(denied)
                    ws = book.add_worksheet("No Access to Crawl")
                    ws.write(
                        "A1",
                        "Directories that could not be traversed due to missing permissions or path limits.",
                    )
                    write_excel_table(ws, denied, startrow=3)

            # 3. ACL membership sheet
            acl_members = _call_reader(reader_obj, "summarize_acls", table=tbl, subdir=subdir)
            if isinstance(acl_members, pd.DataFrame) and not acl_members.empty:
                ws = book.add_worksheet("ACL membership")
                ws.write(
                    "A1",
                    "Active Directory group membership for ACLs discovered in this crawl.",
                )
                write_excel_table(ws, acl_members, startrow=3)

            # 4. Parent-vs-child & File-vs-folder ACL sheets
            if owner is None:
                pvc = _call_reader(
                    reader_obj,
                    "parent_vs_child_report",
                    subdir=subdir,
                    acl_skip=acl_skip,
                    skip_files_report=skip_files_report,
                    use_permission_hierarchy=use_permission_hierarchy,
                    table=tbl,
                    alldirs=False,
                    flatten_cols=True,
                    strip_pathprefix=strip_pathprefix,
                )
                if pvc.dirs_df is not None and not pvc.dirs_df.empty:
                    ws = book.add_worksheet("parent_vs_child")
                    ws.write(
                        "A1",
                        "Path vs ACL: root folder permissions plus every subfolder differing from its parent.",
                    )
                    ws.write(
                        "A2",
                        "Share-level permissions (when available) appear in the trailing columns.",
                    )
                    ws.write("A3", "Legend:")
                    ws.write("B3", "(R)ead")
                    ws.write("C3", "(F)ull Control")
                    ws.write("D3", "(M)odify")
                    ws.write("E3", "(A)dd")
                    ws.write("F3", "(S)pecial")
                    write_excel_table(ws, pvc.dirs_df, startrow=6, header_format=rotated_header)

                if pvc.files_df is not None and not pvc.files_df.empty:
                    ws = book.add_worksheet("file_vs_folderACL")
                    ws.write(
                        "A1",
                        "Files granting more permissions than their containing parent folder.",
                    )
                    ws.write("A2", "Dead SIDs are excluded from this comparison.")
                    ws.write("A3", "Legend: (R)ead, (F)ull Control, (M)odify, (A)dd, (S)pecial")
                    write_excel_table(ws, pvc.files_df, startrow=5, header_format=rotated_header)

            # 5. Possible PII Locations sheet
            if report_pii:
                _write_pii_sheet(
                    book=book,
                    reader_obj=reader_obj,
                    table=tbl,
                    owner=owner,
                    subdir=subdir,
                    limit=row_limit,
                )

            # 6. Largest Directories sheet
            l_dirs = _call_reader(
                reader_obj,
                "largest_subdirectories",
                limit=row_limit,
                table=tbl,
                owner=owner,
                subdir=subdir,
                strip_pathprefix=strip_pathprefix,
            )
            if isinstance(l_dirs, pd.DataFrame) and not l_dirs.empty:
                l_dirs = scale_bytes_cols(l_dirs)
                ws = book.add_worksheet("Largest Directories")
                ws.write("A1", "Largest directories found in the crawl.")
                _write_limit_note(ws, "A2", row_limit)
                write_excel_table(ws, l_dirs, startrow=3)

            # 7. Largest Files sheet
            l_files = _call_reader(
                reader_obj,
                "largest_files",
                limit=row_limit,
                table=tbl,
                owner=owner,
                subdir=subdir,
                strip_pathprefix=strip_pathprefix,
            )
            if isinstance(l_files, pd.DataFrame) and not l_files.empty:
                l_files = l_files.drop(columns=["Id"], errors="ignore")
                l_files = scale_bytes_cols(l_files)
                ws = book.add_worksheet("Largest Files")
                ws.write("A1", "Largest files found in the crawl.")
                _write_limit_note(ws, "A2", row_limit)
                write_excel_table(ws, l_files, startrow=3)

            # 8. Duplicate Files (MD5) sheet
            dup_md5 = _call_reader(
                reader_obj,
                "find_duplicate_md5",
                table=tbl,
                minsize=1,
                limit=row_limit,
                owner=owner,
                subdir=subdir,
            )
            if isinstance(dup_md5, pd.DataFrame) and not dup_md5.empty:
                dup_md5 = dup_md5.drop(columns=["Id"], errors="ignore")
                dup_md5 = scale_bytes_cols(dup_md5)
                ws = book.add_worksheet("Duplicate Files")
                ws.write("A1", "Duplicate files/directories matching identical MD5 checksums.")
                _write_limit_note(ws, "A2", row_limit)
                write_excel_table(ws, dup_md5, startrow=3)

            # 9. Access Time Distribution sheet
            age_dist = _call_reader(
                reader_obj,
                "find_file_age_distribution",
                limit=row_limit,
                table=tbl,
                owner=owner,
                subdir=subdir,
            )
            if isinstance(age_dist, pd.DataFrame) and not age_dist.empty:
                ws = book.add_worksheet("Access Time Distribution")
                ws.write("A1", "Distribution of file last-access years per directory.")
                _write_limit_note(ws, "A2", row_limit)
                write_excel_table(ws, age_dist.reset_index(), startrow=3)

            # 10. Oldest Objects sheet
            oldest = _call_reader(
                reader_obj,
                "oldest_entries",
                limit=row_limit,
                table=tbl,
                owner=owner,
                subdir=subdir,
            )
            if isinstance(oldest, pd.DataFrame) and not oldest.empty:
                oldest = oldest.drop(columns=["Id"], errors="ignore")
                oldest = scale_bytes_cols(oldest)
                ws = book.add_worksheet("Oldest Objects")
                ws.write("A1", "Oldest files and directories ordered by last-access timestamp.")
                _write_limit_note(ws, "A2", row_limit)
                write_excel_table(ws, oldest, startrow=3)

            # 11. Largest Users sheet
            if owner is None:
                l_users = _call_reader(
                    reader_obj, "largest_users", table=tbl, owner=owner, subdir=subdir
                )
                if isinstance(l_users, pd.DataFrame) and not l_users.empty:
                    l_users = scale_bytes_cols(l_users)
                    ws = book.add_worksheet("Largest Users")
                    ws.write("A1", "Total storage aggregated by file/directory owner.")
                    write_excel_table(ws, l_users, startrow=3)

            # 12. Backup Files & Backup Paths sheets
            for obj_kind, sheet_name, desc in (
                ("fname", "Backup Files", "Probable backup files matched by naming heuristics."),
                (
                    "path",
                    "Backup Paths",
                    "Probable backup directories matched by naming heuristics.",
                ),
            ):
                bkp = _call_reader(
                    reader_obj,
                    "find_backups",
                    obj=obj_kind,
                    table=tbl,
                    limit=row_limit,
                    owner=owner,
                    subdir=subdir,
                )
                if isinstance(bkp, pd.DataFrame) and not bkp.empty:
                    bkp = bkp.drop(columns=["Id"], errors="ignore")
                    bkp = scale_bytes_cols(bkp)
                    ws = book.add_worksheet(sheet_name)
                    ws.write("A1", desc)
                    _write_limit_note(ws, "A2", row_limit)
                    write_excel_table(ws, bkp, startrow=3)

            # 13. Objects Owned by User sheet
            if not skip_user_owner_report:
                user_access = _call_reader(
                    reader_obj,
                    "find_objects_with_user_access",
                    table=tbl,
                    owner=owner,
                    limit=row_limit,
                    subdir=subdir,
                )
                if isinstance(user_access, pd.DataFrame) and not user_access.empty:
                    user_access = scale_bytes_cols(user_access)
                    ws = book.add_worksheet("Objects Owned by User")
                    ws.write(
                        "A1",
                        "Folders with direct User-account ACL grants (prefer group-based ACLs).",
                    )
                    _write_limit_note(ws, "A2", row_limit)
                    write_excel_table(ws, user_access, startrow=3)

            # 14. Optional legacy child permission diffs
            if owner is None and not skip_old_acl_report and not reader_obj.is_multidb:
                assert isinstance(reader_obj, CrawlReader)
                added, dropped = reader_obj.find_children_permissions_diffs(
                    table=tbl, subdir=subdir
                )
                if not added.empty:
                    ws = book.add_worksheet("new perms at child")
                    ws.write("A1", "Permissions added at child folders compared to parent.")
                    write_excel_table(ws, added, startrow=3)
                if not dropped.empty:
                    ws = book.add_worksheet("dropped perms at child")
                    ws.write("A1", "Permissions removed at child folders compared to parent.")
                    write_excel_table(ws, dropped, startrow=3)

        logger.info("Wrote LANspector audit report to {}", out_path.resolve())
        return out_path.resolve()
    finally:
        if should_close and isinstance(reader_obj, CrawlReader):
            reader_obj.close()


def generate_open_shares_summary_report(
    crawls: CrawlReader | MultiDB | str | pathlib.Path | Sequence[str | pathlib.Path],
    fout: str | pathlib.Path,
) -> pd.DataFrame | None:
    """Generate an Open Shares summary Excel workbook across one or more crawls.

    Parameters
    ----------
    crawls
        Directory containing ``*.db`` files, a database path, sequence of paths,
        :class:`~lanspector.reader.CrawlReader`, or :class:`~lanspector.reader.MultiDB`.
    fout
        Destination Excel path (version suffix appended if file already exists).

    Returns
    -------
    pandas.DataFrame or None
        Open shares DataFrame written to *fout*, or ``None`` if no share properties exist.
    """
    target: CrawlReader | MultiDB
    should_close = False
    if isinstance(crawls, (str, pathlib.Path)) and pathlib.Path(crawls).is_dir():
        db_files = sorted(pathlib.Path(crawls).glob("*.db"))
        target = MultiDB(db_files)
    else:
        target, should_close = _coerce_reader(crawls)

    try:
        oa = _call_reader(target, "list_open_share_properties")
        out_path = version_adder(fout, extension=".xlsx")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with pd.ExcelWriter(out_path, engine="xlsxwriter") as writer:
            ws = writer.book.add_worksheet("Open Shares")
            ws.write("A1", "LANspector Open Shares Summary Report")
            ws.write(
                "A2",
                "Combines SMB share-level permissions, NTFS builtin exposure counts, and AD group counts.",
            )
            if isinstance(oa, pd.DataFrame) and not oa.empty:
                flat = oa.copy()
                if isinstance(flat.columns, pd.MultiIndex):
                    flat.columns = pd.Index([f"{a} | {b}" for a, b in flat.columns])
                write_excel_table(ws, flat, startrow=4)
            else:
                ws.write("A4", "No share-level or builtin open-access properties found.")

        logger.info("Wrote Open Shares summary report to {}", out_path.resolve())
        return oa if isinstance(oa, pd.DataFrame) else None
    finally:
        if should_close and isinstance(target, CrawlReader):
            target.close()


# ---------------------------------------------------------------------------
# Supporting public utilities (alphabetical)
# ---------------------------------------------------------------------------


def scale_bytes_cols(
    df: pd.DataFrame,
    columns: Sequence[str] | None = None,
) -> pd.DataFrame:
    """Scale byte-valued columns into human-readable units (KB, MB, GB, TB, ...).

    Parameters
    ----------
    df
        Input DataFrame (not modified in place).
    columns
        Specific columns to scale. Defaults to any column named ``"bytes"`` or ``"size"``.

    Returns
    -------
    pandas.DataFrame
        Copy of *df* with scaled numeric columns renamed to ``"<col> [<unit>]"``.
    """
    out = df.copy()
    targets = (
        list(columns)
        if columns is not None
        else [c for c in out.columns if str(c).lower() in ("bytes", "size")]
    )
    rename_map: dict[str, str] = {}
    for col in targets:
        if col not in out.columns or out[col].empty:
            continue
        numeric = pd.to_numeric(out[col], errors="coerce").dropna()
        if numeric.empty:
            continue
        max_val = float(numeric.max())
        power = 0
        while power < 60 and max_val >= 2 ** (power + 10):
            power += 10
        unit = BYTE_UNIT_PREFIXES.get(power, "Bytes")
        if power > 0:
            out[col] = (pd.to_numeric(out[col], errors="coerce") / (2**power)).round(2)
        rename_map[col] = f"{col} [{unit}]"
    if rename_map:
        out = out.rename(columns=rename_map)
    return out


def version_adder(path: str | pathlib.Path, extension: str | None = None) -> pathlib.Path:
    """Return a non-colliding file path by appending ``_v00``, ``_v01``, ... if needed.

    Parameters
    ----------
    path
        Desired file path.
    extension
        Optional extension override (e.g. ``".xlsx"``).

    Returns
    -------
    pathlib.Path
        Original path if unused, otherwise a versioned sibling path.
    """
    target = pathlib.Path(path)
    if extension is not None:
        ext = extension if extension.startswith(".") else f".{extension}"
        if target.suffix.lower() != ext.lower():
            target = target.with_suffix(ext)
    if not target.exists():
        return target
    ver = 0
    while True:
        candidate = target.with_name(f"{target.stem}_v{ver:02d}{target.suffix}")
        if not candidate.exists():
            return candidate
        ver += 1


def write_excel_table(
    worksheet: Any,
    df: pd.DataFrame,
    startrow: int = 3,
    startcol: int = 0,
    header_format: Any = None,
    table_style: str = "Table Style Medium 2",
    min_width: int = 8,
    max_width: int = 60,
) -> None:
    """Write *df* as a formatted Excel Table with auto-sized columns onto *worksheet*.

    Parameters
    ----------
    worksheet
        XlsxWriter worksheet object.
    df
        DataFrame to write.
    startrow
        Zero-based top row index for the table header.
    startcol
        Zero-based left column index.
    header_format
        Optional XlsxWriter Format applied to header cells.
    table_style
        Built-in Excel table style name.
    min_width
        Minimum auto-fitted column width in characters.
    max_width
        Maximum auto-fitted column width in characters.
    """
    if df.empty:
        return

    work = df.copy()
    if isinstance(work.columns, pd.MultiIndex):
        work.columns = pd.Index([" | ".join(str(x) for x in col) for col in work.columns])

    col_names = [str(c) for c in work.columns]
    # Deduplicate column names as required by Excel Tables
    seen: dict[str, int] = {}
    unique_cols: list[str] = []
    for name in col_names:
        count = seen.get(name, 0)
        seen[name] = count + 1
        unique_cols.append(name if count == 0 else f"{name}_{count}")

    nrows, ncols = work.shape
    rows_data: list[list[Any]] = []
    for row in work.itertuples(index=False, name=None):
        cleaned_row: list[Any] = []
        for val in row:
            if isinstance(val, (bool, np.bool_)):
                cleaned_row.append(bool(val))
            elif val is None or (isinstance(val, float) and pd.isna(val)):
                cleaned_row.append("")
            elif isinstance(val, (pd.Timestamp, datetime.datetime)):
                cleaned_row.append(val.strftime("%Y-%m-%d %H:%M:%S"))
            elif isinstance(val, datetime.date):
                cleaned_row.append(val.strftime("%Y-%m-%d"))
            else:
                cleaned_row.append(val)
        rows_data.append(cleaned_row)

    col_defs: list[dict[str, Any]] = []
    for col_name in unique_cols:
        entry: dict[str, Any] = {"header": col_name}
        if header_format is not None:
            entry["header_format"] = header_format
        col_defs.append(entry)

    worksheet.add_table(
        startrow,
        startcol,
        startrow + nrows,
        startcol + ncols - 1,
        {
            "data": rows_data,
            "columns": col_defs,
            "style": table_style,
        },
    )

    for idx, col_name in enumerate(unique_cols):
        sample_widths = [len(col_name)] + [len(str(row[idx])) for row in rows_data[:200]]
        width = max(min_width, min(max_width, max(sample_widths) + 2))
        worksheet.set_column(startcol + idx, startcol + idx, width)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _call_reader(reader_obj: CrawlReader | MultiDB, method_name: str, **kwargs: Any) -> Any:
    """Invoke *method_name* seamlessly on either a CrawlReader or MultiDB instance."""
    if isinstance(reader_obj, MultiDB):
        return reader_obj.query(method_name, **kwargs)
    return getattr(reader_obj, method_name)(**kwargs)


def _coerce_reader(
    db: CrawlReader | MultiDB | str | pathlib.Path | Sequence[str | pathlib.Path],
) -> tuple[CrawlReader | MultiDB, bool]:
    """Normalize *db* into a ``(CrawlReader | MultiDB, should_close)`` pair."""
    if isinstance(db, (CrawlReader, MultiDB)):
        return db, False
    if isinstance(db, pathlib.Path):
        return CrawlReader(db), True
    if isinstance(db, str):
        parts = [p.strip() for p in db.split(",") if p.strip()]
        if len(parts) > 1:
            return MultiDB(parts), False
        return CrawlReader(parts[0]), True
    items = list(db)
    if len(items) == 1:
        return CrawlReader(items[0]), True
    return MultiDB(items), False


def _write_limit_note(ws: Any, cell: str, limit: int | None) -> None:
    """Write a neutral row-limit note into *cell* when *limit* is set."""
    if limit is not None and limit > 0:
        ws.write(cell, f"Note: This sheet is limited to the top {limit} entries per fileshare.")


def _write_pii_sheet(
    book: Any,
    reader_obj: CrawlReader | MultiDB,
    table: str,
    owner: str | None,
    subdir: str | None,
    limit: int | None,
) -> None:
    """Populate the Possible PII Locations sheet combining name and content hits."""
    ws = book.add_worksheet("Possible PII Locations")
    ws.write(
        "A1",
        "Files and folders matching PII keywords in names or scanned file content.",
    )
    ws.write("A2", f"Keywords checked: {', '.join(PII_KEYWORDS)}")
    _write_limit_note(ws, "A3", limit)

    parts: list[pd.DataFrame] = []
    pii_name = _call_reader(
        reader_obj,
        "find_pii_by_name",
        obj="fname",
        limit=limit,
        table=table,
        owner=owner,
        subdir=subdir,
    )
    if not isinstance(pii_name, pd.DataFrame) or pii_name.empty:
        pii_name = _call_reader(
            reader_obj,
            "find_pii_by_name",
            obj="path",
            limit=limit,
            table=table,
            owner=owner,
            subdir=subdir,
        )
    if isinstance(pii_name, pd.DataFrame) and not pii_name.empty:
        parts.append(pii_name.drop(columns=["Id"], errors="ignore"))

    pii_content = _call_reader(
        reader_obj,
        "find_pii_by_content",
        limit=limit,
        table=table,
        owner=owner,
        subdir=subdir,
    )
    if isinstance(pii_content, pd.DataFrame) and not pii_content.empty:
        parts.append(pii_content)

    if parts:
        combined = pd.concat(parts, ignore_index=True)
        write_excel_table(ws, combined, startrow=4)
    else:
        ws.write("A4", "No files or folders matched the configured PII keywords.")


def _write_summary_sheet(
    book: Any,
    reader_obj: CrawlReader | MultiDB,
    table: str,
    owner: str | None,
    subdir: str | None,
    limit: int | None,
    title_format: Any,
) -> None:
    """Write the executive Summary worksheet with audit metadata and cell comments."""
    ws = book.add_worksheet("Summary")
    try:
        nice_date = str(datetime.datetime.strptime(table, TIMESTAMP_FORMAT))
    except ValueError:
        nice_date = table

    ws.write("A1", "LANspector Summary Report", title_format)
    ws.write("C1", f"Generated by LANspector v{_package_version()}")
    ws.write("A2", "Crawl timestamp:")
    ws.write("B2", nice_date)
    if subdir:
        ws.write("C2", f"Filtered to subdirectory: {subdir}")
    if owner:
        ws.write("D2", f"Filtered to owner: {owner}")

    raw_summary = _call_reader(
        reader_obj, "executive_summary", table=table, owner=owner, subdir=subdir
    )
    summaries: list[ExecutiveSummary] = (
        raw_summary if isinstance(raw_summary, list) else [raw_summary]
    )

    info_df = pd.DataFrame.from_records([s.info for s in summaries if s.info])
    all_acls = sorted({a for s in summaries for a in s.acls_found})
    all_owners = sorted({o for s in summaries for o in s.owners_found})

    max_len = max(len(info_df), len(all_acls), len(all_owners), 1)
    if len(info_df) < max_len:
        pad = pd.DataFrame(index=range(max_len - len(info_df)), columns=info_df.columns)
        info_df = pd.concat([info_df, pad], ignore_index=True)

    info_df["ACLs found"] = all_acls + [None] * (max_len - len(all_acls))
    info_df["Users which Own Files/Folders"] = all_owners + [None] * (max_len - len(all_owners))

    rename_map = {
        "path": "Path",
        "scan_start": "Scan Start",
        "scan_end": "Scan End",
        "scan_files": "Scan Files",
        "scan_directories": "Scan Directories",
        "scan_permissions": "Scan Permissions",
        "detect_pii_content": "Scan PII Content",
        "limit": "Scan Limit",
        "max_depth": "Scan Depth",
        "lanspector_version": "LANspector Version",
        "total size": "size",
    }
    info_df = info_df.drop(columns=["scan_md5", "skip_size", "table"], errors="ignore")
    info_df = info_df.rename(columns=rename_map)
    for bool_col in ("Scan Files", "Scan Directories", "Scan Permissions", "Scan PII Content"):
        if bool_col in info_df.columns:
            info_df[bool_col] = (
                info_df[bool_col]
                .astype(object)
                .map(lambda v: None if (v is None or pd.isna(v)) else bool(v))
            )
    info_df = scale_bytes_cols(info_df)

    start_row = 4
    write_excel_table(ws, info_df, startrow=start_row)

    comments = {
        "Path": "Root path crawled by LANspector.",
        "Scan Start": "Timestamp when the crawl started.",
        "Scan End": "Timestamp when the crawl completed.",
        "ACLs found": "Distinct ACL principals discovered across the crawl.",
        "Users which Own Files/Folders": "Distinct file/folder owners; group ownership is recommended.",
    }
    cols = list(info_df.columns)
    for col_name, note in comments.items():
        if col_name in cols:
            ws.write_comment(xl_rowcol_to_cell(start_row, cols.index(col_name)), note)
    _write_limit_note(ws, "A3", limit)
