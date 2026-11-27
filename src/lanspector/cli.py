"""Command-line interface for ``lanspector`` powered by ``jsonargparse``."""

from __future__ import annotations

import pathlib
import sys
from collections.abc import Sequence

import pandas as pd
from jsonargparse import auto_cli
from loguru import logger
from tqdm import tqdm

from lanspector.constants import XLSX_SAFE_OPTIONS
from lanspector.crawler import _package_version, _path_to_db_name, crawl, crawl_driver
from lanspector.datatypes import LogLevel
from lanspector.reader import CrawlReader
from lanspector.reporting import generate_fileshare_report, generate_open_shares_summary_report
from lanspector.settings import (
    CompareSettings,
    CrawlSettings,
    DashboardPrepSettings,
    DashboardServeSettings,
    GuiSettings,
    ReportSettings,
    SharesListSettings,
    SunburstSettings,
)
from lanspector.shares import list_all_shares_in_domain, list_shares
from lanspector.sunburst import export_sunburst_html


def _as_path_list(value: pathlib.Path | list[pathlib.Path]) -> list[pathlib.Path]:
    """Normalize a single Path or list of Paths into a list."""
    return [value] if isinstance(value, pathlib.Path) else list(value)


def _as_str_list(value: str | list[str]) -> list[str]:
    """Normalize a single string or list of strings into a list."""
    return [value] if isinstance(value, str) else list(value)


def _configure_logging(level: LogLevel) -> None:
    """Configure loguru stderr sink at *level*, cooperating with tqdm on TTYs."""
    logger.remove()
    fmt = "{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {name} - {message}"
    if sys.stderr.isatty():
        logger.add(
            lambda msg: tqdm.write(msg, file=sys.stderr, end=""),
            level=level,
            format=fmt,
        )
    else:
        logger.add(sys.stderr, level=level, format=fmt)


# ---------------------------------------------------------------------------
# Primary CLI entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``lanspector`` CLI.

    Exposes typed subcommands backed by :mod:`lanspector.settings` dataclasses:
    ``crawl``, ``report``, ``sunburst``, ``compare``, ``dashboard-prep``,
    ``dashboard``, ``gui``, and ``shares``.

    Parameters
    ----------
    argv
        Optional argument list (defaults to ``sys.argv[1:]``).

    Returns
    -------
    int
        Process exit status code (``0`` on success, non-zero on error).
    """
    settings = auto_cli(
        {
            "crawl": CrawlSettings,
            "report": ReportSettings,
            "sunburst": SunburstSettings,
            "compare": CompareSettings,
            "dashboard-prep": DashboardPrepSettings,
            "dashboard": DashboardServeSettings,
            "gui": GuiSettings,
            "shares": SharesListSettings,
        },
        args=list(argv) if argv is not None else None,
        as_positional=False,
        version=_package_version(),
        description=(
            "LANspector: cross-platform LAN & Windows fileshare auditing, "
            "SOX permission-diff Excel reporting, and interactive Plotly storage sunbursts. "
            "Pass --config <file.yaml> to load settings from a YAML/JSON file, or "
            "<subcommand> --print_config to print a starter YAML template."
        ),
    )

    if isinstance(settings, CrawlSettings):
        return run_crawl(settings)
    if isinstance(settings, ReportSettings):
        return run_report(settings)
    if isinstance(settings, SunburstSettings):
        return run_sunburst(settings)
    if isinstance(settings, CompareSettings):
        return run_compare(settings)
    if isinstance(settings, DashboardPrepSettings):
        return run_dashboard_prep(settings)
    if isinstance(settings, DashboardServeSettings):
        return run_dashboard_serve(settings)
    if isinstance(settings, GuiSettings):
        return run_gui(settings)
    return run_shares(settings)


# ---------------------------------------------------------------------------
# Subcommand handlers (alphabetical)
# ---------------------------------------------------------------------------


def run_compare(settings: CompareSettings) -> int:
    """Execute ``lanspector compare`` to inspect permission and object drift between crawls.

    Parameters
    ----------
    settings
        Parsed CLI settings for comparison.

    Returns
    -------
    int
        Exit status code (``0`` on success, ``1`` on error).
    """
    _configure_logging(settings.log_level)
    if not settings.database.exists():
        logger.error("Crawl database not found: {}", settings.database)
        return 1

    with CrawlReader(settings.database) as reader:
        if len(reader.crawls) < 2 and (
            settings.table_before is None or settings.table_after is None
        ):
            logger.error("Database {} contains fewer than 2 crawls.", settings.database)
            return 1
        diffs = reader.compare_crawls(
            table1=settings.table_before,
            table2=settings.table_after,
            subdir=settings.subdir,
        )

    for section, df in diffs.items():
        print(f"{section}: {len(df)} rows")

    if settings.output is not None:
        settings.output.parent.mkdir(parents=True, exist_ok=True)
        with pd.ExcelWriter(
            settings.output, engine="xlsxwriter", engine_kwargs={"options": XLSX_SAFE_OPTIONS}
        ) as writer:
            for section, df in diffs.items():
                df.to_excel(writer, sheet_name=section[:31], index=False)
        print(f"Wrote comparison workbook to {settings.output.resolve()}")

    return 0


def run_crawl(settings: CrawlSettings) -> int:
    """Execute ``lanspector crawl`` for a single path or a multi-target driver file.

    Parameters
    ----------
    settings
        Parsed CLI settings for crawling.

    Returns
    -------
    int
        Exit status code (``0`` on success, ``1`` on invalid inputs).
    """
    _configure_logging(settings.log_level)

    if settings.driver is not None:
        if not settings.driver.exists():
            logger.error("Driver file not found: {}", settings.driver)
            return 1
        targets = crawl_driver(settings)
        print(f"Driver crawl processed {len(targets)} target(s).")
        return 0

    if settings.path is None:
        logger.error(
            "Missing required target: pass --path <directory> or --driver <driver_file>. "
            "Example: lanspector crawl --path /path/to/share --fout share.db"
        )
        return 1

    if not settings.path.exists():
        logger.error("Target path does not exist: {}", settings.path)
        return 1

    resolved_fout = settings.fout
    if resolved_fout is None:
        resolved_fout = pathlib.Path.cwd() / _path_to_db_name(str(settings.path.resolve()))
        logger.info("No --fout supplied; defaulting crawl database to {}", resolved_fout.resolve())

    crawl(
        path=settings.path,
        scantype=settings.scantype,
        permissions=settings.permissions,
        fout=resolved_fout,
        max_md5=settings.max_md5,
        skip_size=settings.skip_size,
        crawl_acls=settings.crawl_acls,
        summarize=settings.summarize,
        sunburst_html=settings.sunburst_html,
        limit=settings.limit,
        max_depth=settings.max_depth,
        detect_pii_content=settings.detect_pii,
        use_ner=settings.use_ner,
        resume=settings.resume,
    )
    return 0


def run_dashboard_prep(settings: DashboardPrepSettings) -> int:
    """Execute ``lanspector dashboard-prep`` to populate a LANdash SQLite store.

    Parameters
    ----------
    settings
        Parsed CLI settings for dashboard data preparation.

    Returns
    -------
    int
        Exit status code (``0`` on success, ``1`` if no crawl databases found).
    """
    _configure_logging(settings.log_level)
    from lanspector.dashboard.data_prep import commit_data_to_database, generate_dashboard_data

    databases = _as_path_list(settings.databases)
    if not databases:
        logger.error("No crawl databases provided. Pass --databases crawl.db or '[a.db, b.db]'.")
        return 1

    missing = [p for p in databases if not p.exists()]
    if missing:
        logger.error("Crawl database(s) not found: {}", ", ".join(str(m) for m in missing))
        return 1

    # Deduplicate while preserving order, and exclude the destination dashboard DB itself
    dest_resolved = settings.dashboard_db.resolve()
    unique_dbs: list[pathlib.Path] = []
    seen: set[pathlib.Path] = set()
    for p in databases:
        rp = p.resolve()
        if rp != dest_resolved and rp not in seen:
            seen.add(rp)
            unique_dbs.append(p)

    if not unique_dbs:
        logger.error(
            "No crawl databases remaining after excluding destination dashboard DB: {}",
            dest_resolved,
        )
        return 1

    access_df, members_df, burst_df = generate_dashboard_data(
        unique_dbs,
        include_ntfs=settings.include_ntfs,
        include_acls=settings.include_acls,
        include_sunburst=settings.include_sunburst,
    )
    commit_data_to_database(settings.dashboard_db, access_df, members_df, burst_df)
    logger.info(
        "Updated LANdash store {} from {} database(s) (access={}, memberships={}, sunburst={}).",
        dest_resolved,
        len(unique_dbs),
        len(access_df),
        len(members_df),
        len(burst_df),
    )
    logger.info("Launch the dashboard with: lanspector dashboard --dashboard_db {}", dest_resolved)
    return 0


def run_dashboard_serve(settings: DashboardServeSettings) -> int:
    """Execute ``lanspector dashboard`` to launch the LANdash web server.

    Parameters
    ----------
    settings
        Parsed CLI settings for serving the Dash web application.

    Returns
    -------
    int
        Exit status code.
    """
    _configure_logging(settings.log_level)
    from lanspector.dashboard.app import run_dashboard

    return run_dashboard(settings)


def run_gui(settings: GuiSettings) -> int:
    """Execute ``lanspector gui`` to launch the optional Tkinter desktop GUI.

    Parameters
    ----------
    settings
        Parsed CLI settings for the desktop GUI.

    Returns
    -------
    int
        Exit status code.
    """
    _configure_logging(settings.log_level)
    from lanspector.gui import launch_gui

    return launch_gui(settings)


def run_report(settings: ReportSettings) -> int:
    """Execute ``lanspector report`` to build an Excel SOX/audit workbook.

    Parameters
    ----------
    settings
        Parsed CLI settings for report generation.

    Returns
    -------
    int
        Exit status code (``0`` on success, ``1`` on missing databases).
    """
    _configure_logging(settings.log_level)
    databases = _as_path_list(settings.databases)
    if not databases:
        logger.error("No crawl databases provided. Pass --databases crawl.db or '[a.db, b.db]'.")
        return 1

    missing = [p for p in databases if not p.exists()]
    if missing:
        logger.error("Crawl database(s) not found: {}", ", ".join(str(m) for m in missing))
        return 1

    if settings.open_shares:
        generate_open_shares_summary_report(databases, settings.output)
        return 0

    generate_fileshare_report(
        db=databases,
        fout=settings.output,
        table=settings.table,
        limit=settings.limit,
        owner=settings.owner,
        subdir=settings.subdir,
        per_user=settings.per_user,
        use_permission_hierarchy=settings.use_permission_hierarchy,
        skip_files_report=settings.skip_files_report,
        skip_user_owner_report=settings.skip_user_owner_report,
        report_pii=settings.report_pii,
    )
    return 0


def run_shares(settings: SharesListSettings) -> int:
    """Execute ``lanspector shares`` to discover SMB shares across servers or domains.

    Parameters
    ----------
    settings
        Parsed CLI settings for share discovery.

    Returns
    -------
    int
        Exit status code.
    """
    _configure_logging(settings.log_level)
    domains = _as_str_list(settings.domains)
    servers = _as_str_list(settings.servers)
    results: list[dict[str, object]] = []
    if domains:
        results.extend(
            list_all_shares_in_domain(
                domains,
                test_connectivity=settings.test_connectivity,
                get_share_permissions=settings.get_share_permissions,
                skip_admin_shares=settings.skip_admin_shares,
            )
        )
    if servers:
        results.extend(
            list_shares(
                servers=servers,
                get_share_permissions=settings.get_share_permissions,
                skip_admin_shares=settings.skip_admin_shares,
            )
        )

    df = pd.DataFrame.from_records(results)
    if settings.output is not None and not df.empty:
        settings.output.parent.mkdir(parents=True, exist_ok=True)
        if settings.output.suffix.lower() == ".xlsx":
            df.to_excel(settings.output, index=False)
        else:
            df.to_csv(settings.output, index=False)
        print(f"Exported {len(df)} share record(s) to {settings.output.resolve()}")
    else:
        print(f"Discovered {len(df)} share record(s).")
        if not df.empty:
            print(df.to_string(index=False))
    return 0


def run_sunburst(settings: SunburstSettings) -> int:
    """Execute ``lanspector sunburst`` to export an interactive Plotly HTML sunburst chart.

    Parameters
    ----------
    settings
        Parsed CLI settings for sunburst generation.

    Returns
    -------
    int
        Exit status code (``0`` on success, ``1`` if database is missing).
    """
    _configure_logging(settings.log_level)
    if not settings.database.exists():
        logger.error("Crawl database not found: {}", settings.database)
        return 1

    export_sunburst_html(
        reader=settings.database,
        output=settings.output,
        table=settings.table,
        subdir=settings.subdir,
        limit=settings.limit,
        max_depth=settings.max_depth,
        color_by=settings.color_by,
        include_plotlyjs=settings.include_plotlyjs,
        open_browser=settings.open_browser,
    )
    return 0
