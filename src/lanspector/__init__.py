"""LANspector: cross-platform LAN & Windows fileshare auditing, SOX reporting, and storage sunbursts."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from lanspector import constants, datatypes, pii, platform, settings, shares, sunburst
from lanspector.cli import (
    main,
    run_compare,
    run_crawl,
    run_dashboard_prep,
    run_dashboard_serve,
    run_gui,
    run_report,
    run_shares,
    run_sunburst,
)
from lanspector.crawler import (
    convert_to_sqlite,
    crawl,
    crawl_by_existing_dbs,
    crawl_driver,
    md5sum,
    yield_filesystem,
)
from lanspector.datatypes import (
    CrawlEntry,
    CrawlResult,
    ExecutiveSummary,
    ParentChildResult,
    PermissionEntry,
    PiiFinding,
    SharePermissionEntry,
)
from lanspector.reader import CrawlReader, MultiDB, melt_parent_vs_child, nearest_crawl_to_date
from lanspector.reporting import (
    generate_fileshare_report,
    generate_open_shares_summary_report,
    scale_bytes_cols,
    version_adder,
    write_excel_table,
)
from lanspector.sunburst import (
    build_sunburst_figure,
    export_sunburst_html,
    format_bytes,
    paths_to_flare_dict,
    paths_to_hierarchy_df,
)

try:
    __version__ = version("lanspector")
except PackageNotFoundError:
    __version__ = "0.0.0.dev0"

__all__ = [
    "CrawlEntry",
    "CrawlReader",
    "CrawlResult",
    "ExecutiveSummary",
    "MultiDB",
    "ParentChildResult",
    "PermissionEntry",
    "PiiFinding",
    "SharePermissionEntry",
    "__version__",
    "build_sunburst_figure",
    "constants",
    "convert_to_sqlite",
    "crawl",
    "crawl_by_existing_dbs",
    "crawl_driver",
    "datatypes",
    "export_sunburst_html",
    "format_bytes",
    "generate_fileshare_report",
    "generate_open_shares_summary_report",
    "main",
    "md5sum",
    "melt_parent_vs_child",
    "nearest_crawl_to_date",
    "paths_to_flare_dict",
    "paths_to_hierarchy_df",
    "pii",
    "platform",
    "run_compare",
    "run_crawl",
    "run_dashboard_prep",
    "run_dashboard_serve",
    "run_gui",
    "run_report",
    "run_shares",
    "run_sunburst",
    "scale_bytes_cols",
    "settings",
    "shares",
    "sunburst",
    "version_adder",
    "write_excel_table",
    "yield_filesystem",
]
