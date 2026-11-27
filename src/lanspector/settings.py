"""Dataclass configuration models for the ``lanspector`` CLI.

Parsed automatically by :mod:`jsonargparse`, supporting both command-line flags
and YAML/JSON configuration files (``--config``).
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from lanspector.datatypes import LogLevel, PlotlyJsMode, ScanType, SunburstColorBy


@dataclass
class CrawlSettings:
    """Crawl a directory/fileshare (``--path``) or batch target list (``--driver``).

    Provide either ``--path`` (single folder or UNC share) or ``--driver`` (batch
    file of paths/servers/domains). When ``--fout`` is omitted on the CLI, output
    defaults to ``./<target>.db`` in the current working directory and an Excel
    audit summary report is written alongside it (``--summarize true``).

    Attributes
    ----------
    path
        Root directory or UNC fileshare path to crawl (required unless ``--driver`` is set).
    fout
        Output database or file path (``.db``, ``.sqlite``, ``.sqlite3``, ``.csv``, ``.xlsx``).
        Defaults to ``./<target>.db`` in the current working directory when omitted.
    driver
        Optional text driver file listing paths, server names, or ``DN: <Domain>`` entries
        for parallel multi-share crawling.
    driver_out
        Directory to store per-share crawl databases when ``driver`` is specified.
    dryrun
        When used with ``driver``, discover targets without crawling them.
    scantype
        Objects to harvest: ``d`` (directories), ``f`` (files), or ``fd`` (both).
    permissions
        Harvest NTFS/POSIX effective permissions for each crawled object.
    crawl_acls
        Query Active Directory for group membership of discovered ACLs (Windows only).
    max_md5
        Compute MD5 checksums for files smaller than this threshold in bytes (``None`` disables).
    skip_size
        Skip aggregating file sizes inside directories when ``scantype='d'``.
    limit
        Stop crawling after this many objects (``0`` means unlimited).
    max_depth
        Stop crawling after this many directory levels below ``path`` (``0`` means unlimited).
    detect_pii
        Inspect supported file contents (``.txt``, ``.csv``, ``.xlsx``) for PII indicators.
    use_ner
        Enable optional NLTK named-entity recognition during PII content scanning.
    summarize
        Generate a formatted Excel audit report alongside the SQLite database (default ``True``).
    sunburst_html
        Optional path to export a standalone interactive Plotly storage sunburst HTML file.
    resume
        Resume an interrupted crawl (where ``scan_end`` is ``NULL`` in ``CRAWL_INFO``)
        in ``fout``, skipping already-persisted directories and files.
    n_procs
        Maximum concurrent crawl worker processes in ``driver`` mode.
    log_level
        Loguru logging verbosity.
    """

    path: pathlib.Path | None = None
    fout: pathlib.Path | None = None
    driver: pathlib.Path | None = None
    driver_out: pathlib.Path | None = None
    dryrun: bool = False
    scantype: ScanType = "fd"
    permissions: bool = True
    crawl_acls: bool = True
    max_md5: int | None = None
    skip_size: bool = False
    limit: int = 0
    max_depth: int = 0
    detect_pii: bool = False
    use_ner: bool = False
    summarize: bool = True
    sunburst_html: pathlib.Path | None = None
    resume: bool = False
    n_procs: int | None = None
    log_level: LogLevel = "INFO"


@dataclass
class CompareSettings:
    """Configuration for ``lanspector compare``.

    Attributes
    ----------
    database
        Path to a LANspector SQLite crawl database containing at least two crawls.
    table_before
        Earlier crawl table name (defaults to second-most-recent crawl).
    table_after
        Later crawl table name (defaults to most-recent crawl).
    output
        Optional Excel workbook path to export permission and file diffs.
    subdir
        Optional subdirectory prefix to restrict comparison.
    log_level
        Loguru logging verbosity.
    """

    database: pathlib.Path
    table_before: str | None = None
    table_after: str | None = None
    output: pathlib.Path | None = None
    subdir: str | None = None
    log_level: LogLevel = "INFO"


@dataclass
class DashboardPrepSettings:
    """Prepare or update the LANdash SQLite store from one or more crawl databases.

    Run this subcommand before ``lanspector dashboard``. Explicitly list the crawl
    databases to ingest via ``--databases '[crawl1.db, crawl2.db]'``.

    Example::

        lanspector dashboard-prep --databases '[finance.db, hr.db]' --dashboard_db landash.sqlite
        lanspector dashboard --dashboard_db landash.sqlite

    Attributes
    ----------
    databases
        One or more LANspector SQLite crawl database paths (e.g. ``--databases a.db``
        or ``--databases '[a.db, b.db]'``).
    dashboard_db
        Destination SQLite database path for the LANdash web app (default ``landash.sqlite``).
    include_ntfs
        Extract parent-vs-child NTFS/POSIX permission timelines.
    include_acls
        Extract ACL group membership records.
    include_sunburst
        Extract directory storage & access-time records for sunburst exploration.
    log_level
        Loguru logging verbosity.
    """

    databases: pathlib.Path | list[pathlib.Path] = field(default_factory=list)
    dashboard_db: pathlib.Path = pathlib.Path("landash.sqlite")
    include_ntfs: bool = True
    include_acls: bool = True
    include_sunburst: bool = True
    log_level: LogLevel = "INFO"


@dataclass
class DashboardServeSettings:
    """Launch the interactive LANdash web dashboard (requires ``lanspector[dashboard]``).

    Before launching the dashboard, aggregate one or more crawl databases into a
    LANdash SQLite store using ``lanspector dashboard-prep``:

    Example::

        lanspector dashboard-prep --databases '[finance.db]' --dashboard_db landash.sqlite
        lanspector dashboard --dashboard_db landash.sqlite --port 8050

    Attributes
    ----------
    dashboard_db
        Path to the prepared LANdash SQLite database created by ``lanspector dashboard-prep``
        (default ``landash.sqlite``).
    host
        Interface address to bind the Dash server to.
    port
        TCP port for the Dash server.
    debug
        Run Dash in development debug mode.
    log_level
        Loguru logging verbosity.
    """

    dashboard_db: pathlib.Path = pathlib.Path("landash.sqlite")
    host: str = "127.0.0.1"
    port: int = 8050
    debug: bool = False
    log_level: LogLevel = "INFO"


@dataclass
class GuiSettings:
    """Configuration for ``lanspector gui``.

    Attributes
    ----------
    database
        Optional initial crawl database path to pre-populate in the GUI.
    path
        Optional initial directory path to pre-populate in the New Crawl tab.
    log_level
        Loguru logging verbosity.
    """

    database: pathlib.Path | None = None
    path: pathlib.Path | None = None
    log_level: LogLevel = "INFO"


@dataclass
class ReportSettings:
    """Configuration for ``lanspector report``.

    Attributes
    ----------
    databases
        One or more LANspector SQLite crawl database paths.
    output
        Destination Excel workbook path (``.xlsx``).
    table
        Crawl timestamp table name (defaults to latest crawl).
    limit
        Maximum rows written to detail sheets (``None`` or ``0`` means unlimited).
    owner
        Optional owner filter to generate a single-owner report.
    subdir
        Optional subdirectory filter.
    per_user
        Generate separate per-owner Excel workbooks alongside the main workbook.
    use_permission_hierarchy
        Collapse subordinate permissions (e.g. ``MR`` -> ``M``, ``F`` dominates all).
    skip_files_report
        Omit the ``file_vs_folderACL`` sheet.
    skip_user_owner_report
        Omit the ``Objects Owned by User`` sheet.
    report_pii
        Include the ``Possible PII Locations`` sheet.
    open_shares
        Generate an Open Shares summary workbook instead of a full fileshare audit report.
    log_level
        Loguru logging verbosity.
    """

    databases: pathlib.Path | list[pathlib.Path] = field(default_factory=list)
    output: pathlib.Path = pathlib.Path("lanspector_report.xlsx")
    table: str | None = None
    limit: int | None = 500
    owner: str | None = None
    subdir: str | None = None
    per_user: bool = False
    use_permission_hierarchy: bool = False
    skip_files_report: bool = False
    skip_user_owner_report: bool = False
    report_pii: bool = True
    open_shares: bool = False
    log_level: LogLevel = "INFO"


@dataclass
class SharesListSettings:
    """Configuration for ``lanspector shares``.

    Attributes
    ----------
    servers
        Fileserver hostnames or IPs to probe for SMB shares (Windows only).
    domains
        Active Directory domain names to enumerate servers and shares (Windows only).
    test_connectivity
        Filter servers by attempting a TCP connection to SMB port 445 first.
    get_share_permissions
        Harvest share-level DACL permissions alongside share names.
    skip_admin_shares
        Skip administrative shares ending in ``$``.
    output
        Optional CSV or Excel path to export discovered shares.
    log_level
        Loguru logging verbosity.
    """

    servers: str | list[str] = field(default_factory=list)
    domains: str | list[str] = field(default_factory=list)
    test_connectivity: bool = False
    get_share_permissions: bool = True
    skip_admin_shares: bool = True
    output: pathlib.Path | None = None
    log_level: LogLevel = "INFO"


@dataclass
class SunburstSettings:
    """Configuration for ``lanspector sunburst``.

    Attributes
    ----------
    database
        Path to a LANspector SQLite crawl database.
    output
        Destination standalone HTML file path.
    table
        Crawl timestamp table name (defaults to latest crawl).
    subdir
        Optional subdirectory filter.
    limit
        Maximum directories to include in the chart.
    max_depth
        Optional maximum folder depth rendered in the sunburst rings.
    color_by
        Color scale metric: ``age`` (days since last access) or ``size`` (bytes).
    include_plotlyjs
        ``inline`` embeds Plotly.js for offline/air-gapped use; ``cdn`` keeps the HTML small.
    open_browser
        Automatically open the generated HTML file in the system browser.
    log_level
        Loguru logging verbosity.
    """

    database: pathlib.Path
    output: pathlib.Path = pathlib.Path("lanspector_sunburst.html")
    table: str | None = None
    subdir: str | None = None
    limit: int | None = 500
    max_depth: int | None = None
    color_by: SunburstColorBy = "age"
    include_plotlyjs: PlotlyJsMode = "inline"
    open_browser: bool = False
    log_level: LogLevel = "INFO"
