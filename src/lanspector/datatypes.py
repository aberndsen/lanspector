"""Typed data models and type aliases used across LANspector."""

from __future__ import annotations

import datetime
import pathlib
from dataclasses import dataclass, field
from typing import Any, Literal

import pandas as pd

ScanType = Literal["d", "f", "fd"]
LogLevel = Literal["ERROR", "WARNING", "INFO", "DEBUG", "TRACE"]
SunburstColorBy = Literal["age", "size"]
PlotlyJsMode = Literal["cdn", "inline"]


@dataclass(slots=True)
class CrawlEntry:
    """Metadata harvested for a single directory or file entry.

    Attributes
    ----------
    path
        Normalized directory path containing the object (or the directory itself).
    fname
        Filename when the entry is a file, or ``None`` for directories.
    bytes
        Size in bytes (sum of contained files for directories when not skipped).
    owner
        Account name owning the file or directory.
    ctime
        Creation / metadata-change timestamp.
    atime
        Last access timestamp.
    mtime
        Last modification timestamp.
    md5
        Optional MD5 hex digest.
    is_symlink
        Whether the object is a symbolic link.
    entry_id
        Assigned integer primary key during crawl persistence.
    """

    path: str
    fname: str | None = None
    bytes: int = 0
    owner: str | None = None
    ctime: datetime.datetime | None = None
    atime: datetime.datetime | None = None
    mtime: datetime.datetime | None = None
    md5: str | None = None
    is_symlink: bool = False
    entry_id: int | None = None

    def to_record(self) -> dict[str, Any]:
        """Convert this entry into a flat SQLite/DataFrame record dictionary."""
        return {
            "Id": self.entry_id,
            "path": self.path,
            "fname": self.fname,
            "bytes": self.bytes,
            "owner": self.owner,
            "ctime": self.ctime,
            "atime": self.atime,
            "mtime": self.mtime,
            "md5": self.md5,
        }


@dataclass(slots=True)
class CrawlResult:
    """Outcome returned by :func:`lanspector.crawler.crawl`.

    Attributes
    ----------
    tablename
        Timestamp identifier of the crawl table (``YYYYMMDDTHHMMSS``).
    output_path
        Destination file path if persisted to disk, otherwise ``None``.
    files_df
        In-memory metadata DataFrame when ``fout`` is ``None`` (empty otherwise).
    perms_df
        In-memory permissions DataFrame when ``fout`` is ``None`` (empty otherwise).
    pii_df
        In-memory PII findings DataFrame when ``fout`` is ``None`` (empty otherwise).
    objects_processed
        Total count of directories and files harvested during the crawl.
    report_path
        Path to the generated Excel summary workbook if ``summarize=True``.
    sunburst_path
        Path to the generated standalone Plotly HTML sunburst chart if requested.
    """

    tablename: str
    output_path: pathlib.Path | None = None
    files_df: pd.DataFrame = field(default_factory=pd.DataFrame)
    perms_df: pd.DataFrame = field(default_factory=pd.DataFrame)
    pii_df: pd.DataFrame = field(default_factory=pd.DataFrame)
    objects_processed: int = 0
    report_path: pathlib.Path | None = None
    sunburst_path: pathlib.Path | None = None


@dataclass(slots=True)
class ExecutiveSummary:
    """High-level audit rollup returned by :meth:`lanspector.reader.CrawlReader.executive_summary`.

    Attributes
    ----------
    info
        Crawl metadata and object counts/total size mapping.
    acls_found
        Distinct ACL names discovered across the crawl.
    owners_found
        Distinct file/folder owners discovered across the crawl.
    """

    info: dict[str, Any]
    acls_found: list[str] = field(default_factory=list)
    owners_found: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ParentChildResult:
    """Result of the compressed parent-vs-child ACL difference report.

    Attributes
    ----------
    dirs_df
        Folder permission-difference DataFrame (root + folders differing from parent),
        or ``None`` when no directory permissions exist.
    files_df
        File-vs-folder elevated-permission DataFrame, or ``None`` when skipped or empty.
    """

    dirs_df: pd.DataFrame | None
    files_df: pd.DataFrame | None


@dataclass(slots=True)
class PermissionEntry:
    """Single effective ACL/permission entry for a path or file.

    Attributes
    ----------
    domain
        Domain or authority name (e.g. Windows domain, ``BUILTIN``, or ``POSIX``).
    name
        Account, group, or SID label.
    permission
        Normalized permission string (e.g. ``Read(RX)``, ``Change``, ``Full Control(All)``).
    object_type
        Principal category (``User``, ``Group``, ``WellKnownGroup``, ``dead``, etc.).
    entry_id
        Foreign key matching :attr:`CrawlEntry.entry_id`.
    """

    domain: str
    name: str
    permission: str
    object_type: str
    entry_id: int | None = None

    def to_record(self) -> dict[str, Any]:
        """Convert this permission entry into a SQLite/DataFrame record dictionary."""
        return {
            "Id": self.entry_id,
            "Domain": self.domain,
            "Name": self.name,
            "Permission": self.permission,
            "ObjectType": self.object_type,
        }


@dataclass(slots=True)
class PiiFinding:
    """Single PII keyword or named-entity match within a crawled file.

    Attributes
    ----------
    pii_word_id
        Index into :data:`lanspector.constants.PII_KEYWORDS`.
    snippet
        Contextual text snippet surrounding the match.
    entry_id
        Foreign key matching :attr:`CrawlEntry.entry_id`.
    """

    pii_word_id: int
    snippet: str
    entry_id: int | None = None

    def to_record(self) -> dict[str, Any]:
        """Convert this finding into a SQLite/DataFrame record dictionary."""
        return {
            "Id": self.entry_id,
            "pii_wordId": self.pii_word_id,
            "snippet": self.snippet,
        }


@dataclass(slots=True)
class SharePermissionEntry:
    """Share-level SMB permission entry harvested from a Windows fileserver.

    Attributes
    ----------
    server
        Server hostname or IP.
    fqdn
        Resolved fully qualified domain name.
    sharename
        SMB share name.
    acl_domain
        Domain of the share-level ACL principal.
    acl_name
        Principal name granted share-level access.
    acl_type
        Principal SID type label.
    permission
        Share-level permission string.
    """

    server: str
    fqdn: str
    sharename: str
    acl_domain: str
    acl_name: str
    acl_type: str
    permission: str

    def to_record(self) -> dict[str, Any]:
        """Convert this share permission into a SQLite/DataFrame record dictionary."""
        return {
            "server": self.server,
            "fqdn": self.fqdn,
            "sharename": self.sharename,
            "ACLDomain": self.acl_domain,
            "ACLName": self.acl_name,
            "ACLtype": self.acl_type,
            "permission": self.permission,
        }
