"""Immutable constants for LANspector crawling, permissions, PII detection, and reporting."""

from __future__ import annotations

import re

# Database metadata & table suffixes
CRAWL_INFO_TABLE = "CRAWL_INFO"
PERM_TABLE_SUFFIX = "_p"
MEMBER_TABLE_SUFFIX = "_m"
SHARE_PERM_TABLE_SUFFIX = "_sp"
PII_TABLE_SUFFIX = "_pii"
PII_WORDS_TABLE_SUFFIX = "_pii_words"

AUXILIARY_TABLE_SUFFIXES: tuple[str, ...] = (
    PERM_TABLE_SUFFIX,
    MEMBER_TABLE_SUFFIX,
    SHARE_PERM_TABLE_SUFFIX,
    PII_TABLE_SUFFIX,
    PII_WORDS_TABLE_SUFFIX,
)
DASHBOARD_TABLES: frozenset[str] = frozenset(
    {"fileshares", "adobjects", "parentVchild", "acl_membership", "dashburst"}
)

TIMESTAMP_FORMAT = "%Y%m%dT%H%M%S"
DEFAULT_CHUNKSIZE = 900
PROGRESS_LOG_INTERVAL = 10_000

SUPPORTED_DB_EXTENSIONS: tuple[str, ...] = (".db", ".sqlite", ".sqlite3")
SUPPORTED_OUTPUT_EXTENSIONS: tuple[str, ...] = (".csv", ".xlsx", ".db", ".sqlite", ".sqlite3")

# Default columns persisted in crawl tables
CRAWL_DATA_COLUMNS: tuple[str, ...] = (
    "Id",
    "path",
    "fname",
    "bytes",
    "owner",
    "ctime",
    "atime",
    "mtime",
    "md5",
)
PERM_DATA_COLUMNS: tuple[str, ...] = ("Id", "Domain", "Name", "Permission", "ObjectType")
PII_DATA_COLUMNS: tuple[str, ...] = ("Id", "pii_wordId", "snippet")

# Builtin accounts that typically indicate broad or open access
BUILTIN_OPEN_ACCOUNTS: tuple[str, ...] = (
    "Everyone",
    "Users",
    "Domain Users",
    "Authenticated Users",
    "Access Denied",
)

# Win32 NTFS DACL access mask values -> readable permission names
DACL_ACCESS_MASKS: dict[int, str] = {
    1: "ACCESS_READ",
    2: "ACCESS_WRITE",
    4: "ACCESS_CREATE",
    8: "ACCESS_EXEC",
    16: "ACCESS_DELETE",
    32: "ACCESS_ATTRIB",
    64: "ACCESS_PERM",
    128: "Read_Attributes",
    256: "Write_Attributes",
    278: "Write",
    32768: "ACCESS_GROUP",
    65535: "SPECIFIC_RIGHTS_ALL",
    65536: "DELETE",
    131072: "READ_CONTROL",
    131209: "Read",
    131241: "ReadAndExecute",
    262144: "WRITE_DAC",
    524288: "WRITE_OWNER",
    983040: "STANDARD_RIGHTS_REQUIRED",
    1048576: "SYNCHRONIZE",
    1179817: "Read(RX)",
    1180086: "Add",
    1180095: "Add&Read",
    1245631: "Change",
    1245663: "Special",
    2031616: "STANDARD_RIGHTS_ALL",
    2032127: "Full Control(All)",
    16777216: "ACCESS_SYSTEM_SECURITY",
    33554432: "MAXIMUM_ALLOWED",
    268435456: "GENERIC_ALL",
    536870912: "GENERIC_EXECUTE",
    1073741824: "GENERIC_WRITE",
}

# Win32 SID account type enum values -> human-readable labels
SID_TYPES: dict[int, str] = {
    1: "User",
    2: "Group",
    3: "Domain",
    4: "Alias",
    5: "WellKnownGroup",
    6: "DeletedAccount",
    7: "Invalid",
    8: "Unknown",
}

# Bitmask mapping used to aggregate & diff NTFS/POSIX effective permissions
PERM_BIT_READ = 1
PERM_BIT_ADD_READ = 2
PERM_BIT_CHANGE = 4
PERM_BIT_SPECIAL = 8
PERM_BIT_OTHER = 16
PERM_BIT_FULL = 32

NTFS_BITMASK_MAP: dict[str, int] = {
    "Read": PERM_BIT_READ,
    "Read(RX)": PERM_BIT_READ,
    "ReadAndExecute": PERM_BIT_READ,
    "Add": PERM_BIT_ADD_READ,
    "Add&Read": PERM_BIT_ADD_READ,
    "Change": PERM_BIT_CHANGE,
    "Write": PERM_BIT_CHANGE,
    "Special": PERM_BIT_SPECIAL,
    "Full Control(All)": PERM_BIT_FULL,
    "GENERIC_ALL": PERM_BIT_FULL,
}

# Backup filename/path heuristic regex patterns
BACKUP_PATTERNS: tuple[str, ...] = (
    r"\d{4}[-/]\d{2}[-/][012]\d",
    r"[12]\d{3}[01]\d[012]\d",
    r"[12]\d{3}Q[1234]",
    r"\.bak\b",
    r"( v\d+)",
    r"(_v\d+)",
)
BACKUP_REGEXES: tuple[re.Pattern[str], ...] = tuple(re.compile(p, re.I) for p in BACKUP_PATTERNS)

# PII keyword heuristic patterns (kept generic; 'Proper Name' is reserved for optional NER)
PII_PROPER_NAME_LABEL = "Proper Name"
PII_KEYWORDS: tuple[str, ...] = (
    "address",
    "birth",
    r"!\\client",
    "coverage",
    " ids ",
    "identity card",
    "gender",
    "((first)|(last))+ ?name",
    "performance ?reviews?",
    "phone",
    "policy",
    "sex",
    "social",
    "ssn",
    PII_PROPER_NAME_LABEL,
)
PII_SNIPPET_LENGTH = 64

# Networking / path limits
MAX_WIN32_PATH = 255
SMB_PORT = 445
IP_REGEX: re.Pattern[str] = re.compile(
    r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
    r"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
    re.I,
)

# Byte scaling power-of-2 labels
BYTE_UNIT_PREFIXES: dict[int, str] = {
    0: "Bytes",
    10: "KB",
    20: "MB",
    30: "GB",
    40: "TB",
    50: "PB",
    60: "EB",
}
