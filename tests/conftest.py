"""Shared pytest fixtures building deterministic synthetic directory trees and crawl DBs."""

from __future__ import annotations

import os
import pathlib
import shutil
import stat
from dataclasses import dataclass

import pytest

from lanspector.crawler import crawl

FIXTURE_PII_XLSX = pathlib.Path(__file__).resolve().parent / "data" / "pii_test_document.xlsx"


@dataclass
class SampleTree:
    """Paths to the synthetic test filesystem and pre-crawled SQLite databases."""

    root: pathlib.Path
    dirs_db: pathlib.Path
    files_db: pathlib.Path
    maxdepth_db: pathlib.Path
    drift_db: pathlib.Path
    t1: str
    t2: str


@pytest.fixture(scope="session")
def sample_tree(tmp_path_factory: pytest.TempPathFactory) -> SampleTree:
    """Create a deterministic directory tree with varied permissions, duplicates, backups, and PII."""
    base = tmp_path_factory.mktemp("lanspector_suite")
    root = base / "share_root"
    finance = root / "finance"
    restricted = finance / "restricted"
    archive = root / "archive"
    deep = archive / "2024" / "q1" / "nested"

    for folder in (root, finance, restricted, archive, deep):
        folder.mkdir(parents=True, exist_ok=True)

    # Normal files + exact duplicate pair for MD5 testing
    payload = b"quarterly financial summary data\n" * 64
    (finance / "summary.txt").write_bytes(payload)
    (archive / "summary_copy.txt").write_bytes(payload)

    # Backup-named files & PII text file
    (finance / "ledger_2024-01-15.bak").write_text("backup ledger snapshot\n", encoding="utf-8")
    (finance / "customer_address_phone.csv").write_text(
        "first name,last name,ssn,phone\nJane,Doe,123-45-6789,555-0100\n",
        encoding="utf-8",
    )
    (deep / "old_report_v2.txt").write_text("historical archive entry\n", encoding="utf-8")

    # Copy synthetic Excel PII document into tree
    if FIXTURE_PII_XLSX.exists():
        shutil.copy2(FIXTURE_PII_XLSX, restricted / "pii_test_document.xlsx")

    # Set distinct POSIX modes to trigger parent-vs-child permission diffs & file-vs-folder elevation
    os.chmod(root, 0o755)
    os.chmod(finance, 0o755)
    os.chmod(restricted, 0o700)
    os.chmod(archive, 0o755)
    os.chmod(deep, 0o755)
    elevated_file = restricted / "elevated_secret.txt"
    elevated_file.write_text("elevated file permission test\n", encoding="utf-8")
    os.chmod(elevated_file, 0o755)

    # Set a mid-2021 access/modified timestamp on the deep archive file for timezone-safe age tests
    old_epoch = 1623758400  # 2021-06-15T12:00:00 UTC
    os.utime(deep / "old_report_v2.txt", (old_epoch, old_epoch))

    t1 = "20250101T120000"
    t2 = "20250201T120000"
    dirs_db = base / "crawl_dirs.db"
    files_db = base / "crawl_files.db"
    maxdepth_db = base / "crawl_maxdepth.db"
    drift_db = base / "crawl_drift.db"

    crawl(
        root,
        scantype="d",
        fout=dirs_db,
        tablename=t1,
        max_md5=10 * 2**20,
        detect_pii_content=True,
        crawl_acls=False,
    )
    # Re-apply deterministic 2021 timestamp in case the OS updated atime during dirs_db reads
    os.utime(deep / "old_report_v2.txt", (old_epoch, old_epoch))
    crawl(
        root,
        scantype="fd",
        fout=files_db,
        tablename=t1,
        max_md5=10 * 2**20,
        detect_pii_content=True,
        crawl_acls=False,
    )
    crawl(
        root,
        scantype="d",
        fout=maxdepth_db,
        tablename=t1,
        max_depth=2,
        crawl_acls=False,
    )

    # Build a two-crawl database simulating permission & file drift
    crawl(root, scantype="fd", fout=drift_db, tablename=t1, crawl_acls=False)
    added_file = finance / "new_audit_drop.txt"
    added_file.write_text("new file added between crawls\n", encoding="utf-8")
    os.chmod(archive, stat.S_IRWXU)  # change archive from 0o755 -> 0o700
    crawl(root, scantype="fd", fout=drift_db, tablename=t2, crawl_acls=False)

    # Restore original state
    os.chmod(archive, 0o755)
    added_file.unlink()

    return SampleTree(
        root=root,
        dirs_db=dirs_db,
        files_db=files_db,
        maxdepth_db=maxdepth_db,
        drift_db=drift_db,
        t1=t1,
        t2=t2,
    )
