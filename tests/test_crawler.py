"""Unit tests for filesystem crawling, SQLite/CSV/Excel persistence, and driver orchestration."""

from __future__ import annotations

import pathlib
from typing import Any, cast

import pandas as pd
import pytest
from assertpy import assert_that

from lanspector.constants import CRAWL_INFO_TABLE, PII_KEYWORDS
from lanspector.crawler import (
    convert_to_sqlite,
    crawl,
    crawl_by_existing_dbs,
    crawl_driver,
    md5sum,
)
from lanspector.reader import CrawlReader
from lanspector.settings import CrawlSettings
from tests.conftest import SampleTree


def test_crawl_in_memory(sample_tree: SampleTree) -> None:
    """Verify in-memory crawl returns populated metadata, permissions, and PII DataFrames."""
    res = crawl(sample_tree.root, scantype="fd", permissions=True, detect_pii_content=True)
    assert_that(res.output_path).is_none()
    assert_that(res.objects_processed).is_greater_than(5)
    assert_that(res.files_df["fname"].dropna().tolist()).contains("summary.txt")
    assert_that(len(res.perms_df)).is_greater_than_or_equal_to(len(res.files_df))
    assert_that(len(res.pii_df)).is_greater_than(0)


def test_crawl_sqlite_tables_and_pii_words(sample_tree: SampleTree) -> None:
    """Verify SQLite crawl creates primary, permission, share, PII, and CRAWL_INFO tables."""
    with CrawlReader(sample_tree.files_db) as reader:
        tbl = reader.crawls[0]
        assert_that(tbl).is_equal_to(sample_tree.t1)
        for expected in (
            tbl,
            f"{tbl}_p",
            f"{tbl}_sp",
            f"{tbl}_pii",
            f"{tbl}_pii_words",
            CRAWL_INFO_TABLE,
        ):
            assert_that(reader.tables).contains(expected)
        stored_words = pd.read_sql_table(f"{tbl}_pii_words", reader.engine)
        assert_that(len(stored_words)).is_equal_to(len(PII_KEYWORDS))


def test_crawl_limit_and_max_depth(sample_tree: SampleTree, tmp_path: pathlib.Path) -> None:
    """Verify limit caps harvested objects and max_depth constrains directory depth."""
    limited_db = tmp_path / "limited.db"
    res = crawl(sample_tree.root, fout=limited_db, limit=3, crawl_acls=False)
    assert_that(res.objects_processed).is_equal_to(3)

    with CrawlReader(sample_tree.maxdepth_db) as reader:
        root_str = str(reader.crawl_root()[0])
        dirs = reader.list_of_directories()["path"].tolist()
        for d in dirs:
            rel = pathlib.Path(d).relative_to(root_str)
            assert_that(len(rel.parts)).is_less_than_or_equal_to(2)


def test_crawl_csv_and_convert_to_sqlite(sample_tree: SampleTree, tmp_path: pathlib.Path) -> None:
    """Verify CSV output and conversion to SQLite."""
    csv_out = tmp_path / "crawl_out.csv"
    crawl(sample_tree.root, fout=csv_out, scantype="fd", permissions=False)
    assert_that(csv_out.exists()).is_true()

    db_out = convert_to_sqlite(csv_out, crawldate="20250301T000000")
    assert_that(db_out.exists()).is_true()
    with CrawlReader(db_out) as reader:
        assert_that(reader.crawls).contains("20250301T000000")
        assert_that(reader.number_of_objects()).is_greater_than(0)


def test_crawl_driver_dryrun_and_execute(sample_tree: SampleTree, tmp_path: pathlib.Path) -> None:
    """Verify driver-file parsing handles comments, blank lines, dry-run, and actual execution."""
    driver_file = tmp_path / "driver.txt"
    driver_file.write_text(
        f"# Sample driver\n\n{sample_tree.root / 'finance'}\n{sample_tree.root / 'archive'}\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "driver_out"
    dry_settings = CrawlSettings(
        driver=driver_file, driver_out=out_dir, dryrun=True, crawl_acls=False
    )
    planned = crawl_driver(dry_settings)
    assert_that(planned).is_length(2)
    assert_that(all(not p.exists() for p in planned)).is_true()

    run_settings = CrawlSettings(
        driver=driver_file, driver_out=out_dir, dryrun=False, crawl_acls=False
    )
    crawled = crawl_driver(run_settings)
    assert_that(crawled).is_length(2)
    assert_that(all(p.exists() for p in crawled)).is_true()
    assert_that((out_dir / "open_shares_report.xlsx").exists()).is_true()


def test_crawl_validation_errors_and_helpers(
    sample_tree: SampleTree, tmp_path: pathlib.Path
) -> None:
    """Verify validation errors, md5sum, and crawl_by_existing_dbs dry-run."""
    with pytest.raises(ValueError):
        crawl(sample_tree.root, scantype=cast(Any, "invalid"))
    with pytest.raises(FileNotFoundError):
        crawl(tmp_path / "does_not_exist")
    with pytest.raises(ValueError):
        crawl(sample_tree.root, fout=tmp_path / "bad.parquet")

    digest = md5sum(sample_tree.root / "finance" / "summary.txt")
    assert_that(digest).is_length(32)
    assert_that(md5sum(tmp_path / "missing.bin")).is_equal_to("")

    stale_db = tmp_path / "srv01_finance.db"
    crawl(
        sample_tree.root / "finance", fout=stale_db, tablename="20240101T000000", crawl_acls=False
    )
    cmds = crawl_by_existing_dbs(tmp_path, mindate="20250101T000000", dryrun=True)
    assert_that(cmds).is_length(1)


def test_crawl_resume_after_interrupted_run(
    sample_tree: SampleTree, tmp_path: pathlib.Path
) -> None:
    """Verify resume=True picks up an incomplete crawl (scan_end IS NULL) without duplicates."""
    from sqlalchemy import text

    resume_db = tmp_path / "interrupted.db"
    partial_table = "20250501T100000"

    # Simulate an interrupted crawl that stopped after 4 objects and never wrote scan_end
    first = crawl(
        sample_tree.root,
        scantype="fd",
        fout=resume_db,
        tablename=partial_table,
        limit=4,
        chunksize=2,
        crawl_acls=False,
    )
    assert_that(first.objects_processed).is_equal_to(4)

    with CrawlReader(resume_db) as reader:
        with reader.engine.begin() as conn:
            conn.execute(
                text(f"UPDATE [{CRAWL_INFO_TABLE}] SET [scan_end] = NULL WHERE [table] = :tbl"),
                {"tbl": partial_table},
            )
        assert_that(reader.number_of_objects(table=partial_table)).is_equal_to(4)

    # Resume automatically without specifying tablename (finds scan_end IS NULL for same path)
    resumed = crawl(
        sample_tree.root,
        scantype="fd",
        fout=resume_db,
        crawl_acls=False,
        resume=True,
    )
    assert_that(resumed.tablename).is_equal_to(partial_table)
    assert_that(resumed.objects_processed).is_greater_than(0)

    with (
        CrawlReader(resume_db) as resumed_reader,
        CrawlReader(sample_tree.files_db) as full_reader,
    ):
        assert_that(resumed_reader.crawls).is_equal_to([partial_table])
        opts = resumed_reader.crawl_options(table=partial_table)
        assert opts is not None
        assert_that(opts["scan_end"]).is_not_none()

        resumed_df = resumed_reader.crawl(table=partial_table)
        full_df = full_reader.crawl()
        # Same unique (path, fname) set, zero duplicate entries, monotonic unique IDs
        assert_that(len(resumed_df)).is_equal_to(len(full_df))
        assert_that(resumed_df["Id"].is_unique).is_true()
        resumed_keys = set(zip(resumed_df["path"], resumed_df["fname"].fillna(""), strict=False))
        full_keys = set(zip(full_df["path"], full_df["fname"].fillna(""), strict=False))
        assert_that(resumed_keys).is_equal_to(full_keys)
