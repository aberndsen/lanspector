"""Unit tests for CrawlReader analytics, parent-vs-child SOX diffs, drift, and MultiDB."""

from __future__ import annotations

import datetime
import pathlib

from assertpy import assert_that

from lanspector.crawler import crawl
from lanspector.reader import CrawlReader, MultiDB, nearest_crawl_to_date
from tests.conftest import SampleTree


def test_reader_core_queries(sample_tree: SampleTree) -> None:
    """Verify CrawlReader metadata, counts, directory listings, users, and ACLs."""
    with CrawlReader(sample_tree.files_db) as db:
        assert_that(db.is_multidb).is_false()
        assert_that(db.latest_crawl).is_equal_to(sample_tree.t1)
        assert_that(db.nearest_crawl_to_date(datetime.datetime(2025, 1, 2))).is_equal_to(
            sample_tree.t1
        )
        assert_that(db.number_of_files()).is_greater_than_or_equal_to(6)
        assert_that(db.number_of_directories()).is_greater_than_or_equal_to(5)
        assert_that(db.number_of_objects()).is_equal_to(
            db.number_of_files() + db.number_of_directories()
        )
        assert_that(db.number_of_entitlements()).is_greater_than(0)
        assert_that(db.crawl().shape[1]).is_equal_to(9)
        assert_that(len(db.head(3))).is_equal_to(3)
        assert_that(len(db.users())).is_greater_than(0)

        acls = db.acls()
        assert_that(len(acls)).is_greater_than(0)
        first_acl = str(acls.iloc[0]["Name"])
        assert_that(len(db.find_where_acl_is_applied(first_acl))).is_greater_than(0)
        assert_that(len(db.count_where_acl_is_applied([first_acl]))).is_equal_to(1)

        summary = db.executive_summary()
        assert_that(summary.info["Number of Files"]).is_greater_than(0)
        assert_that(summary.acls_found).is_not_empty()
        assert_that(summary.owners_found).is_not_empty()


def test_parent_vs_child_compression_and_file_elevation(sample_tree: SampleTree) -> None:
    """Verify parent_vs_child_report compresses unchanged folders and flags elevated files."""
    with CrawlReader(sample_tree.files_db) as db:
        pvc = db.parent_vs_child_report(use_permission_hierarchy=True)
        assert_that(pvc.dirs_df).is_not_none()
        assert pvc.dirs_df is not None
        # Should include root + restricted (0o700 differs from 0o755) while compressing identical dirs
        all_dirs_count = db.number_of_directories()
        assert_that(len(pvc.dirs_df)).is_less_than(all_dirs_count)
        assert_that(any("restricted" in str(idx) for idx in pvc.dirs_df.index)).is_true()

        # elevated_secret.txt (0o755) inside restricted/ (0o700) must be flagged in files_df
        assert_that(pvc.files_df).is_not_none()
        assert pvc.files_df is not None
        fnames = [idx[1] for idx in pvc.files_df.index]
        assert_that(fnames).contains("elevated_secret.txt")

        # Melted and open-access views
        melted = db.parent_vs_child_report(skip_files_report=True, melt=True).dirs_df
        assert melted is not None
        assert_that(list(melted.columns)).contains("path", "Domain", "Name", "permission")

        open_res = db.find_open_access(skip_files_report=True)
        assert_that(open_res.dirs_df).is_not_none()


def test_storage_hygiene_pii_and_duplicates(sample_tree: SampleTree) -> None:
    """Verify duplicates, backups, age distribution, oldest entries, and PII queries."""
    with CrawlReader(sample_tree.files_db) as db:
        dups = db.find_duplicate_md5()
        assert_that(len(dups)).is_greater_than_or_equal_to(2)

        backups = db.find_backups("fname")
        assert_that(backups["fname"].tolist()).contains(
            "ledger_2024-01-15.bak", "old_report_v2.txt"
        )

        pii_name = db.find_pii_by_name("fname")
        assert_that(pii_name["fname"].tolist()).contains("customer_address_phone.csv")

        pii_content = db.find_pii_by_content()
        assert_that(len(pii_content)).is_greater_than(0)

        age_dist = db.find_file_age_distribution()
        assert_that(len(age_dist)).is_greater_than(0)
        assert_that(age_dist.columns.tolist()).contains(2021)

        assert_that(len(db.largest_files())).is_greater_than(0)
        assert_that(len(db.largest_directories(level=1))).is_greater_than(0)
        assert_that(len(db.largest_users())).is_greater_than(0)
        assert_that(len(db.oldest_entries())).is_greater_than(0)
        assert_that(len(db.find_longest_path())).is_greater_than(0)
        assert_that(db.get_latest_object_date()).is_not_none()


def test_dirs_vs_files_crawl_storage_parity(sample_tree: SampleTree) -> None:
    """Verify dirs-only crawl total usage and PII content match files+dirs crawl."""
    with CrawlReader(sample_tree.dirs_db) as ddb, CrawlReader(sample_tree.files_db) as fdb:
        sub = str(sample_tree.root / "finance")
        assert_that(ddb.get_total_storage(subdir=sub)).is_equal_to(
            fdb.get_total_storage(subdir=sub)
        )
        assert_that(len(ddb.find_pii_by_content())).is_equal_to(len(fdb.find_pii_by_content()))


def test_compare_crawls_and_drift_detection(sample_tree: SampleTree) -> None:
    """Verify compare_crawls detects added files and folder permission changes."""
    with CrawlReader(sample_tree.drift_db) as db:
        assert_that(db.crawls).is_equal_to([sample_tree.t1, sample_tree.t2])
        diffs = db.compare_crawls()
        assert_that(diffs["new_files"]["fname"].tolist()).contains("new_audit_drop.txt")
        assert_that(len(diffs["permission_changes"])).is_greater_than(0)
        assert_that(
            any("archive" in str(p) for p in diffs["permission_changes"]["path"].tolist())
        ).is_true()

        when_changed = db.find_when_permissions_changed()
        assert_that(len(when_changed)).is_greater_than(0)

        growth = db.get_storage_growth_rate()
        assert_that(len(growth)).is_equal_to(2)


def test_remove_crawl_and_multidb(sample_tree: SampleTree, tmp_path: pathlib.Path) -> None:
    """Verify remove_crawl drops tables cleanly and MultiDB aggregates across DBs."""
    temp_db = tmp_path / "removable.db"
    crawl(sample_tree.root / "finance", fout=temp_db, tablename="20250401T000000", crawl_acls=False)
    with CrawlReader(temp_db) as db:
        assert_that(db.crawls).contains("20250401T000000")
        db.remove_crawl("20250401T000000")
        assert_that(db.crawls).is_empty()

    mdb = MultiDB([sample_tree.dirs_db, sample_tree.files_db])
    assert_that(mdb.is_multidb).is_true()
    assert_that(str(mdb)).is_equal_to("<MultiDB: 2 DBs, 2 crawls>")
    assert_that(mdb.latest_crawl).is_equal_to(sample_tree.t1)
    assert_that(mdb.list_methods()).contains(
        "parent_vs_child_report", "executive_summary", "largest_files"
    )
    assert_that(mdb.query("number_of_directories")).is_greater_than(0)
    pvc_agg = mdb.query("parent_vs_child_report", flatten_cols=True)
    assert_that(pvc_agg.dirs_df).is_not_none()
    assert_that(
        nearest_crawl_to_date(["20250101T000000", "20250601T000000"], "2025-01-05", max_delta=10)
    ).is_equal_to("20250101T000000")
    assert_that(nearest_crawl_to_date(["20250101T000000"], "2025-06-01", max_delta=5)).is_none()


def test_reader_extended_audit_queries(sample_tree: SampleTree) -> None:
    """Verify additional CrawlReader audit, diff, and ownership queries."""
    with CrawlReader(sample_tree.files_db) as db:
        assert_that(len(db.list_of_crawls())).is_equal_to(1)
        assert_that(db.total_usage()["bytes"].iloc[0]).is_greater_than(0)
        assert_that(len(db.return_crawl_with_permissions())).is_greater_than(0)

        owner = str(db.users()["owner"].iloc[0])
        assert_that(len(db.find_users_files(owner))).is_greater_than(0)
        assert_that(len(db.find_where_user_has_access(owner))).is_greater_than(0)
        assert_that(len(db.find_where_acl_is_not_applied("NonExistentGroup"))).is_greater_than(0)
        assert_that(db.find_objects_owned_by_dead_sids().empty).is_true()
        assert_that(db.find_duplicate_files().empty).is_true()

        added, dropped = db.find_children_permissions_diffs()
        assert_that(len(added) + len(dropped)).is_greater_than(0)

        root_str = str(sample_tree.root)
        assert_that(len(db.users_with_access_at_level(root_str))).is_greater_than(0)
        assert_that(len(db.users_with_access_below_folder(root_str))).is_greater_than(0)
