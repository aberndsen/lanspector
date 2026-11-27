"""Security and reliability regression tests for LANspector hardening."""

from __future__ import annotations

import os
import pathlib
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any

import openpyxl
import pandas as pd
import pytest
from assertpy import assert_that
from sqlalchemy.pool import NullPool, StaticPool

from lanspector import platform as plat
from lanspector.crawler import crawl, crawl_driver, create_crawl_engine
from lanspector.dashboard.data_prep import (
    LanDashStore,
    commit_data_to_database,
    generate_dashboard_data,
)
from lanspector.pii import extract_file_text
from lanspector.reader import CrawlReader
from lanspector.reporting import _sanitize_filename_token, generate_fileshare_report
from lanspector.settings import CrawlSettings
from lanspector.sunburst import build_sunburst_hover_text, paths_to_hierarchy_df


def test_excel_formula_injection_disabled(tmp_path: pathlib.Path) -> None:
    """Verify filenames/cells starting with '=' or '+' are written as literal strings, not formulas."""
    share = tmp_path / "share"
    share.mkdir()
    (share / "=SUM(1,2).txt").write_text(
        '=HYPERLINK("http://example.invalid") ssn\n', encoding="utf-8"
    )
    (share / "+cmd.csv").write_text("phone\n=1+1\n", encoding="utf-8")

    db_path = tmp_path / "formula.db"
    crawl(share, fout=db_path, detect_pii_content=True, crawl_acls=False)

    xlsx_path = tmp_path / "audit.xlsx"
    generate_fileshare_report(db_path, xlsx_path)

    wb = openpyxl.load_workbook(xlsx_path, data_only=False)
    try:
        found_formula_literal = False
        for sheet in wb.worksheets:
            for row in sheet.iter_rows():
                for cell in row:
                    if isinstance(cell.value, str) and "=SUM(1,2).txt" in cell.value:
                        found_formula_literal = True
                        assert_that(cell.data_type).is_equal_to("s")
                    assert_that(cell.data_type).is_not_equal_to("f")
        assert_that(found_formula_literal).is_true()
    finally:
        wb.close()


def test_sql_identifier_validation_and_no_cli_tablename(tmp_path: pathlib.Path) -> None:
    """Verify unsafe table identifiers are rejected and CrawlSettings omits CLI tablename."""
    assert_that(hasattr(CrawlSettings(), "tablename")).is_false()

    share = tmp_path / "share"
    share.mkdir()
    (share / "a.txt").write_text("ok", encoding="utf-8")
    db_path = tmp_path / "safe.db"

    with pytest.raises(ValueError, match="Invalid crawl table name"):
        crawl(share, fout=db_path, tablename="bad]; DROP TABLE CRAWL_INFO; --", crawl_acls=False)

    crawl(share, fout=db_path, crawl_acls=False)
    with CrawlReader(db_path) as reader:
        with pytest.raises(ValueError, match="Invalid crawl table name"):
            reader.crawl(table="bad]; --")
        with pytest.raises(ValueError, match="Invalid crawl table name"):
            reader.remove_crawl("bad]; --")
        with pytest.raises(ValueError, match="does not exist"):
            reader.crawl(table="20990101T000000")


def test_sunburst_hover_escapes_html_characters() -> None:
    """Verify HTML tags in directory names are escaped in Plotly sunburst hover overlays."""
    df = pd.DataFrame(
        {
            "path": ["/srv/share/<script>alert(1)</script>", "/srv/share/<a href='x'>link</a>"],
            "size": [2048, 4096],
            "max_atime": ["2025-01-01", "2025-02-01"],
        }
    )
    hierarchy = paths_to_hierarchy_df(df)
    hover = build_sunburst_hover_text(hierarchy)
    joined = "\n".join(hover)
    assert_that(joined).does_not_contain("<script>")
    assert_that(joined).contains("&lt;script&gt;alert(1)&lt;/script&gt;")
    assert_that(joined).does_not_contain("<a href=")
    assert_that(joined).contains("&lt;a href=")


def test_symlink_files_skipped_for_md5_and_pii_and_bounded_reads(tmp_path: pathlib.Path) -> None:
    """Verify file symlinks are never hashed/PII-scanned and oversized files are skipped."""
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("ssn: 123-45-6789 phone: 555-0100\n", encoding="utf-8")

    share = tmp_path / "share"
    share.mkdir()
    (share / "normal.txt").write_text("plain text\n", encoding="utf-8")
    link = share / "linked_secret.txt"
    os.symlink(outside, link)

    db_path = tmp_path / "sym.db"
    crawl(share, fout=db_path, max_md5=10 * 2**20, detect_pii_content=True, crawl_acls=False)
    with CrawlReader(db_path) as reader:
        raw = reader.crawl()
        sym_row = raw[raw["fname"] == "linked_secret.txt"].iloc[0]
        assert_that(bool(pd.isna(sym_row["md5"]))).is_true()
        assert_that(reader.find_pii_by_content().empty).is_true()

    # Verify max_bytes guard skips oversized files cleanly
    big_txt = tmp_path / "oversized.txt"
    big_txt.write_text("ssn " * 200, encoding="utf-8")
    assert_that(extract_file_text(big_txt, max_bytes=32)).is_equal_to("")


def test_filename_token_sanitization_and_nullpool_concurrency(tmp_path: pathlib.Path) -> None:
    """Verify strict per_user filename sanitization and thread-safe NullPool SQLite reads."""
    assert_that(_sanitize_filename_token("../../evil:user*name")).is_equal_to("evil_user_name")
    assert_that(_sanitize_filename_token("...")).is_equal_to("unknown")

    mem_engine = create_crawl_engine(":memory:")
    assert_that(mem_engine.pool).is_instance_of(StaticPool)
    mem_engine.dispose()

    share = tmp_path / "share"
    share.mkdir()
    (share / "file.txt").write_text("hello", encoding="utf-8")
    crawl_db = tmp_path / "crawl.db"
    crawl(share, fout=crawl_db, crawl_acls=False)

    file_engine = create_crawl_engine(crawl_db)
    assert_that(file_engine.pool).is_instance_of(NullPool)
    file_engine.dispose()

    dash_db = tmp_path / "dash.sqlite"
    acc, mem, burst = generate_dashboard_data([crawl_db])
    commit_data_to_database(dash_db, acc, mem, burst)
    with LanDashStore(dash_db) as store:
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: len(store.load_sunburst_data()), range(12)))
        assert_that(all(r >= 1 for r in results)).is_true()


def test_recursive_ad_group_membership_with_cycle_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify _win32_group_membership tracks direct & nested groups without infinite cycles."""
    group_graph: dict[str, list[dict[str, Any]]] = {
        "Finance": [
            {"domainandname": "CORP\\SubGroup", "sidusage": 2},
            {"domainandname": "CORP\\direct_user", "sidusage": 1},
        ],
        "SubGroup": [
            {"domainandname": "CORP\\Finance", "sidusage": 2},  # cycle back to root!
            {"domainandname": "CORP\\nested_user", "sidusage": 1},
        ],
    }

    fake_sec = SimpleNamespace(
        DsGetDcName=lambda domainName: {"DomainControllerName": "\\\\dc01"},
        LookupAccountName=lambda server, name: (None, "CORP", 2 if "Group" in name else 1),
    )
    fake_net = SimpleNamespace(
        NetLocalGroupGetMembers=lambda server, grp, level, resume, maxlen: (
            group_graph.get(grp, []),
            len(group_graph.get(grp, [])),
            0,
        ),
        NetGroupGetUsers=lambda server, grp, level, resume, maxlen: (
            [{"name": m["domainandname"].split("\\", 1)[1]} for m in group_graph.get(grp, [])],
            len(group_graph.get(grp, [])),
            0,
        ),
    )
    fake_con = SimpleNamespace(MAX_PREFERRED_LENGTH=-1)

    monkeypatch.setattr(plat, "_win32security", fake_sec)
    monkeypatch.setattr(plat, "_win32net", fake_net)
    monkeypatch.setattr(plat, "_win32netcon", fake_con)

    df = plat._win32_group_membership(domain="CORP", group="Finance", acl_type="Alias")
    assert_that(df["member.logon"].tolist()).contains(
        "CORP\\SubGroup", "CORP\\direct_user", "CORP\\nested_user"
    )
    nested_row = df[df["member.logon"] == "CORP\\nested_user"].iloc[0]
    assert_that(nested_row["Domain"]).is_equal_to("CORP")
    assert_that(nested_row["ACL"]).is_equal_to("Finance")
    assert_that(nested_row["member.nestedACL"]).is_equal_to("CORP\\SubGroup")


def test_crawl_driver_isolates_per_target_failures(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify one failing target in crawl_driver does not abort surviving shares or reporting."""
    good = tmp_path / "good_share"
    bad = tmp_path / "bad_share"
    good.mkdir()
    bad.mkdir()
    (good / "ok.txt").write_text("ok", encoding="utf-8")
    (bad / "fail.txt").write_text("fail", encoding="utf-8")

    driver_file = tmp_path / "driver.txt"
    driver_file.write_text(f"{good}\n{bad}\n", encoding="utf-8")
    out_dir = tmp_path / "driver_out"

    from lanspector import crawler as crawler_mod

    real_crawl = crawler_mod.crawl

    def _flaky_crawl(*args: Any, **kwargs: Any) -> Any:
        target = str(kwargs.get("path", args[0] if args else ""))
        if "bad_share" in target:
            raise PermissionError("Simulated share failure")
        return real_crawl(*args, **kwargs)

    monkeypatch.setattr(crawler_mod, "crawl", _flaky_crawl)
    settings = CrawlSettings(driver=driver_file, driver_out=out_dir, crawl_acls=False)
    succeeded = crawl_driver(settings)
    assert_that(succeeded).is_length(1)
    assert_that(succeeded[0].exists()).is_true()
    assert_that((out_dir / "open_shares_report.xlsx").exists()).is_true()
