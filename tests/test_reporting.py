"""Unit tests for Excel audit report generation and formatting utilities."""

from __future__ import annotations

import pathlib

import openpyxl
import pandas as pd
from assertpy import assert_that

from lanspector.reporting import (
    generate_fileshare_report,
    generate_open_shares_summary_report,
    scale_bytes_cols,
    version_adder,
)
from tests.conftest import SampleTree


def test_generate_fileshare_report_sheets(sample_tree: SampleTree, tmp_path: pathlib.Path) -> None:
    """Verify multi-sheet Excel audit workbook contains expected SOX & cleanup sheets."""
    out_xlsx = tmp_path / "audit_report.xlsx"
    written = generate_fileshare_report(sample_tree.files_db, out_xlsx, limit=50)
    assert_that(written.exists()).is_true()

    with pd.ExcelFile(written) as wb:
        sheets = wb.sheet_names
        assert_that(sheets).contains(
            "Summary",
            "parent_vs_child",
            "file_vs_folderACL",
            "Possible PII Locations",
            "Largest Directories",
            "Largest Files",
            "Duplicate Files",
            "Access Time Distribution",
            "Oldest Objects",
            "Largest Users",
            "Backup Files",
            "Objects Owned by User",
        )
        pvc_df = pd.read_excel(wb, "parent_vs_child", skiprows=6)
        assert_that(len(pvc_df)).is_greater_than_or_equal_to(1)

        dirs_df = pd.read_excel(wb, "Largest Directories", skiprows=3)
        assert_that(len(dirs_df)).is_greater_than_or_equal_to(1)

    xl_wb = openpyxl.load_workbook(written)
    try:
        ws = xl_wb["Summary"]
        headers = {ws.cell(5, col).value: col for col in range(1, ws.max_column + 1)}
        for bool_col in ("Scan Files", "Scan Directories", "Scan Permissions", "Scan PII Content"):
            assert_that(headers).contains_key(bool_col)
            cell = ws.cell(6, headers[bool_col])
            assert_that(cell.data_type).is_equal_to("b")
            assert_that(cell.value).is_true()
    finally:
        xl_wb.close()


def test_generate_multidb_and_open_shares_reports(
    sample_tree: SampleTree, tmp_path: pathlib.Path
) -> None:
    """Verify MultiDB Excel summary and Open Shares report generation."""
    multi_out = tmp_path / "multi_audit.xlsx"
    written = generate_fileshare_report([sample_tree.dirs_db, sample_tree.files_db], multi_out)
    assert_that(written.exists()).is_true()

    open_out = tmp_path / "open_shares.xlsx"
    oa = generate_open_shares_summary_report([sample_tree.files_db], open_out)
    assert_that(open_out.exists()).is_true()
    assert_that(oa).is_not_none()


def test_scale_bytes_and_version_adder(tmp_path: pathlib.Path) -> None:
    """Verify byte unit auto-scaling and non-colliding file versioning."""
    df = pd.DataFrame({"path": ["/a", "/b"], "bytes": [2 * 2**20, 4 * 2**20]})
    scaled = scale_bytes_cols(df)
    assert_that(list(scaled.columns)).contains("bytes [MB]")
    assert_that(scaled["bytes [MB]"].tolist()).is_equal_to([2.0, 4.0])

    base = tmp_path / "report.xlsx"
    assert_that(version_adder(base)).is_equal_to(base)
    base.write_text("placeholder", encoding="utf-8")
    v0 = version_adder(base)
    assert_that(v0.name).is_equal_to("report_v00.xlsx")
    v0.write_text("placeholder", encoding="utf-8")
    assert_that(version_adder(base).name).is_equal_to("report_v01.xlsx")
