"""Unit tests for the jsonargparse-powered ``lanspector`` CLI subcommands."""

from __future__ import annotations

import pathlib

import pytest
from assertpy import assert_that

from lanspector.cli import main
from tests.conftest import SampleTree


def test_cli_crawl_default_fout_and_yaml_config(
    sample_tree: SampleTree,
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Verify --path alone writes a default DB + Excel summary and --config loads YAML."""
    monkeypatch.chdir(tmp_path)
    rc = main(["crawl", "--path", str(sample_tree.root), "--crawl_acls", "false"])
    assert_that(rc).is_equal_to(0)

    captured = capsys.readouterr()
    assert_that(captured.err).contains("Wrote LANspector audit report to")
    assert_that(captured.err.count("Wrote LANspector audit report to")).is_equal_to(1)
    assert_that(captured.err).contains("Crawl finished")
    assert_that(captured.out).is_empty()
    assert_that(list(tmp_path.glob("*.db"))).is_length(1)
    assert_that(list(tmp_path.glob("*.xlsx"))).is_length(1)

    cfg_yaml = tmp_path / "crawl_cfg.yaml"
    cfg_db = tmp_path / "from_yaml.db"
    cfg_yaml.write_text(
        f"path: {sample_tree.root}\n"
        f"fout: {cfg_db}\n"
        "scantype: d\n"
        "crawl_acls: false\n"
        "summarize: true\n"
        "log_level: INFO\n",
        encoding="utf-8",
    )
    rc_cfg = main(["crawl", "--config", str(cfg_yaml)])
    assert_that(rc_cfg).is_equal_to(0)
    assert_that(cfg_db.exists()).is_true()
    assert_that(list(tmp_path.glob("from_yaml_*.xlsx"))).is_length(1)


def test_cli_crawl_report_sunburst_compare(sample_tree: SampleTree, tmp_path: pathlib.Path) -> None:
    """Verify end-to-end CLI workflows for crawl, report, sunburst, compare, and dashboard-prep."""
    db_path = tmp_path / "cli_crawl.db"
    sun_path = tmp_path / "cli_sunburst.html"
    rc = main(
        [
            "crawl",
            "--path",
            str(sample_tree.root),
            "--fout",
            str(db_path),
            "--crawl_acls",
            "false",
            "--sunburst_html",
            str(sun_path),
            "--log_level",
            "WARNING",
        ]
    )
    assert_that(rc).is_equal_to(0)
    assert_that(db_path.exists()).is_true()
    assert_that(sun_path.exists()).is_true()

    report_path = tmp_path / "cli_report.xlsx"
    rc = main(
        [
            "report",
            "--databases",
            f"[{db_path}]",
            "--output",
            str(report_path),
            "--log_level",
            "WARNING",
        ]
    )
    assert_that(rc).is_equal_to(0)
    assert_that(report_path.exists()).is_true()

    sun2_path = tmp_path / "cli_sunburst2.html"
    rc = main(
        [
            "sunburst",
            "--database",
            str(db_path),
            "--output",
            str(sun2_path),
            "--color_by",
            "size",
            "--include_plotlyjs",
            "cdn",
            "--log_level",
            "WARNING",
        ]
    )
    assert_that(rc).is_equal_to(0)
    assert_that(sun2_path.exists()).is_true()

    diff_xlsx = tmp_path / "cli_compare.xlsx"
    rc = main(
        [
            "compare",
            "--database",
            str(sample_tree.drift_db),
            "--output",
            str(diff_xlsx),
            "--log_level",
            "WARNING",
        ]
    )
    assert_that(rc).is_equal_to(0)
    assert_that(diff_xlsx.exists()).is_true()

    dash_db = tmp_path / "cli_landash.sqlite"
    rc = main(
        [
            "dashboard-prep",
            "--databases",
            f"[{db_path}, {sample_tree.drift_db}]",
            "--dashboard_db",
            str(dash_db),
            "--log_level",
            "WARNING",
        ]
    )
    assert_that(rc).is_equal_to(0)
    assert_that(dash_db.exists()).is_true()

    # Single unbracketed SQLite path must NOT be misparsed as a text list-of-paths file
    dash_db_single = tmp_path / "cli_landash_single.sqlite"
    rc = main(
        [
            "dashboard-prep",
            "--databases",
            str(db_path),
            "--dashboard_db",
            str(dash_db_single),
            "--log_level",
            "WARNING",
        ]
    )
    assert_that(rc).is_equal_to(0)
    assert_that(dash_db_single.exists()).is_true()


def test_cli_error_exit_codes(tmp_path: pathlib.Path) -> None:
    """Verify missing paths and empty inputs return non-zero exit status cleanly."""
    assert_that(main(["crawl", "--log_level", "ERROR"])).is_equal_to(1)
    assert_that(
        main(["crawl", "--path", str(tmp_path / "nope"), "--log_level", "ERROR"])
    ).is_equal_to(1)
    assert_that(main(["report", "--log_level", "ERROR"])).is_equal_to(1)
    assert_that(main(["dashboard-prep", "--log_level", "ERROR"])).is_equal_to(1)
    assert_that(
        main(["sunburst", "--database", str(tmp_path / "nope.db"), "--log_level", "ERROR"])
    ).is_equal_to(1)
    assert_that(
        main(["compare", "--database", str(tmp_path / "nope.db"), "--log_level", "ERROR"])
    ).is_equal_to(1)
    assert_that(main(["shares", "--servers", "[localhost]", "--log_level", "ERROR"])).is_equal_to(0)


def test_cli_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify ``lanspector --version`` prints the installed package version and exits cleanly."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert_that(exc_info.value.code).is_equal_to(0)
    assert_that(capsys.readouterr().out.strip()).is_not_empty()
