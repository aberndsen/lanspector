"""Unit tests for interactive Plotly storage sunburst charts and flare JSON trees."""

from __future__ import annotations

import json
import pathlib

import pandas as pd
import plotly.graph_objects as go
from assertpy import assert_that

from lanspector.sunburst import (
    build_sunburst_figure,
    export_sunburst_html,
    format_bytes,
    paths_to_flare_dict,
    paths_to_hierarchy_df,
)
from tests.conftest import SampleTree


def test_build_sunburst_figure_and_export_html(
    sample_tree: SampleTree, tmp_path: pathlib.Path
) -> None:
    """Verify Plotly Sunburst figure construction and standalone HTML export."""
    fig_age = build_sunburst_figure(sample_tree.files_db, color_by="age")
    assert_that(fig_age).is_instance_of(go.Figure)
    assert_that(len(fig_age.data)).is_equal_to(1)
    assert_that(fig_age.data[0].type).is_equal_to("sunburst")

    fig_size = build_sunburst_figure(sample_tree.files_db, color_by="size", max_depth=2)
    assert_that(fig_size.data[0].type).is_equal_to("sunburst")

    html_out = tmp_path / "sunburst.html"
    written = export_sunburst_html(
        sample_tree.files_db,
        html_out,
        color_by="age",
        include_plotlyjs="cdn",
        open_browser=False,
    )
    assert_that(written.exists()).is_true()
    html_text = written.read_text(encoding="utf-8")
    assert_that(html_text).contains("LANspector Storage Sunburst")
    assert_that(html_text).contains("sunburst")


def test_paths_to_hierarchy_and_flare(tmp_path: pathlib.Path) -> None:
    """Verify hierarchy roll-up preserves branchvalues='total' and writes valid flare JSON."""
    df = pd.DataFrame(
        {
            "path": [
                "/srv/share/finance/q1",
                "/srv/share/finance/q2",
                "/srv/share/archive/old",
            ],
            "size": [1000, 2000, 3000],
            "max_atime": ["2025-01-10", "2025-02-01", "2022-05-01"],
        }
    )
    hier = paths_to_hierarchy_df(df)
    root_rows = hier[hier["parent"] == ""]
    assert_that(len(root_rows)).is_equal_to(1)
    assert_that(float(root_rows.iloc[0]["size"])).is_equal_to(6000.0)

    flare_file = tmp_path / "flare.json"
    flare = paths_to_flare_dict(df, jout=flare_file)
    assert_that(flare).contains_key("name", "children")
    assert_that(json.loads(flare_file.read_text(encoding="utf-8"))).is_equal_to(flare)

    assert_that(format_bytes(512)).is_equal_to("512 Bytes")
    assert_that(format_bytes(int(1.5 * 2**10))).is_equal_to("1.50 KB")
    assert_that(format_bytes(int(2.35 * 2**20))).is_equal_to("2.35 MB")
    assert_that(format_bytes(2**30)).is_equal_to("1.00 GB")
    assert_that(format_bytes(int(3.25 * 2**40))).is_equal_to("3.25 TB")
