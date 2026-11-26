"""Unit tests for the optional LANdash SQLite store, ETL pipeline, and Dash 3+ app."""

from __future__ import annotations

import pathlib

import pandas as pd
from assertpy import assert_that

from lanspector.dashboard.app import (
    build_acl_network_figure,
    build_dashboard_sunburst_figure,
    build_permission_pie_figure,
    build_timeline_figure,
    create_app,
)
from lanspector.dashboard.components import autoscale_bytes, get_series_color
from lanspector.dashboard.data_prep import (
    LanDashStore,
    commit_data_to_database,
    generate_dashboard_data,
)
from tests.conftest import SampleTree


def test_dashboard_etl_and_store(sample_tree: SampleTree, tmp_path: pathlib.Path) -> None:
    """Verify generating dashboard tables from crawl DBs and querying LanDashStore."""
    access_df, members_df, burst_df = generate_dashboard_data([sample_tree.drift_db])
    assert_that(access_df.empty).is_false()
    assert_that(burst_df.empty).is_false()

    dash_db = tmp_path / "landash.sqlite"
    commit_data_to_database(dash_db, access_df, members_df, burst_df)

    with LanDashStore(dash_db) as store:
        assert_that(len(store.crawl_dates)).is_equal_to(2)
        assert_that(len(store.fileshares)).is_greater_than_or_equal_to(1)
        assert_that(len(store.acl_principals)).is_greater_than_or_equal_to(1)

        crawl_data = store.get_crawl_data()
        assert_that(crawl_data.empty).is_false()
        sun_data = store.load_sunburst_data()
        assert_that(sun_data.empty).is_false()

        # Verify pure Plotly chart builders
        assert_that(len(build_timeline_figure(crawl_data).data)).is_greater_than(0)
        dash_sun = build_dashboard_sunburst_figure(sun_data)
        assert_that(len(dash_sun.data)).is_equal_to(1)
        assert_that(dash_sun.data[0].hovertemplate).is_equal_to("%{hovertext}<extra></extra>")
        assert_that(list(dash_sun.data[0].hovertext)).is_not_empty()
        assert_that(dash_sun.data[0].hovertext[0]).contains("Size:")
        assert_that(len(build_permission_pie_figure(crawl_data).data)).is_equal_to(1)

    # Verify ACL network builder with synthetic membership DataFrame
    mem_sample = pd.DataFrame(
        {
            "acl_name": ["GRP_FINANCE", "GRP_FINANCE"],
            "member_name": ["alice", "bob"],
        }
    )
    net_fig = build_acl_network_figure(mem_sample)
    assert_that(len(net_fig.data)).is_equal_to(3)


def test_create_dash_app_smoke(sample_tree: SampleTree, tmp_path: pathlib.Path) -> None:
    """Verify Dash 3+ app initializes cleanly with offline serve_locally=True."""
    dash_db = tmp_path / "landash_app.sqlite"
    access_df, members_df, burst_df = generate_dashboard_data([sample_tree.files_db])
    commit_data_to_database(dash_db, access_df, members_df, burst_df)

    app = create_app(dash_db)
    assert_that(app.title).is_equal_to("LANspector Dashboard")
    assert_that(app.layout).is_not_none()

    exp, unit = autoscale_bytes(5 * 2**30)
    assert_that(exp).is_equal_to(30)
    assert_that(unit).is_equal_to("GB")
    assert_that(get_series_color(0)).starts_with("#")


def test_dashboard_tables_inside_crawl_db_do_not_break_sunburst(
    sample_tree: SampleTree, tmp_path: pathlib.Path
) -> None:
    """Verify CrawlReader.crawls ignores LANdash tables if present in the same SQLite DB."""
    import shutil

    from lanspector.dashboard.data_prep import create_dashboard_tables
    from lanspector.reader import CrawlReader

    mixed_db = tmp_path / "mixed.db"
    shutil.copy2(sample_tree.files_db, mixed_db)
    with CrawlReader(mixed_db) as reader:
        create_dashboard_tables(reader.engine)
        assert_that(reader.crawls).is_equal_to([sample_tree.t1])
        assert_that(reader.latest_crawl).is_equal_to(sample_tree.t1)

    access_df, members_df, burst_df = generate_dashboard_data([mixed_db])
    assert_that(access_df.empty).is_false()
    assert_that(burst_df.empty).is_false()

    out_dash = tmp_path / "out_dash.sqlite"
    commit_data_to_database(out_dash, access_df, members_df, burst_df)
    with LanDashStore(out_dash) as store:
        sun_df = store.load_sunburst_data()
        assert_that(sun_df.empty).is_false()
        fig = build_dashboard_sunburst_figure(sun_df)
        assert_that(len(fig.data)).is_equal_to(1)
        assert_that(fig.data[0].type).is_equal_to("sunburst")
