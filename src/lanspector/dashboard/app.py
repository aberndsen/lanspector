"""Modern Dash 3+ / Plotly 6+ LANdash web application (offline/air-gapped ready).

Replaces legacy Dash 0.42 + vendored React components (``dash_sunburst``, ``dash_network``)
with native Plotly :class:`plotly.graph_objects.Sunburst` and :class:`plotly.graph_objects.Scatter`
network visualizations served locally (``serve_locally=True``) for restricted corporate LANs.
"""

from __future__ import annotations

import math
import pathlib
from typing import Any

import pandas as pd
import plotly.graph_objects as go
from loguru import logger

from lanspector.dashboard.components import (
    get_series_color,
    indicator_card,
    navbar,
    section_card,
)
from lanspector.dashboard.data_prep import LanDashStore
from lanspector.settings import DashboardServeSettings
from lanspector.sunburst import build_sunburst_hover_text, format_bytes, paths_to_hierarchy_df

# ---------------------------------------------------------------------------
# Primary public entry points
# ---------------------------------------------------------------------------


def create_app(db_path: str | pathlib.Path) -> Any:
    """Create and configure the LANdash :class:`dash.Dash` application.

    Parameters
    ----------
    db_path
        Path to a prepared LANdash SQLite database created via
        :func:`~lanspector.dashboard.data_prep.commit_data_to_database`.

    Returns
    -------
    dash.Dash
        Configured Dash 3+ application ready to serve locally or via WSGI.
    """
    try:
        import dash
        from dash import Input, Output, dcc, html
    except ImportError as exc:  # pragma: no cover - optional extra guard
        raise ImportError(
            "LANdash requires the optional dashboard dependencies. "
            'Install them with: pip install "lanspector[dashboard]"'
        ) from exc

    store = LanDashStore(db_path)
    app = dash.Dash(
        __name__,
        title="LANspector Dashboard",
        serve_locally=True,
    )

    fs_df = store.fileshares
    domain_opts = sorted(fs_df["domain"].dropna().unique().tolist()) if not fs_df.empty else []
    host_opts = sorted(fs_df["host"].dropna().unique().tolist()) if not fs_df.empty else []
    date_opts = store.crawl_dates
    latest_date = date_opts[-1] if date_opts else None

    app.layout = html.Div(
        style={
            "fontFamily": "system-ui, -apple-system, sans-serif",
            "backgroundColor": "#f8fafc",
            "minHeight": "100vh",
        },
        children=[
            navbar("LANspector — LAN Storage & Access Governance"),
            html.Main(
                style={"maxWidth": "1320px", "margin": "0 auto", "padding": "16px 24px 48px"},
                children=[
                    section_card(
                        "Filters",
                        [
                            html.Div(
                                style={
                                    "display": "grid",
                                    "gridTemplateColumns": "repeat(auto-fit, minmax(220px, 1fr))",
                                    "gap": "12px",
                                },
                                children=[
                                    html.Div(
                                        [
                                            html.Label(
                                                "Crawl Date",
                                                style={"fontWeight": "600", "fontSize": "0.85rem"},
                                            ),
                                            dcc.Dropdown(
                                                id="filter-date",
                                                options=[
                                                    {"label": d, "value": d} for d in date_opts
                                                ],
                                                value=latest_date,
                                                placeholder="All dates",
                                            ),
                                        ]
                                    ),
                                    html.Div(
                                        [
                                            html.Label(
                                                "Fileshare Domain",
                                                style={"fontWeight": "600", "fontSize": "0.85rem"},
                                            ),
                                            dcc.Dropdown(
                                                id="filter-domain",
                                                options=[
                                                    {"label": d, "value": d} for d in domain_opts
                                                ],
                                                multi=True,
                                                placeholder="All domains",
                                            ),
                                        ]
                                    ),
                                    html.Div(
                                        [
                                            html.Label(
                                                "Fileserver Host",
                                                style={"fontWeight": "600", "fontSize": "0.85rem"},
                                            ),
                                            dcc.Dropdown(
                                                id="filter-host",
                                                options=[
                                                    {"label": h, "value": h} for h in host_opts
                                                ],
                                                multi=True,
                                                placeholder="All hosts",
                                            ),
                                        ]
                                    ),
                                    html.Div(
                                        [
                                            html.Label(
                                                "Folder Filter (Sunburst)",
                                                style={"fontWeight": "600", "fontSize": "0.85rem"},
                                            ),
                                            dcc.Input(
                                                id="filter-folder",
                                                type="text",
                                                placeholder="Substring filter...",
                                                style={
                                                    "width": "100%",
                                                    "padding": "7px 10px",
                                                    "borderRadius": "4px",
                                                    "border": "1px solid #cbd5e1",
                                                },
                                            ),
                                        ]
                                    ),
                                ],
                            )
                        ],
                    ),
                    section_card(
                        "Executive Summary",
                        [
                            html.Div(
                                id="summary-cards",
                                style={"display": "flex", "gap": "14px", "flexWrap": "wrap"},
                            )
                        ],
                    ),
                    section_card(
                        "Permission Exposure Timeline",
                        [dcc.Graph(id="timeline-graph")],
                    ),
                    section_card(
                        "Storage Sunburst (Data Cleanup)",
                        [dcc.Graph(id="sunburst-graph", style={"height": "620px"})],
                    ),
                    section_card(
                        "ACL Membership Network & Snapshot",
                        [
                            html.Div(
                                style={
                                    "display": "grid",
                                    "gridTemplateColumns": "repeat(auto-fit, minmax(360px, 1fr))",
                                    "gap": "16px",
                                },
                                children=[
                                    dcc.Graph(id="snapshot-pie"),
                                    dcc.Graph(id="acl-network-graph"),
                                ],
                            )
                        ],
                    ),
                    section_card(
                        "Parent-vs-Child Access Records",
                        [
                            html.Div(
                                id="raw-table-container",
                                style={"overflowX": "auto"},
                            )
                        ],
                        open_by_default=False,
                    ),
                ],
            ),
        ],
    )

    @app.callback(
        Output("summary-cards", "children"),
        Output("timeline-graph", "figure"),
        Output("sunburst-graph", "figure"),
        Output("snapshot-pie", "figure"),
        Output("acl-network-graph", "figure"),
        Output("raw-table-container", "children"),
        Input("filter-date", "value"),
        Input("filter-domain", "value"),
        Input("filter-host", "value"),
        Input("filter-folder", "value"),
    )
    def _update_dashboard(
        selected_date: str | None,
        selected_domains: list[str] | None,
        selected_hosts: list[str] | None,
        folder_filter: str | None,
    ) -> tuple[Any, go.Figure, go.Figure, go.Figure, go.Figure, Any]:
        all_timeline = store.get_crawl_data(
            domains=selected_domains or None, hosts=selected_hosts or None
        )
        snap = (
            all_timeline[all_timeline["crawlDate"].astype(str) == str(selected_date)]
            if selected_date and not all_timeline.empty
            else all_timeline
        )
        burst_df = store.load_sunburst_data(
            domains=selected_domains or None,
            hosts=selected_hosts or None,
            folder_filter=folder_filter or None,
            limit=500,
        )
        members_df = store.get_acl_membership(crawl_date=selected_date)

        n_shares = (
            int(snap[["domain", "host", "share"]].drop_duplicates().shape[0])
            if not snap.empty
            else 0
        )
        n_acls = int(snap["acl_name"].nunique()) if not snap.empty else 0
        n_paths = int(snap["subdir"].nunique()) if not snap.empty else 0
        total_storage = (
            format_bytes(float(burst_df["size"].sum())) if not burst_df.empty else "0 Bytes"
        )

        cards = [
            indicator_card("Fileshares", n_shares),
            indicator_card("Distinct ACLs", n_acls),
            indicator_card("Permission Diffs", n_paths),
            indicator_card("Tracked Storage", total_storage),
        ]

        timeline_fig = build_timeline_figure(all_timeline)
        sunburst_fig = build_dashboard_sunburst_figure(burst_df)
        pie_fig = build_permission_pie_figure(snap)
        net_fig = build_acl_network_figure(members_df)

        table_view: Any
        if snap.empty:
            table_view = html.P("No access records matching the current filters.")
        else:
            preview = snap.head(250)
            cols = [str(c) for c in preview.columns]
            table_view = html.Table(
                style={"width": "100%", "borderCollapse": "collapse", "fontSize": "0.85rem"},
                children=[
                    html.Thead(
                        html.Tr(
                            [
                                html.Th(
                                    col,
                                    style={
                                        "textAlign": "left",
                                        "padding": "8px",
                                        "borderBottom": "2px solid #cbd5e1",
                                    },
                                )
                                for col in cols
                            ]
                        )
                    ),
                    html.Tbody(
                        [
                            html.Tr(
                                [
                                    html.Td(
                                        "" if pd.isna(val) else str(val),
                                        style={
                                            "padding": "6px 8px",
                                            "borderBottom": "1px solid #e2e8f0",
                                        },
                                    )
                                    for val in row
                                ]
                            )
                            for row in preview.itertuples(index=False, name=None)
                        ]
                    ),
                ],
            )
        return cards, timeline_fig, sunburst_fig, pie_fig, net_fig, table_view

    return app


def run_dashboard(settings: DashboardServeSettings) -> int:
    """Launch the LANdash web server from *settings*.

    Parameters
    ----------
    settings
        Parsed CLI / configuration settings for ``lanspector dashboard``.

    Returns
    -------
    int
        Exit status code (``0`` on clean shutdown, ``1`` if DB is missing).
    """
    if not settings.dashboard_db.exists():
        logger.error(
            "LANdash database not found: {}. Run 'lanspector dashboard-prep "
            '--databases "[crawl.db]" --dashboard_db {}\' first.',
            settings.dashboard_db,
            settings.dashboard_db,
        )
        return 1
    app = create_app(settings.dashboard_db)
    logger.info("Serving LANdash at http://{}:{}", settings.host, settings.port)
    app.run(host=settings.host, port=settings.port, debug=settings.debug)
    return 0


# ---------------------------------------------------------------------------
# Pure Plotly figure builders (alphabetical, testable without browser)
# ---------------------------------------------------------------------------


def build_acl_network_figure(members_df: pd.DataFrame) -> go.Figure:
    """Render an interactive Plotly graph of ACL groups connected to their members.

    Parameters
    ----------
    members_df
        DataFrame returned by :meth:`~lanspector.dashboard.data_prep.LanDashStore.get_acl_membership`.

    Returns
    -------
    plotly.graph_objects.Figure
        Plotly scatter/edge network figure.
    """
    fig = go.Figure()
    if members_df.empty:
        fig.update_layout(title="ACL Membership Network (no AD membership data)")
        return fig

    groups = sorted(members_df["acl_name"].astype(str).unique().tolist())
    members = sorted(members_df["member_name"].astype(str).unique().tolist())
    coords: dict[str, tuple[float, float]] = {}

    for idx, grp in enumerate(groups):
        angle = 2.0 * math.pi * idx / max(1, len(groups))
        coords[f"G:{grp}"] = (math.cos(angle), math.sin(angle))
    for idx, mem in enumerate(members):
        angle = 2.0 * math.pi * idx / max(1, len(members))
        coords[f"M:{mem}"] = (2.2 * math.cos(angle), 2.2 * math.sin(angle))

    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    for acl_name, member_name in zip(
        members_df["acl_name"].astype(str),
        members_df["member_name"].astype(str),
        strict=False,
    ):
        gx, gy = coords[f"G:{acl_name}"]
        mx, my = coords[f"M:{member_name}"]
        edge_x.extend([gx, mx, None])
        edge_y.extend([gy, my, None])

    fig.add_trace(
        go.Scatter(
            x=edge_x,
            y=edge_y,
            mode="lines",
            line={"width": 1, "color": "#94a3b8"},
            hoverinfo="none",
            showlegend=False,
        )
    )
    fig.add_trace(
        go.Scatter(
            x=[coords[f"G:{g}"][0] for g in groups],
            y=[coords[f"G:{g}"][1] for g in groups],
            mode="markers+text",
            text=groups,
            textposition="top center",
            marker={"size": 14, "color": get_series_color(0)},
            name="ACL Groups",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=[coords[f"M:{m}"][0] for m in members],
            y=[coords[f"M:{m}"][1] for m in members],
            mode="markers+text",
            text=members,
            textposition="bottom center",
            marker={"size": 9, "color": get_series_color(1)},
            name="Members",
        )
    )
    fig.update_layout(
        title="ACL Membership Network",
        xaxis={"visible": False},
        yaxis={"visible": False},
        margin={"t": 45, "l": 10, "r": 10, "b": 10},
    )
    return fig


def build_dashboard_sunburst_figure(burst_df: pd.DataFrame) -> go.Figure:
    """Build a native Plotly :class:`go.Sunburst` figure from ``dashburst`` rows.

    Parameters
    ----------
    burst_df
        DataFrame returned by :meth:`~lanspector.dashboard.data_prep.LanDashStore.load_sunburst_data`.

    Returns
    -------
    plotly.graph_objects.Figure
        Interactive Plotly Sunburst figure.
    """
    if burst_df.empty:
        fig = go.Figure()
        fig.update_layout(title="Storage Sunburst (no data)")
        return fig

    hierarchy = paths_to_hierarchy_df(
        burst_df, path_col="path", size_col="size", atime_col="max_atime"
    )
    if hierarchy.empty:
        fig = go.Figure()
        fig.update_layout(title="Storage Sunburst (no data)")
        return fig

    hover_text = build_sunburst_hover_text(hierarchy)
    fig = go.Figure(
        go.Sunburst(
            ids=hierarchy["id"].tolist(),
            labels=hierarchy["label"].tolist(),
            parents=hierarchy["parent"].tolist(),
            values=hierarchy["size"].tolist(),
            branchvalues="total",
            hovertext=hover_text,
            hovertemplate="%{hovertext}<extra></extra>",
            marker={
                "colors": hierarchy["age_days"].tolist(),
                "colorscale": "RdYlGn_r",
                "showscale": True,
                "colorbar": {"title": "Days Since Last Access"},
            },
        )
    )
    fig.update_layout(margin={"t": 20, "l": 10, "r": 10, "b": 10})
    return fig


def build_permission_pie_figure(snap_df: pd.DataFrame) -> go.Figure:
    """Build a pie chart showing the breakdown of permission levels in the snapshot.

    Parameters
    ----------
    snap_df
        Filtered parent-vs-child snapshot DataFrame.

    Returns
    -------
    plotly.graph_objects.Figure
        Plotly pie figure.
    """
    fig = go.Figure()
    if snap_df.empty or "permission" not in snap_df.columns:
        fig.update_layout(title="Permission Distribution (no data)")
        return fig
    counts = snap_df["permission"].fillna("Unknown").value_counts()
    fig.add_trace(go.Pie(labels=counts.index.tolist(), values=counts.values.tolist(), hole=0.35))
    fig.update_layout(title="Permission Distribution", margin={"t": 45, "l": 10, "r": 10, "b": 10})
    return fig


def build_timeline_figure(timeline_df: pd.DataFrame) -> go.Figure:
    """Build a time-series line chart of permission diff counts by crawl date.

    Parameters
    ----------
    timeline_df
        Parent-vs-child records across all available crawl dates.

    Returns
    -------
    plotly.graph_objects.Figure
        Plotly line chart grouped by permission code.
    """
    fig = go.Figure()
    if timeline_df.empty:
        fig.update_layout(title="Permission Exposure Timeline (no data)")
        return fig
    grouped = timeline_df.groupby(["crawlDate", "permission"], as_index=False).size()
    for idx, (perm, grp) in enumerate(grouped.groupby("permission")):
        fig.add_trace(
            go.Scatter(
                x=grp["crawlDate"].astype(str).tolist(),
                y=grp["size"].tolist(),
                mode="lines+markers",
                name=str(perm),
                line={"color": get_series_color(idx)},
            )
        )
    fig.update_layout(
        title="Permission Diffs Over Time",
        xaxis_title="Crawl Date",
        yaxis_title="Number of Entries",
        margin={"t": 45, "l": 45, "r": 20, "b": 40},
    )
    return fig
