"""Interactive Plotly storage sunburst charts and hierarchical tree builders."""

from __future__ import annotations

import datetime
import json
import pathlib
import re
import webbrowser
from typing import Any

import pandas as pd
import plotly.graph_objects as go
from loguru import logger

from lanspector.constants import BYTE_UNIT_PREFIXES
from lanspector.datatypes import PlotlyJsMode, SunburstColorBy
from lanspector.reader import CrawlReader

# ---------------------------------------------------------------------------
# Primary public routines
# ---------------------------------------------------------------------------


def build_sunburst_figure(
    reader: CrawlReader | str | pathlib.Path,
    table: str | None = None,
    subdir: str | None = None,
    limit: int | None = 500,
    max_depth: int | None = None,
    color_by: SunburstColorBy = "age",
    title: str | None = None,
) -> go.Figure:
    """Build an interactive Plotly storage sunburst figure from a crawl database.

    Uses :class:`plotly.graph_objects.Sunburst` with ``branchvalues="total"`` so
    analysts can click any ring to zoom into storage hotspots and identify stale
    directories for cleanup.

    Parameters
    ----------
    reader
        An open :class:`~lanspector.reader.CrawlReader` or path to a SQLite crawl DB.
    table
        Crawl table name (defaults to latest crawl).
    subdir
        Optional subdirectory prefix filter.
    limit
        Maximum number of top directories to include (``None`` for all).
    max_depth
        Optional maximum ring depth relative to the common root.
    color_by
        Color scale metric: ``"age"`` (days since last access) or ``"size"`` (bytes).
    title
        Optional custom chart title.

    Returns
    -------
    plotly.graph_objects.Figure
        Interactive Plotly Sunburst figure.
    """
    owned = not isinstance(reader, CrawlReader)
    cr = CrawlReader(reader) if not isinstance(reader, CrawlReader) else reader
    try:
        tbl = table or cr.latest_crawl
        ld = cr.largest_subdirectories(table=tbl, subdir=subdir, limit=limit, max_atime=True)
        roots = cr.crawl_root(table=tbl)
        root_label = roots[0] if roots else "root"
    finally:
        if owned:
            cr.close()

    if ld.empty:
        fig = go.Figure()
        fig.update_layout(title=title or f"LANspector Storage Sunburst ({root_label}) — No Data")
        return fig

    hierarchy = paths_to_hierarchy_df(ld, max_depth=max_depth)
    if hierarchy.empty:
        fig = go.Figure()
        fig.update_layout(title=title or f"LANspector Storage Sunburst ({root_label}) — No Data")
        return fig

    total_bytes = float(hierarchy.loc[hierarchy["parent"] == "", "size"].sum()) or 1.0
    hover_text = build_sunburst_hover_text(hierarchy)

    if color_by == "age":
        color_vals = hierarchy["age_days"].tolist()
        colorscale = "RdYlGn_r"
        colorbar_title = "Days Since Last Access"
    else:
        color_vals = hierarchy["size"].tolist()
        colorscale = "Blues"
        colorbar_title = "Bytes"

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
                "colors": color_vals,
                "colorscale": colorscale,
                "showscale": True,
                "colorbar": {"title": colorbar_title},
            },
            maxdepth=max_depth or -1,
        )
    )
    chart_title = (
        title or f"LANspector Storage Sunburst — {root_label} ({format_bytes(total_bytes)})"
    )
    fig.update_layout(
        title=chart_title,
        margin={"t": 50, "l": 10, "r": 10, "b": 10},
    )
    return fig


def export_sunburst_html(
    reader: CrawlReader | str | pathlib.Path,
    output: str | pathlib.Path,
    table: str | None = None,
    subdir: str | None = None,
    limit: int | None = 500,
    max_depth: int | None = None,
    color_by: SunburstColorBy = "age",
    include_plotlyjs: PlotlyJsMode = "inline",
    open_browser: bool = False,
) -> pathlib.Path:
    """Render and save a standalone interactive Plotly HTML sunburst chart.

    Parameters
    ----------
    reader
        An open :class:`~lanspector.reader.CrawlReader` or path to a SQLite crawl DB.
    output
        Destination HTML file path.
    table
        Crawl table name (defaults to latest crawl).
    subdir
        Optional subdirectory prefix filter.
    limit
        Maximum top directories to include.
    max_depth
        Optional maximum folder ring depth.
    color_by
        Color metric (``"age"`` or ``"size"``).
    include_plotlyjs
        ``"inline"`` embeds Plotly.js for offline/air-gapped viewing; ``"cdn"`` links CDN.
    open_browser
        Open the generated HTML file in the system default browser when ``True``.

    Returns
    -------
    pathlib.Path
        Resolved path to the generated HTML file.
    """
    fig = build_sunburst_figure(
        reader=reader,
        table=table,
        subdir=subdir,
        limit=limit,
        max_depth=max_depth,
        color_by=color_by,
    )
    out_path = pathlib.Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plotlyjs_arg: bool | str = True if include_plotlyjs == "inline" else "cdn"
    fig.write_html(str(out_path), include_plotlyjs=plotlyjs_arg, full_html=True)
    resolved = out_path.resolve()
    logger.info("Wrote Plotly sunburst chart to {}", resolved)
    if open_browser:
        webbrowser.open(resolved.as_uri())
    return resolved


# ---------------------------------------------------------------------------
# Supporting public utilities (alphabetical)
# ---------------------------------------------------------------------------


def build_sunburst_hover_text(hierarchy: pd.DataFrame) -> list[str]:
    """Build formatted Plotly hover overlay labels with auto-scaled byte sizes.

    Parameters
    ----------
    hierarchy
        Node table returned by :func:`paths_to_hierarchy_df`.

    Returns
    -------
    list[str]
        HTML hover overlay strings (one per row) with human-readable ``TB/GB/MB/KB``
        sizes, root share percentage, and last-access date.
    """
    total_bytes = float(hierarchy.loc[hierarchy["parent"] == "", "size"].sum()) or 1.0
    human_sizes = [format_bytes(s) for s in hierarchy["size"]]
    pct_of_root = [100.0 * float(s) / total_bytes for s in hierarchy["size"]]
    atime_strs = [
        ts.strftime("%Y-%m-%d") if pd.notna(ts) else "n/a" for ts in hierarchy["max_atime"]
    ]
    return [
        f"<b>{label}</b><br>Path: {node_id}<br>Size: {hsize} ({pct:.1f}%)<br>Last Access: {atime}"
        for label, node_id, hsize, pct, atime in zip(
            hierarchy["label"],
            hierarchy["id"],
            human_sizes,
            pct_of_root,
            atime_strs,
            strict=False,
        )
    ]


def format_bytes(num_bytes: float) -> str:
    """Format *num_bytes* into a concise human-readable string (e.g. ``12.40 GB``).

    Parameters
    ----------
    num_bytes
        Byte count to format.

    Returns
    -------
    str
        Formatted size string with binary unit prefix using ``3.2f`` precision.
    """
    value = max(0.0, float(num_bytes))
    power = 0
    while power < 60 and value >= 2 ** (power + 10):
        power += 10
    unit = BYTE_UNIT_PREFIXES.get(power, "Bytes")
    if power == 0:
        return f"{int(value)} {unit}"
    return f"{value / (2**power):3.2f} {unit}"


def paths_to_flare_dict(
    df: pd.DataFrame,
    path_col: str = "path",
    size_col: str = "size",
    jout: str | pathlib.Path | None = None,
) -> dict[str, Any]:
    """Convert a directory-size DataFrame into a nested flare JSON tree dictionary.

    Parameters
    ----------
    df
        DataFrame with path and size columns.
    path_col
        Column containing directory paths.
    size_col
        Column containing numeric byte sizes.
    jout
        Optional path to persist the resulting JSON tree to disk.

    Returns
    -------
    dict[str, Any]
        Nested ``{"name": ..., "children": [...]}`` hierarchy dictionary.
    """
    root: dict[str, Any] = {"name": "root", "children": []}
    if df.empty:
        return root

    node_map: dict[tuple[str, ...], dict[str, Any]] = {(): root}
    for row in df[[path_col, size_col]].itertuples(index=False, name=None):
        raw_path, raw_size = str(row[0]), float(row[1] or 0)
        parts = _split_components(raw_path)
        if not parts:
            continue
        for depth in range(1, len(parts) + 1):
            key = tuple(parts[:depth])
            if key not in node_map:
                parent_node = node_map[key[:-1]]
                new_node: dict[str, Any] = {"name": parts[depth - 1], "children": []}
                parent_node["children"].append(new_node)
                node_map[key] = new_node
        leaf = node_map[tuple(parts)]
        leaf["size"] = leaf.get("size", 0.0) + raw_size

    # Collapse single-child root wrappers so the top ring starts at the first branch
    current = root
    while len(current.get("children", [])) == 1 and "size" not in current:
        child = current["children"][0]
        if child.get("children"):
            current = child
        else:
            break

    _prune_empty_children(current)
    if jout is not None:
        out_path = pathlib.Path(jout)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(current, indent=2), encoding="utf-8")
    return current


def paths_to_hierarchy_df(
    df: pd.DataFrame,
    path_col: str = "path",
    size_col: str = "size",
    atime_col: str = "max_atime",
    max_depth: int | None = None,
) -> pd.DataFrame:
    """Aggregate a flat directory-size DataFrame into a Plotly Sunburst node table.

    Rolls up descendant byte sizes onto every ancestor node so ``branchvalues="total"``
    holds strictly across the entire tree.

    Parameters
    ----------
    df
        DataFrame with ``path``, ``size``, and optional ``max_atime`` columns.
    path_col
        Column name holding directory paths.
    size_col
        Column name holding immediate byte sizes.
    atime_col
        Optional column name holding latest access timestamps.
    max_depth
        Optional depth limit below the common root prefix.

    Returns
    -------
    pandas.DataFrame
        DataFrame with columns ``id``, ``label``, ``parent``, ``size``, ``max_atime``, ``age_days``.
    """
    cols = ["id", "label", "parent", "size", "max_atime", "age_days"]
    if df.empty:
        return pd.DataFrame(columns=cols)

    parsed_rows: list[tuple[list[str], float, pd.Timestamp | None]] = []
    has_atime = atime_col in df.columns
    for idx in range(len(df)):
        parts = _split_components(str(df.iloc[idx][path_col]))
        size_val = float(df.iloc[idx][size_col] or 0)
        if not parts or size_val <= 0:
            continue
        atime_val: pd.Timestamp | None = None
        if has_atime:
            ts = pd.to_datetime(df.iloc[idx][atime_col], errors="coerce")
            if pd.notna(ts):
                atime_val = ts
        parsed_rows.append((parts, size_val, atime_val))

    if not parsed_rows:
        return pd.DataFrame(columns=cols)

    # Strip shared leading prefix while keeping the deepest common root directory
    common_len = 0
    min_len = min(len(p) for p, _, _ in parsed_rows)
    while common_len < min_len:
        seg = parsed_rows[0][0][common_len]
        if all(p[common_len] == seg for p, _, _ in parsed_rows):
            common_len += 1
        else:
            break
    strip_len = max(0, common_len - 1)

    totals: dict[tuple[str, ...], float] = {}
    max_atimes: dict[tuple[str, ...], pd.Timestamp | None] = {}

    for parts, size_val, atime_val in parsed_rows:
        trimmed = parts[strip_len:]
        if max_depth is not None and max_depth > 0:
            trimmed = trimmed[: max_depth + 1]
        for depth in range(1, len(trimmed) + 1):
            key = tuple(trimmed[:depth])
            totals[key] = totals.get(key, 0.0) + size_val
            if atime_val is not None:
                prev = max_atimes.get(key)
                if prev is None or atime_val > prev:
                    max_atimes[key] = atime_val

    now = pd.Timestamp(datetime.datetime.now(datetime.UTC).replace(tzinfo=None))
    records: list[dict[str, Any]] = []
    for key, total_size in sorted(totals.items(), key=lambda kv: (len(kv[0]), kv[0])):
        node_id = "/".join(key)
        parent_id = "/".join(key[:-1]) if len(key) > 1 else ""
        label = key[-1]
        atime_val = max_atimes.get(key)
        age_days = (
            max(0.0, float((now - atime_val).total_seconds() / 86400.0))
            if atime_val is not None
            else 0.0
        )
        records.append(
            {
                "id": node_id,
                "label": label,
                "parent": parent_id,
                "size": total_size,
                "max_atime": atime_val,
                "age_days": round(age_days, 1),
            }
        )

    return pd.DataFrame.from_records(records, columns=cols)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _prune_empty_children(node: dict[str, Any]) -> None:
    """Recursively remove empty ``children`` lists from leaf flare nodes."""
    children = node.get("children")
    if not children:
        node.pop("children", None)
        return
    for child in children:
        _prune_empty_children(child)


def _split_components(path: str) -> list[str]:
    """Split Windows or POSIX path strings into clean non-empty segments."""
    return [seg for seg in re.split(r"[\\/]+", path.strip()) if seg]
