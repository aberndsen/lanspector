"""Neutral reusable Dash 3+ UI components and palette helpers for LANdash."""

from __future__ import annotations

from typing import Any

from lanspector.constants import BYTE_UNIT_PREFIXES

NEUTRAL_PALETTE: tuple[str, ...] = (
    "#1f77b4",
    "#2ca02c",
    "#ff7f0e",
    "#d62728",
    "#9467bd",
    "#17becf",
    "#8c564b",
    "#e377c2",
    "#7f7f7f",
    "#bcbd22",
)


def autoscale_bytes(value: float) -> tuple[int, str]:
    """Determine the binary power-of-2 exponent and unit label for *value* bytes.

    Parameters
    ----------
    value
        Byte count to scale.

    Returns
    -------
    tuple[int, str]
        Pair of ``(exponent, unit_label)`` such as ``(30, "GB")``.
    """
    mag = 0
    while mag < 60 and value >= 2 ** (mag + 10):
        mag += 10
    return mag, BYTE_UNIT_PREFIXES.get(mag, "Bytes")


def get_series_color(index: int) -> str:
    """Return a deterministic neutral hex color for series *index*.

    Parameters
    ----------
    index
        Zero-based series index.

    Returns
    -------
    str
        Hex color string.
    """
    return NEUTRAL_PALETTE[index % len(NEUTRAL_PALETTE)]


def indicator_card(title: str, value: Any, card_id: str | None = None) -> Any:
    """Build a clean KPI card component for the LANdash executive summary row.

    Parameters
    ----------
    title
        Descriptive label shown above the metric.
    value
        Formatted metric value.
    card_id
        Optional Dash component ID assigned to the value element.

    Returns
    -------
    dash.html.Div
        Styled KPI card div.
    """
    from dash import html

    value_props: dict[str, Any] = {
        "style": {
            "fontSize": "1.75rem",
            "fontWeight": "700",
            "margin": "4px 0 0 0",
            "color": "#0f172a",
        },
    }
    if card_id is not None:
        value_props["id"] = card_id

    return html.Div(
        style={
            "flex": "1",
            "minWidth": "160px",
            "padding": "14px 18px",
            "backgroundColor": "#f8fafc",
            "border": "1px solid #e2e8f0",
            "borderRadius": "8px",
        },
        children=[
            html.Div(title, style={"fontSize": "0.85rem", "color": "#475569", "fontWeight": "600"}),
            html.Div(str(value), **value_props),
        ],
    )


def navbar(title: str = "LANspector Dashboard") -> Any:
    """Build a neutral top navigation bar for LANdash.

    Parameters
    ----------
    title
        Header title displayed on the navigation bar.

    Returns
    -------
    dash.html.Header
        Styled header banner component.
    """
    from dash import html

    return html.Header(
        style={
            "backgroundColor": "#0f172a",
            "color": "#f8fafc",
            "padding": "14px 24px",
            "display": "flex",
            "justifyContent": "space-between",
            "alignItems": "center",
        },
        children=[
            html.Span(title, style={"fontSize": "1.25rem", "fontWeight": "700"}),
            html.A(
                "LANspector on GitHub",
                href="https://github.com/aberndsen/lanspector",
                target="_blank",
                style={"color": "#93c5fd", "textDecoration": "none", "fontSize": "0.9rem"},
            ),
        ],
    )


def section_card(title: str, children: list[Any], open_by_default: bool = True) -> Any:
    """Wrap *children* inside a native HTML ``<details>`` collapsible panel.

    Parameters
    ----------
    title
        Section heading shown in the summary bar.
    children
        Dash components rendered inside the section body.
    open_by_default
        Whether the section starts expanded.

    Returns
    -------
    dash.html.Details
        Collapsible section container.
    """
    from dash import html

    return html.Details(
        open=open_by_default,
        style={
            "margin": "14px 0",
            "border": "1px solid #cbd5e1",
            "borderRadius": "8px",
            "backgroundColor": "#ffffff",
            "overflow": "hidden",
        },
        children=[
            html.Summary(
                title,
                style={
                    "padding": "12px 18px",
                    "backgroundColor": "#f1f5f9",
                    "fontWeight": "600",
                    "fontSize": "1rem",
                    "cursor": "pointer",
                },
            ),
            html.Div(children=children, style={"padding": "16px 18px"}),
        ],
    )
