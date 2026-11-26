"""Optional LANdash interactive web dashboard (requires ``lanspector[dashboard]``)."""

from __future__ import annotations

from lanspector.dashboard.data_prep import (
    LanDashStore,
    commit_data_to_database,
    create_dashboard_tables,
    generate_dashboard_data,
)

__all__ = [
    "LanDashStore",
    "commit_data_to_database",
    "create_dashboard_tables",
    "generate_dashboard_data",
]
