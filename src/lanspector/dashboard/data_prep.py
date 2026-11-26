"""SQLite data store and ETL pipeline backing the optional LANdash web dashboard."""

from __future__ import annotations

import datetime
import pathlib
from collections.abc import Sequence
from typing import Any

import pandas as pd
from loguru import logger
from sqlalchemy import (
    Column,
    Date,
    Engine,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    inspect,
    text,
)

from lanspector.crawler import create_crawl_engine
from lanspector.platform import extract_domain_host_share_subdir
from lanspector.reader import CrawlReader

# ---------------------------------------------------------------------------
# Primary class & ETL functions
# ---------------------------------------------------------------------------


class LanDashStore:
    """SQLite-backed analytical store serving the LANdash web dashboard.

    Parameters
    ----------
    db
        Path to a LANdash SQLite database or an existing SQLAlchemy :class:`Engine`.
    """

    def __init__(self, db: str | pathlib.Path | Engine) -> None:
        if isinstance(db, Engine):
            self.engine = db
            self.db_path: pathlib.Path | None = None
        else:
            self.db_path = pathlib.Path(db)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.engine = create_crawl_engine(self.db_path)
        create_dashboard_tables(self.engine)

    def __enter__(self) -> LanDashStore:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            f"<LanDashStore ({len(self.crawl_dates)} dates, "
            f"{len(self.fileshares)} fileshares, {len(self.acl_principals)} principals)>"
        )

    def close(self) -> None:
        """Dispose the underlying SQLAlchemy engine."""
        self.engine.dispose()

    @property
    def acl_principals(self) -> pd.DataFrame:
        """Return all distinct AD/POSIX principals stored in ``adobjects``."""
        return pd.read_sql_table("adobjects", self.engine)

    @property
    def crawl_dates(self) -> list[str]:
        """Return sorted ISO date strings present in ``parentVchild``."""
        df = pd.read_sql_query(
            "SELECT DISTINCT crawlDate FROM parentVchild ORDER BY crawlDate", self.engine
        )
        return [str(v) for v in df["crawlDate"].dropna().tolist()]

    @property
    def fileshares(self) -> pd.DataFrame:
        """Return all fileshares registered in ``fileshares``."""
        return pd.read_sql_table("fileshares", self.engine)

    def get_acl_membership(
        self,
        crawl_date: str | None = None,
        acl_names: Sequence[str] | None = None,
    ) -> pd.DataFrame:
        """Query ACL group membership records with resolved principal names.

        Parameters
        ----------
        crawl_date
            Optional ISO crawl date filter.
        acl_names
            Optional list of ACL group names to filter.

        Returns
        -------
        pandas.DataFrame
            DataFrame with ``crawlDate``, ``acl_domain``, ``acl_name``, ``member_domain``,
            ``member_name``, and ``nested_acl``.
        """
        qry = """
            SELECT
                m.crawlDate,
                a.Domain AS acl_domain,
                a.Name AS acl_name,
                u.Domain AS member_domain,
                u.Name AS member_name,
                m.nested_acl
            FROM acl_membership m
            INNER JOIN adobjects a ON m.acl_id = a.adobj_id
            INNER JOIN adobjects u ON m.member_id = u.adobj_id
        """
        df = pd.read_sql_query(qry, self.engine)
        if df.empty:
            return df
        if crawl_date:
            df = df[df["crawlDate"].astype(str) == str(crawl_date)]
        if acl_names:
            lowered = {n.lower() for n in acl_names}
            df = df[df["acl_name"].astype(str).str.lower().isin(lowered)]
        return df.reset_index(drop=True)

    def get_crawl_data(
        self,
        crawl_date: str | None = None,
        domains: Sequence[str] | None = None,
        hosts: Sequence[str] | None = None,
        acl_domains: Sequence[str] | None = None,
        acl_names: Sequence[str] | None = None,
        permissions: Sequence[str] | None = None,
    ) -> pd.DataFrame:
        """Query joined parent-vs-child permission timeline rows with optional filters.

        Parameters
        ----------
        crawl_date
            Optional exact ISO crawl date.
        domains
            Optional list of fileshare domains.
        hosts
            Optional list of fileshare hostnames.
        acl_domains
            Optional list of ACL domains.
        acl_names
            Optional list of ACL principal names.
        permissions
            Optional list of permission codes (e.g. ``["R", "M", "F"]``).

        Returns
        -------
        pandas.DataFrame
            Filtered permission records.
        """
        qry = """
            SELECT
                p.crawlDate,
                f.domain,
                f.host,
                f.share,
                p.subdir,
                a.Domain AS acl_domain,
                a.Name AS acl_name,
                p.permission,
                p.fileshare_lastaccess
            FROM parentVchild p
            INNER JOIN fileshares f ON p.fileshare_id = f.fileshare_id
            INNER JOIN adobjects a ON p.adobj_id = a.adobj_id
        """
        df = pd.read_sql_query(qry, self.engine)
        if df.empty:
            return df
        if crawl_date:
            df = df[df["crawlDate"].astype(str) == str(crawl_date)]
        if domains:
            df = df[df["domain"].isin(domains)]
        if hosts:
            df = df[df["host"].isin(hosts)]
        if acl_domains:
            df = df[df["acl_domain"].isin(acl_domains)]
        if acl_names:
            df = df[df["acl_name"].isin(acl_names)]
        if permissions:
            df = df[df["permission"].isin(permissions)]
        return df.reset_index(drop=True)

    def load_sunburst_data(
        self,
        domains: Sequence[str] | None = None,
        hosts: Sequence[str] | None = None,
        folder_filter: str | None = None,
        limit: int = 500,
    ) -> pd.DataFrame:
        """Query directory storage sizes and access dates for the dashboard sunburst panel.

        Parameters
        ----------
        domains
            Optional list of fileshare domains.
        hosts
            Optional list of fileshare hosts.
        folder_filter
            Optional case-insensitive substring filter applied to ``subdir``.
        limit
            Maximum rows ordered by ``size`` descending.

        Returns
        -------
        pandas.DataFrame
            DataFrame with ``path``, ``domain``, ``host``, ``share``, ``subdir``,
            ``size``, and ``max_atime``.
        """
        qry = """
            SELECT
                f.domain,
                f.host,
                f.share,
                d.subdir,
                d.size,
                d.atime AS max_atime
            FROM dashburst d
            INNER JOIN fileshares f ON d.fileshare_id = f.fileshare_id
            ORDER BY d.size DESC
        """
        df = pd.read_sql_query(qry, self.engine)
        if df.empty:
            return pd.DataFrame(
                columns=["path", "domain", "host", "share", "subdir", "size", "max_atime"]
            )
        if domains:
            df = df[df["domain"].isin(domains)]
        if hosts:
            df = df[df["host"].isin(hosts)]
        if folder_filter:
            df = df[df["subdir"].astype(str).str.contains(folder_filter, case=False, na=False)]
        if limit > 0:
            df = df.head(limit)
        df = df.copy()
        df["path"] = (
            df["host"].astype(str)
            + "/"
            + df["share"].astype(str)
            + "/"
            + df["subdir"].fillna("").astype(str)
        ).str.rstrip("/")
        return df.reset_index(drop=True)


def generate_dashboard_data(
    databases: Sequence[str | pathlib.Path],
    include_ntfs: bool = True,
    include_acls: bool = True,
    include_sunburst: bool = True,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Extract normalized permission, membership, and sunburst tables from crawl databases.

    Parameters
    ----------
    databases
        Sequence of LANspector SQLite crawl database paths.
    include_ntfs
        Extract melted parent-vs-child permission snapshots.
    include_acls
        Extract ACL group membership records when present.
    include_sunburst
        Extract directory storage & access-time records for sunburst charts.

    Returns
    -------
    tuple[pandas.DataFrame, pandas.DataFrame, pandas.DataFrame]
        Three DataFrames: ``(access_df, membership_df, sunburst_df)``.
    """
    access_parts: list[pd.DataFrame] = []
    acl_parts: list[pd.DataFrame] = []
    burst_parts: list[pd.DataFrame] = []

    for db_path in databases:
        p = pathlib.Path(db_path)
        if not p.exists():
            logger.warning("Skipping missing crawl database: {}", p)
            continue

        with CrawlReader(p) as reader:
            if not reader.crawls:
                logger.debug("Skipping non-crawl SQLite database: {}", p)
                continue
            for tbl in reader.crawls:
                crawl_date = _parse_crawl_date(tbl)
                if include_ntfs:
                    pvc = reader.parent_vs_child_report(
                        table=tbl,
                        skip_files_report=True,
                        add_latest_atime=True,
                        melt=True,
                    )
                    if pvc.dirs_df is not None and not pvc.dirs_df.empty:
                        frame = pvc.dirs_df.copy()
                        parsed = [extract_domain_host_share_subdir(str(x)) for x in frame["path"]]
                        frame["domain"] = [t[0] for t in parsed]
                        frame["host"] = [t[1] for t in parsed]
                        frame["share"] = [t[2] for t in parsed]
                        frame["subdir"] = [t[3] for t in parsed]
                        frame["crawlDate"] = crawl_date
                        access_parts.append(frame)

                if include_acls:
                    members = reader.summarize_acls(table=tbl)
                    if members is not None and not members.empty:
                        mframe = members.copy()
                        mframe["crawlDate"] = crawl_date
                        acl_parts.append(mframe)

            if include_sunburst and reader.latest_crawl is not None:
                ld = reader.largest_subdirectories(table=reader.latest_crawl, max_atime=True)
                if not ld.empty:
                    bframe = ld[ld["size"] > 0].copy()
                    parsed = [extract_domain_host_share_subdir(str(x)) for x in bframe["path"]]
                    bframe["domain"] = [t[0] for t in parsed]
                    bframe["host"] = [t[1] for t in parsed]
                    bframe["share"] = [t[2] for t in parsed]
                    bframe["subdir"] = [t[3] for t in parsed]
                    bframe["atime"] = pd.to_datetime(bframe["max_atime"], errors="coerce").dt.date
                    burst_parts.append(
                        bframe[["domain", "host", "share", "subdir", "size", "atime"]]
                    )

    access_df = pd.concat(access_parts, ignore_index=True) if access_parts else pd.DataFrame()
    membership_df = pd.concat(acl_parts, ignore_index=True) if acl_parts else pd.DataFrame()
    sunburst_df = pd.concat(burst_parts, ignore_index=True) if burst_parts else pd.DataFrame()
    return access_df, membership_df, sunburst_df


def commit_data_to_database(
    store: LanDashStore | str | pathlib.Path,
    access_df: pd.DataFrame | None = None,
    membership_df: pd.DataFrame | None = None,
    sunburst_df: pd.DataFrame | None = None,
) -> None:
    """Persist extracted dashboard DataFrames into a :class:`LanDashStore` SQLite database.

    Parameters
    ----------
    store
        Open :class:`LanDashStore` or path to a LANdash SQLite database.
    access_df
        Parent-vs-child permission timeline DataFrame.
    membership_df
        ACL membership DataFrame.
    sunburst_df
        Directory size and last-access DataFrame.
    """
    owned = not isinstance(store, LanDashStore)
    dash_store = LanDashStore(store) if not isinstance(store, LanDashStore) else store
    try:
        engine = dash_store.engine

        # 1. Upsert fileshares
        fs_frames = [
            df[["domain", "host", "share"]].drop_duplicates()
            for df in (access_df, sunburst_df)
            if df is not None and not df.empty and {"domain", "host", "share"}.issubset(df.columns)
        ]
        if fs_frames:
            fs_new = pd.concat(fs_frames, ignore_index=True).drop_duplicates()
            existing_fs = pd.read_sql_table("fileshares", engine)
            existing_keys = set(
                zip(existing_fs["domain"], existing_fs["host"], existing_fs["share"], strict=False)
            )
            to_insert = fs_new[
                [
                    (d, h, s) not in existing_keys
                    for d, h, s in zip(
                        fs_new["domain"], fs_new["host"], fs_new["share"], strict=False
                    )
                ]
            ]
            if not to_insert.empty:
                to_insert.to_sql("fileshares", engine, if_exists="append", index=False)

        fs_map = {
            (str(rec["domain"]), str(rec["host"]), str(rec["share"])): int(rec["fileshare_id"])
            for rec in pd.read_sql_table("fileshares", engine).to_dict("records")
        }

        # 2. Upsert AD/POSIX principals
        principal_rows: list[tuple[str, str, str]] = []
        if access_df is not None and not access_df.empty:
            for d, n in zip(access_df["Domain"], access_df["Name"], strict=False):
                principal_rows.append((str(d or "BUILTIN"), str(n), "Principal"))
        if membership_df is not None and not membership_df.empty:
            for rec in membership_df.to_dict("records"):
                dom = str(rec.get("Domain") or "BUILTIN")
                acl = str(rec.get("ACL") or "")
                if acl:
                    principal_rows.append((dom, acl, "Group"))
                member = str(rec.get("member.logon") or rec.get("member_logon") or "")
                if member:
                    if "\\" in member:
                        mdom, mname = member.split("\\", 1)
                    else:
                        mdom, mname = dom, member
                    principal_rows.append((mdom, mname, "User"))

        if principal_rows:
            existing_ad = pd.read_sql_table("adobjects", engine)
            existing_ad_keys = {
                (str(d).lower(), str(n).lower())
                for d, n in zip(existing_ad["Domain"], existing_ad["Name"], strict=False)
            }
            deduped: list[dict[str, str]] = []
            for d, n, t in principal_rows:
                key = (d.lower(), n.lower())
                if key not in existing_ad_keys:
                    existing_ad_keys.add(key)
                    deduped.append({"Domain": d, "Name": n, "type": t})
            if deduped:
                pd.DataFrame.from_records(deduped).to_sql(
                    "adobjects", engine, if_exists="append", index=False
                )

        ad_map = {
            (str(rec["Domain"]).lower(), str(rec["Name"]).lower()): int(rec["adobj_id"])
            for rec in pd.read_sql_table("adobjects", engine).to_dict("records")
        }

        # 3. Insert parentVchild rows
        if access_df is not None and not access_df.empty:
            pvc_rows: list[dict[str, Any]] = []
            for rec in access_df.to_dict("records"):
                fs_id = fs_map.get((str(rec["domain"]), str(rec["host"]), str(rec["share"])))
                ad_id = ad_map.get(
                    (str(rec.get("Domain") or "BUILTIN").lower(), str(rec["Name"]).lower())
                )
                if fs_id is None or ad_id is None:
                    continue
                pvc_rows.append(
                    {
                        "crawlDate": rec["crawlDate"],
                        "fileshare_id": fs_id,
                        "adobj_id": ad_id,
                        "subdir": str(rec.get("subdir") or ""),
                        "permission": str(rec.get("permission") or ""),
                        "fileshare_lastaccess": rec.get("fileshare_lastaccess"),
                    }
                )
            if pvc_rows:
                pd.DataFrame.from_records(pvc_rows).to_sql(
                    "parentVchild", engine, if_exists="append", index=False, chunksize=500
                )

        # 4. Insert acl_membership rows
        if membership_df is not None and not membership_df.empty:
            mem_rows: list[dict[str, Any]] = []
            for rec in membership_df.to_dict("records"):
                dom = str(rec.get("Domain") or "BUILTIN")
                acl = str(rec.get("ACL") or "")
                member = str(rec.get("member.logon") or rec.get("member_logon") or "")
                mdom, mname = member.split("\\", 1) if "\\" in member else (dom, member)
                acl_id = ad_map.get((dom.lower(), acl.lower()))
                mem_id = ad_map.get((mdom.lower(), mname.lower()))
                if acl_id is None or mem_id is None:
                    continue
                mem_rows.append(
                    {
                        "crawlDate": rec["crawlDate"],
                        "acl_id": acl_id,
                        "member_id": mem_id,
                        "nested_acl": str(rec.get("member.nestedACL") or ""),
                    }
                )
            if mem_rows:
                pd.DataFrame.from_records(mem_rows).to_sql(
                    "acl_membership", engine, if_exists="append", index=False, chunksize=500
                )

        # 5. Replace dashburst snapshot rows for updated fileshares
        if sunburst_df is not None and not sunburst_df.empty:
            burst_rows: list[dict[str, Any]] = []
            touched_fs: set[int] = set()
            for rec in sunburst_df.to_dict("records"):
                fs_id = fs_map.get((str(rec["domain"]), str(rec["host"]), str(rec["share"])))
                if fs_id is None:
                    continue
                touched_fs.add(fs_id)
                burst_rows.append(
                    {
                        "fileshare_id": fs_id,
                        "subdir": str(rec.get("subdir") or ""),
                        "size": int(rec["size"]),
                        "atime": rec.get("atime"),
                    }
                )
            if touched_fs:
                with engine.begin() as conn:
                    for fid in touched_fs:
                        conn.execute(
                            text("DELETE FROM dashburst WHERE fileshare_id = :fid"), {"fid": fid}
                        )
            if burst_rows:
                pd.DataFrame.from_records(burst_rows).to_sql(
                    "dashburst", engine, if_exists="append", index=False, chunksize=500
                )
    finally:
        if owned:
            dash_store.close()


def create_dashboard_tables(engine: Engine) -> None:
    """Create the normalized LANdash SQLite schema if tables do not already exist.

    Parameters
    ----------
    engine
        SQLAlchemy 2.x engine pointing to the LANdash SQLite database.
    """
    existing = set(inspect(engine).get_table_names())
    meta = MetaData()

    if "fileshares" not in existing:
        Table(
            "fileshares",
            meta,
            Column("fileshare_id", Integer, primary_key=True),
            Column("domain", String(64), index=True, nullable=False),
            Column("host", String(128), index=True, nullable=False),
            Column("share", String(128), index=True, nullable=False),
        )

    if "adobjects" not in existing:
        Table(
            "adobjects",
            meta,
            Column("adobj_id", Integer, primary_key=True),
            Column("Domain", String(64), index=True, nullable=True),
            Column("Name", String(128), index=True, nullable=False),
            Column("type", String(32), index=True),
        )

    if "parentVchild" not in existing:
        Table(
            "parentVchild",
            meta,
            Column("crawlDate", Date, index=True, nullable=False),
            Column("fileshare_id", Integer, ForeignKey("fileshares.fileshare_id"), nullable=False),
            Column("adobj_id", Integer, ForeignKey("adobjects.adobj_id"), nullable=False),
            Column("subdir", String(1024)),
            Column("permission", String(32)),
            Column("fileshare_lastaccess", Date),
        )

    if "acl_membership" not in existing:
        Table(
            "acl_membership",
            meta,
            Column("crawlDate", Date, index=True, nullable=False),
            Column("acl_id", Integer, ForeignKey("adobjects.adobj_id"), nullable=False),
            Column("member_id", Integer, ForeignKey("adobjects.adobj_id"), nullable=False),
            Column("nested_acl", String(196)),
        )

    if "dashburst" not in existing:
        Table(
            "dashburst",
            meta,
            Column("fileshare_id", Integer, ForeignKey("fileshares.fileshare_id"), nullable=False),
            Column("subdir", String(2048)),
            Column("size", Integer),
            Column("atime", Date),
        )

    meta.create_all(engine)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_crawl_date(tablename: str) -> datetime.date:
    """Extract a date from a crawl timestamp table name, falling back to today."""
    for fmt in ("%Y%m%dT%H%M%S", "%Y%m%d"):
        try:
            return datetime.datetime.strptime(tablename, fmt).date()
        except ValueError:
            continue
    return datetime.datetime.now(datetime.UTC).date()
