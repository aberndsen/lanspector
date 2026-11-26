"""Query, SOX permission-diff analytics, and multi-database aggregation for LANspector crawls."""

from __future__ import annotations

import datetime
import inspect as pyinspect
import itertools
import os
import pathlib
import re
from collections.abc import Sequence
from typing import Any

import pandas as pd
from loguru import logger
from sqlalchemy import Engine, event, inspect, text

from lanspector.constants import (
    AUXILIARY_TABLE_SUFFIXES,
    BACKUP_REGEXES,
    BUILTIN_OPEN_ACCOUNTS,
    CRAWL_INFO_TABLE,
    DASHBOARD_TABLES,
    MEMBER_TABLE_SUFFIX,
    PERM_BIT_FULL,
    PERM_TABLE_SUFFIX,
    PII_TABLE_SUFFIX,
    PII_WORDS_TABLE_SUFFIX,
    SHARE_PERM_TABLE_SUFFIX,
    SUPPORTED_DB_EXTENSIONS,
    TIMESTAMP_FORMAT,
)
from lanspector.crawler import convert_to_sqlite, create_crawl_engine
from lanspector.datatypes import ExecutiveSummary, ParentChildResult
from lanspector.pii import count_pii_name_matches
from lanspector.platform import (
    bitmask_to_code,
    get_group_membership,
    ntfs_to_bitmask,
    reduce_permission_hierarchy,
    subdir_fqdn_to_hostname,
)

# ---------------------------------------------------------------------------
# Primary classes: CrawlReader & MultiDB
# ---------------------------------------------------------------------------


class CrawlReader:
    """Read and analyze LANspector SQLite crawl databases.

    Parameters
    ----------
    fname
        Path to a LANspector SQLite database (``.db``, ``.sqlite``, ``.sqlite3``)
        or a CSV/Excel crawl file (automatically converted to SQLite).
    overwrite
        When converting a CSV/Excel file, overwrite any existing table in the
        generated SQLite database.
    """

    def __init__(self, fname: str | pathlib.Path, overwrite: bool = False) -> None:
        src = pathlib.Path(fname)
        if not src.exists():
            raise FileNotFoundError(f"Could not find crawl database: {src.resolve()}")

        ext = src.suffix.lower()
        if ext in SUPPORTED_DB_EXTENSIONS:
            db_path = src
        elif ext in (".csv", ".xlsx", ".xlsm"):
            db_path = convert_to_sqlite(src, overwrite=overwrite)
        else:
            raise ValueError(f"Unrecognized LANspector database extension: {ext!r}")

        self.fname: pathlib.Path = db_path
        self.engine: Engine = create_crawl_engine(db_path)
        event.listen(self.engine, "connect", _register_sqlite_functions)

    def __enter__(self) -> CrawlReader:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"<CrawlReader: {self.fname.name}, {len(self.crawls)} crawls>"

    @property
    def is_multidb(self) -> bool:
        """Return ``False`` since this instance wraps a single database."""
        return False

    def close(self) -> None:
        """Dispose the underlying SQLAlchemy connection pool."""
        self.engine.dispose()

    # -- Important primary analytics routines -------------------------------

    def parent_vs_child_report(
        self,
        subdir: str | None = None,
        acl_skip: Sequence[tuple[str, str]] | None = None,
        table: str | None = None,
        restrict_to: str | Sequence[str] | None = None,
        ignore_dead_sids: bool = True,
        add_latest_atime: bool = False,
        alldirs: bool = False,
        use_permission_hierarchy: bool = False,
        skip_files_report: bool = False,
        flatten_cols: bool = False,
        strip_pathprefix: str | None = None,
        mapback: bool = True,
        melt: bool = False,
    ) -> ParentChildResult:
        """Generate the compressed parent-vs-child ACL permission-difference report.

        Lists the crawl root folder with its full effective permissions and every
        child folder whose permissions differ from its immediate parent. When
        ``skip_files_report=False``, also compares file permissions against their
        containing folder and flags files with *elevated* permissions.

        Parameters
        ----------
        subdir
            Optional subdirectory prefix to restrict the comparison.
        acl_skip
            Optional sequence of ``(Domain, Name)`` tuples to ignore during diffing.
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        restrict_to
            Optional ACL name or list of ACL names to focus the comparison on.
        ignore_dead_sids
            Ignore unresolved Windows SIDs (``S-1-5-*``) when comparing differences.
        add_latest_atime
            Append a ``fileshare_lastaccess`` date column derived from the latest file ``atime``.
        alldirs
            Return all directories rather than only those differing from their parent.
        use_permission_hierarchy
            Collapse subordinate permissions (e.g. ``MR`` -> ``M``, ``F`` dominates all).
        skip_files_report
            Omit the file-vs-folder elevated-permission comparison.
        flatten_cols
            Flatten ``(Domain, Name)`` column MultiIndex into ``Domain\\Name`` strings.
        strip_pathprefix
            Optional path prefix to strip from displayed paths.
        mapback
            Decode internal bitmask integers back to compact codes (``R``, ``A``, ``M``, ``S``, ``F``).
        melt
            Unpivot the report into long ``(path, Domain, Name, permission)`` format.

        Returns
        -------
        ParentChildResult
            Dataclass with ``dirs_df`` and ``files_df`` DataFrames (either may be ``None``).
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return ParentChildResult(dirs_df=None, files_df=None)

        ptable = f"{tbl}{PERM_TABLE_SUFFIX}"
        sptable = f"{tbl}{SHARE_PERM_TABLE_SUFFIX}"
        if ptable not in self.tables:
            logger.warning("Crawl {} did not harvest effective permissions.", tbl)
            return ParentChildResult(dirs_df=None, files_df=None)

        restrict_list: list[str] | None = None
        if isinstance(restrict_to, str):
            restrict_list = sorted(x.strip().lower() for x in restrict_to.split(",") if x.strip())
        elif restrict_to is not None:
            restrict_list = sorted(x.strip().lower() for x in restrict_to if x.strip())

        qry_d = (
            f"SELECT DISTINCT A.path, ifnull(B.Domain, '') AS Domain, B.Name, B.Permission "
            f"FROM [{tbl}] A INNER JOIN [{ptable}] B ON A.Id = B.Id "
            f"WHERE A.fname IS NULL"
        )
        ret_d = pd.read_sql_query(qry_d, self.engine)
        if ret_d.empty:
            return ParentChildResult(dirs_df=None, files_df=None)

        if strip_pathprefix:
            prefix = _normalize_strip_prefix(strip_pathprefix)
            ret_d["path"] = ret_d["path"].apply(
                lambda p: p.replace(prefix, "", 1) if isinstance(p, str) else p
            )

        ret_f: pd.DataFrame | None = None
        if not skip_files_report:
            with self.engine.connect() as conn:
                n_files = int(
                    conn.execute(
                        text(f"SELECT COUNT(Id) FROM [{tbl}] WHERE fname IS NOT NULL")
                    ).scalar()
                    or 0
                )
            if n_files > 150_000:
                qry_f = (
                    f"SELECT DISTINCT A.path, 'set(permissions on all files)' AS fname, "
                    f"ifnull(B.Domain, '') AS Domain, B.Name, B.Permission "
                    f"FROM [{tbl}] A INNER JOIN [{ptable}] B ON A.Id = B.Id "
                    f"WHERE A.fname IS NOT NULL"
                )
            else:
                qry_f = (
                    f"SELECT DISTINCT A.path, A.fname, ifnull(B.Domain, '') AS Domain, B.Name, B.Permission "
                    f"FROM [{tbl}] A INNER JOIN [{ptable}] B ON A.Id = B.Id "
                    f"WHERE A.fname IS NOT NULL"
                )
            ret_f = pd.read_sql_query(qry_f, self.engine)
            if restrict_list is not None and not ret_f.empty:
                ret_f = ret_f[ret_f["Name"].astype(str).str.lower().isin(restrict_list)]
            if strip_pathprefix and not ret_f.empty:
                prefix = _normalize_strip_prefix(strip_pathprefix)
                ret_f["path"] = ret_f["path"].apply(
                    lambda p: p.replace(prefix, "", 1) if isinstance(p, str) else p
                )

        if subdir is not None:
            norm_sub = os.path.normcase(os.path.normpath(subdir))
            mask_d = ret_d["path"].astype(str).str.startswith(norm_sub)
            if not mask_d.any():
                was_fqdn, alt_subdir = subdir_fqdn_to_hostname(subdir)
                if was_fqdn:
                    return self.parent_vs_child_report(
                        subdir=alt_subdir,
                        acl_skip=acl_skip,
                        table=tbl,
                        restrict_to=restrict_to,
                        ignore_dead_sids=ignore_dead_sids,
                        add_latest_atime=add_latest_atime,
                        alldirs=alldirs,
                        use_permission_hierarchy=use_permission_hierarchy,
                        skip_files_report=skip_files_report,
                        flatten_cols=flatten_cols,
                        strip_pathprefix=strip_pathprefix,
                        mapback=mapback,
                        melt=melt,
                    )
                return ParentChildResult(dirs_df=None, files_df=None)
            ret_d = ret_d[mask_d]
            if ret_f is not None and not ret_f.empty:
                ret_f = ret_f[ret_f["path"].astype(str).str.startswith(norm_sub)]

        pivots: dict[str, pd.DataFrame] = {}
        index_cols = {"dirs": ["path"], "files": ["path", "fname"]}
        for key, frame in (("dirs", ret_d), ("files", ret_f)):
            if frame is None:
                continue
            if frame.empty:
                pivots[key] = pd.DataFrame()
                continue
            work = frame.copy()
            work["Permission2"] = work["Permission"].map(ntfs_to_bitmask)
            work["Domain"] = work["Domain"].apply(
                lambda d: "BUILTIN" if not isinstance(d, str) or len(d) == 0 else d
            )
            piv = work.pivot_table(
                values="Permission2",
                index=index_cols[key],
                columns=["Domain", "Name"],
                aggfunc="sum",
                fill_value=0,
            )
            piv = piv.sort_index()
            pivots[key] = piv

        drop_cols: set[tuple[str, str]] = set()
        all_pivot_cols: set[tuple[str, str]] = set()
        for piv in pivots.values():
            if not piv.empty:
                all_pivot_cols.update(piv.columns.tolist())

        if ignore_dead_sids:
            drop_cols.update(c for c in all_pivot_cols if str(c[1]).startswith("S-1-5"))
        if acl_skip is not None:
            skip_set = set(acl_skip)
            drop_cols.update(c for c in all_pivot_cols if c in skip_set)
        if restrict_list is not None:
            drop_cols.update(c for c in all_pivot_cols if str(c[1]).lower() not in restrict_list)

        result_frames: dict[str, pd.DataFrame] = {}
        if alldirs:
            result_frames = pivots
        else:
            dirs_piv = pivots["dirs"]
            if dirs_piv.empty:
                result_frames["dirs"] = dirs_piv
            else:
                root_path = str(dirs_piv.index[0])
                parent_indices = [
                    _parent_index(str(p), dirs_piv.index, root_path, for_files=False)
                    for p in dirs_piv.index
                ]
                p1 = dirs_piv.reset_index(drop=True)
                p2 = dirs_piv.loc[parent_indices].reset_index(drop=True)
                if use_permission_hierarchy:
                    p1 = p1.apply(reduce_permission_hierarchy)
                    p2 = p2.apply(reduce_permission_hierarchy)
                delta = p1 - p2
                will_drop = [c for c in drop_cols if c in delta.columns]
                diff_mask = delta.drop(columns=will_drop).abs().sum(axis=1) > 0
                changed = dirs_piv.loc[diff_mask.to_numpy()].copy()
                root_row = dirs_piv.iloc[[0]]
                if root_path not in changed.index:
                    changed = pd.concat([root_row, changed])
                result_frames["dirs"] = changed

            if not skip_files_report and "files" in pivots:
                files_piv = pivots["files"]
                if files_piv.empty or dirs_piv.empty:
                    result_frames["files"] = pd.DataFrame()
                else:
                    root_path = str(dirs_piv.index[0])
                    parent_indices = [
                        _parent_index(str(idx[0]), dirs_piv.index, root_path, for_files=True)
                        for idx in files_piv.index
                    ]
                    p1 = files_piv.reset_index(drop=True)
                    p2 = dirs_piv.loc[parent_indices].reset_index(drop=True)
                    all_cols = p1.columns.union(p2.columns)
                    p1 = p1.reindex(columns=all_cols, fill_value=0)
                    p2 = p2.reindex(columns=all_cols, fill_value=0)
                    if use_permission_hierarchy:
                        p1 = p1.apply(reduce_permission_hierarchy)
                        p2 = p2.apply(reduce_permission_hierarchy)
                    delta_f = (p1 - p2).clip(lower=0)
                    if use_permission_hierarchy:
                        delta_f = delta_f.where(p2 < PERM_BIT_FULL, 0)
                    will_drop = [c for c in drop_cols if c in delta_f.columns]
                    elevated_mask = delta_f.drop(columns=will_drop).sum(axis=1) > 0
                    elevated = files_piv.loc[elevated_mask.to_numpy()].copy()
                    if not elevated.empty:
                        parent_dirs = sorted(
                            {
                                _parent_index(
                                    str(idx[0]), dirs_piv.index, root_path, for_files=True
                                )
                                for idx in elevated.index
                            }
                        )
                        to_add = dirs_piv.loc[parent_dirs].copy()
                        to_add.index = pd.MultiIndex.from_tuples(
                            [(p, "") for p in parent_dirs], names=["path", "fname"]
                        )
                        drop_parent = [c for c in drop_cols if c in to_add.columns]
                        to_add = to_add.drop(columns=drop_parent)
                        elevated = pd.concat([elevated, to_add]).fillna(0).astype("int64")
                    result_frames["files"] = elevated

        # Post-process: decode bitmasks, attach share permissions, flatten/melt
        latest_atime_date: datetime.date | None = None
        if add_latest_atime:
            latest_dt = self.get_latest_object_date("atime", table=tbl)
            if latest_dt is not None:
                latest_atime_date = latest_dt.date()

        share_lookup = (
            self.list_share_permissions(table=tbl, as_dictlookup=True)
            if sptable in self.tables
            else {}
        )

        for key, frame in list(result_frames.items()):
            if frame.empty:
                continue
            obj = frame.map(bitmask_to_code) if mapback else frame.copy()
            obj = obj.sort_index(axis=1, level=0, ascending=False).sort_index()

            if isinstance(share_lookup, dict) and share_lookup:
                obj = _attach_share_permissions(obj, share_lookup)

            if flatten_cols and isinstance(obj.columns, pd.MultiIndex):
                obj.columns = pd.Index(
                    [f"{d}\\{n}" for d, n in obj.columns], name="ACL domain\\name"
                )
                obj = obj.reset_index()

            if melt:
                obj = melt_parent_vs_child(obj)

            if latest_atime_date is not None:
                obj["fileshare_lastaccess"] = latest_atime_date

            result_frames[key] = obj

        dirs_out = result_frames.get("dirs")
        files_out = None if skip_files_report else result_frames.get("files")
        if files_out is not None and files_out.empty:
            files_out = None
        return ParentChildResult(dirs_df=dirs_out, files_df=files_out)

    def executive_summary(
        self,
        table: str | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> ExecutiveSummary:
        """Compute executive metadata, object counts, total bytes, ACLs, and owners.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        ExecutiveSummary
            Summary object with crawl metadata dict, ACL list, and owner list.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return ExecutiveSummary(info={})

        info = dict(self.crawl_options(table=tbl) or {})
        info.setdefault("table", tbl)
        if "path" not in info:
            roots = self.crawl_root(table=tbl)
            info["path"] = roots[0] if roots else ""

        info["Number of Directories"] = self.number_of_directories(
            table=tbl, owner=owner, subdir=subdir
        )
        info["Number of Files"] = self.number_of_files(table=tbl, owner=owner, subdir=subdir)
        info["total size"] = self.get_total_storage(table=tbl, owner=owner, subdir=subdir)

        acls_df = self.acls(table=tbl, subdir=subdir)
        acls_found = sorted(
            {
                f"{dom}\\{name}" if dom else str(name)
                for dom, name in zip(acls_df["Domain"], acls_df["Name"], strict=False)
            }
        )
        users_df = self.users(table=tbl, subdir=subdir)
        owners_found = sorted(str(u) for u in users_df["owner"].dropna().unique().tolist())

        return ExecutiveSummary(info=info, acls_found=acls_found, owners_found=owners_found)

    def compare_crawls(
        self,
        table1: str | None = None,
        table2: str | None = None,
        subdir: str | None = None,
    ) -> dict[str, pd.DataFrame]:
        """Compare two crawls for added/removed files, directories, and permission drift.

        Parameters
        ----------
        table1
            Earlier crawl table name (defaults to second-most-recent crawl).
        table2
            Later crawl table name (defaults to most-recent crawl).
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        dict[str, pandas.DataFrame]
            Mapping with keys ``"new_files"``, ``"removed_files"``, ``"new_directories"``,
            ``"removed_directories"``, and ``"permission_changes"``.
        """
        t1, t2 = self._resolve_two_tables(table1, table2)
        return {
            "new_files": self.new_files(table1=t1, table2=t2, subdir=subdir),
            "removed_files": self.removed_files(table1=t1, table2=t2, subdir=subdir),
            "new_directories": self.new_directories(table1=t1, table2=t2, subdir=subdir),
            "removed_directories": self.removed_directories(table1=t1, table2=t2, subdir=subdir),
            "permission_changes": self.find_permission_changes(table1=t1, table2=t2, subdir=subdir),
        }

    def find_permission_changes(
        self,
        table1: str | None = None,
        table2: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Identify directories whose effective permissions changed between two crawls.

        Parameters
        ----------
        table1
            Earlier crawl table name.
        table2
            Later crawl table name.
        subdir
            Optional subdirectory filter.

        Returns
        -------
        pandas.DataFrame
            Long-form DataFrame of paths and ACL principals whose permission code changed,
            with columns ``path``, ``Domain``, ``Name``, ``before``, ``after``.
        """
        t1, t2 = self._resolve_two_tables(table1, table2)
        pvc1 = self.parent_vs_child_report(
            table=t1, subdir=subdir, alldirs=True, skip_files_report=True, melt=True
        ).dirs_df
        pvc2 = self.parent_vs_child_report(
            table=t2, subdir=subdir, alldirs=True, skip_files_report=True, melt=True
        ).dirs_df

        cols = ["path", "Domain", "Name", "before", "after"]
        if pvc1 is None and pvc2 is None:
            return pd.DataFrame(columns=cols)
        df1 = (
            pvc1.rename(columns={"permission": "before"})
            if pvc1 is not None and not pvc1.empty
            else pd.DataFrame(columns=["path", "Domain", "Name", "before"])
        )
        df2 = (
            pvc2.rename(columns={"permission": "after"})
            if pvc2 is not None and not pvc2.empty
            else pd.DataFrame(columns=["path", "Domain", "Name", "after"])
        )
        merged = pd.merge(df1, df2, on=["path", "Domain", "Name"], how="outer")
        merged["before"] = merged["before"].fillna("")
        merged["after"] = merged["after"].fillna("")
        changed = merged[merged["before"] != merged["after"]].sort_values(
            ["path", "Domain", "Name"]
        )
        return changed.reset_index(drop=True)

    def crawl_acls(self, table: str | None = None) -> pd.DataFrame | None:
        """Query Active Directory for group membership of all ACLs in *table*.

        Stores harvested membership rows into ``<table_name>_m``. On non-Windows
        platforms, returns ``None`` cleanly without error.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).

        Returns
        -------
        pandas.DataFrame or None
            Harvested membership DataFrame if any members were resolved, else ``None``.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return None

        acls_df = self.acls(table=tbl)
        if acls_df.empty:
            return None

        groups = acls_df[acls_df["ObjectType"].isin(["Group", "Alias"])]
        if groups.empty:
            return None

        frames: list[pd.DataFrame] = []
        scan_date = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        for row in groups.itertuples(index=False):
            dom = str(row.Domain or "")
            name = str(row.Name or "")
            otype = str(row.ObjectType or "Group")
            if not dom or not name:
                continue
            members = get_group_membership(
                domain=dom, group=name, acl_type=otype, scan_date=scan_date
            )
            if not members.empty:
                frames.append(members)

        if not frames:
            return None

        combined = pd.concat(frames, ignore_index=True).drop_duplicates()
        combined.to_sql(
            f"{tbl}{MEMBER_TABLE_SUFFIX}", self.engine, if_exists="replace", index=False
        )
        return combined

    def summarize_acls(
        self,
        table: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame | None:
        """Return Active Directory ACL group membership stored for *table*.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        subdir
            Optional subdirectory prefix to filter relevant ACLs.

        Returns
        -------
        pandas.DataFrame or None
            Group membership DataFrame, or ``None`` if no membership table exists.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return None
        mtable = f"{tbl}{MEMBER_TABLE_SUFFIX}"
        if mtable not in self.tables:
            return None
        df = pd.read_sql_table(mtable, self.engine)
        if subdir is not None and not df.empty:
            acls_sub = self.acls(table=tbl, subdir=subdir)
            if not acls_sub.empty and {"Domain", "Name"}.issubset(acls_sub.columns):
                pairs = set(
                    zip(acls_sub["Domain"].astype(str), acls_sub["Name"].astype(str), strict=False)
                )
                mask = [
                    (str(d), str(a)) in pairs
                    for d, a in zip(df["Domain"].astype(str), df["ACL"].astype(str), strict=False)
                ]
                df = df.loc[mask].reset_index(drop=True)
        return df

    # -- Properties & supporting query methods (alphabetical) ---------------

    def acls(self, table: str | None = None, subdir: str | None = None) -> pd.DataFrame:
        """List distinct ACL principals discovered in *table*.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            DataFrame with columns ``Domain``, ``Name``, ``ObjectType``.
        """
        tbl = self._resolve_table(table)
        if tbl is None or f"{tbl}{PERM_TABLE_SUFFIX}" not in self.tables:
            return pd.DataFrame(columns=["Domain", "Name", "ObjectType"])

        ptable = f"{tbl}{PERM_TABLE_SUFFIX}"
        where_sql, params = _build_where(subdir=subdir, table_alias="A")
        qry = (
            f"SELECT DISTINCT ifnull(B.Domain, '') AS Domain, B.Name, B.ObjectType "
            f"FROM [{tbl}] A INNER JOIN [{ptable}] B ON A.Id = B.Id {where_sql} "
            f"ORDER BY Domain, B.Name"
        )
        return pd.read_sql_query(text(qry), self.engine, params=params)

    @property
    def all_crawls(self) -> list[str]:
        """Return sorted list of crawl table names in this database."""
        return self.crawls

    def count_where_acl_is_applied(
        self,
        acl_names: Sequence[str],
        table: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Count crawled objects where each ACL in *acl_names* is applied.

        Parameters
        ----------
        acl_names
            Account or group names to count.
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        subdir
            Optional subdirectory filter.

        Returns
        -------
        pandas.DataFrame
            DataFrame with columns ``Name`` and ``N``.
        """
        tbl = self._resolve_table(table)
        if tbl is None or f"{tbl}{PERM_TABLE_SUFFIX}" not in self.tables or not acl_names:
            return pd.DataFrame(columns=["Name", "N"])

        ptable = f"{tbl}{PERM_TABLE_SUFFIX}"
        placeholders = ", ".join(f":acl_{i}" for i in range(len(acl_names)))
        params: dict[str, Any] = {f"acl_{i}": name.lower() for i, name in enumerate(acl_names)}
        extra_where, sub_params = _build_where(subdir=subdir, table_alias="A", leading_and=True)
        params.update(sub_params)
        qry = (
            f"SELECT B.Name, COUNT(DISTINCT A.Id) AS N "
            f"FROM [{tbl}] A INNER JOIN [{ptable}] B ON A.Id = B.Id "
            f"WHERE LOWER(B.Name) IN ({placeholders}) {extra_where} "
            f"GROUP BY B.Name ORDER BY N DESC"
        )
        return pd.read_sql_query(text(qry), self.engine, params=params)

    def crawl(
        self,
        table: str | None = None,
        limit: int | None = None,
    ) -> pd.DataFrame:
        """Return the raw crawl metadata table as a DataFrame.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Optional maximum row limit.

        Returns
        -------
        pandas.DataFrame
            Crawl rows with columns ``Id``, ``path``, ``fname``, ``bytes``, ``owner``,
            ``ctime``, ``atime``, ``mtime``, ``md5``.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame()
        limit_sql = f" LIMIT {int(limit)}" if limit and limit > 0 else ""
        return pd.read_sql_query(f"SELECT * FROM [{tbl}]{limit_sql}", self.engine)

    def crawl_options(self, table: str | None = None) -> dict[str, Any] | None:
        """Return the recorded ``CRAWL_INFO`` metadata dictionary for *table*.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).

        Returns
        -------
        dict[str, Any] or None
            Metadata record, or ``None`` if ``CRAWL_INFO`` is absent.
        """
        tbl = self._resolve_table(table)
        if tbl is None or CRAWL_INFO_TABLE not in self.tables:
            return None
        df = pd.read_sql_query(
            text(f"SELECT * FROM [{CRAWL_INFO_TABLE}] WHERE [table] = :tbl"),
            self.engine,
            params={"tbl": tbl},
        )
        if df.empty:
            return None
        record = dict(df.iloc[-1].to_dict())
        for bool_col in (
            "scan_files",
            "scan_directories",
            "scan_permissions",
            "skip_size",
            "detect_pii_content",
        ):
            if bool_col in record and pd.notna(record[bool_col]):
                record[bool_col] = bool(record[bool_col])
        return record

    def crawl_root(self, table: str | None = None) -> list[str]:
        """Return the root path(s) crawled in *table*.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).

        Returns
        -------
        list[str]
            Single-element list containing the crawl root path (empty if unavailable).
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return []
        opts = self.crawl_options(table=tbl)
        if opts and opts.get("path"):
            return [str(opts["path"])]
        df = pd.read_sql_query(
            f"SELECT path FROM [{tbl}] ORDER BY LENGTH(path) ASC LIMIT 1",
            self.engine,
        )
        return [str(df.iloc[0]["path"])] if not df.empty else []

    @property
    def crawls(self) -> list[str]:
        """Return sorted list of primary crawl table names stored in this database."""
        return sorted(
            t
            for t in self.tables
            if t != CRAWL_INFO_TABLE
            and t not in DASHBOARD_TABLES
            and not t.startswith("sqlite_")
            and not any(t.endswith(sfx) for sfx in AUXILIARY_TABLE_SUFFIXES)
        )

    def find_backups(
        self,
        obj: str = "fname",
        table: str | None = None,
        limit: int | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Detect probable backup files or directories via filename/path regex heuristics.

        Parameters
        ----------
        obj
            Column to match against: ``"fname"`` (files) or ``"path"`` (directories).
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Optional maximum rows returned.
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Matching rows ordered by size descending.
        """
        if obj not in ("fname", "path"):
            raise ValueError("obj must be 'fname' or 'path'.")
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame()
        df = self._filtered_table(tbl, owner=owner, subdir=subdir)
        if df.empty:
            return df
        if obj == "fname":
            df = df[df["fname"].notna()]
            if df.empty:
                return df.reset_index(drop=True)
            mask = df["fname"].astype(str).apply(_is_backup_name)
        else:
            df = df[df["fname"].isna()]
            if df.empty:
                return df.reset_index(drop=True)
            mask = df["path"].astype(str).apply(_is_backup_name)
        matched = df[mask].sort_values("bytes", ascending=False)
        if limit and limit > 0:
            matched = matched.head(limit)
        return matched.reset_index(drop=True)

    def find_children_permissions_diffs(
        self,
        table: str | None = None,
        subdir: str | None = None,
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        """Return ``(added_perms_df, dropped_perms_df)`` comparing children to parent folders.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        tuple[pandas.DataFrame, pandas.DataFrame]
            Two DataFrames detailing permissions added and dropped at child folders.
        """
        pvc = self.parent_vs_child_report(
            table=table, subdir=subdir, alldirs=True, skip_files_report=True, mapback=False
        ).dirs_df
        empty = pd.DataFrame(columns=["path", "Domain", "Name", "delta"])
        if pvc is None or pvc.empty:
            return empty, empty.copy()

        root_path = str(pvc.index[0])
        parent_indices = [
            _parent_index(str(p), pvc.index, root_path, for_files=False) for p in pvc.index
        ]
        delta = pvc.reset_index(drop=True) - pvc.loc[parent_indices].reset_index(drop=True)
        delta.index = pvc.index

        added_rows: list[dict[str, Any]] = []
        dropped_rows: list[dict[str, Any]] = []
        for path_val, row in delta.iterrows():
            for (dom, name), val in row.items():
                if val > 0:
                    added_rows.append(
                        {"path": path_val, "Domain": dom, "Name": name, "delta": int(val)}
                    )
                elif val < 0:
                    dropped_rows.append(
                        {"path": path_val, "Domain": dom, "Name": name, "delta": int(val)}
                    )
        return (
            pd.DataFrame.from_records(added_rows) if added_rows else empty,
            pd.DataFrame.from_records(dropped_rows) if dropped_rows else empty.copy(),
        )

    def find_duplicate_files(
        self,
        table: str | None = None,
        minsize: int = 1,
        limit: int | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Identify potential duplicate files sharing the same filename and byte size.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        minsize
            Minimum file size in bytes.
        limit
            Optional maximum rows returned.
        owner
            Optional owner filter.
        subdir
            Optional subdirectory filter.

        Returns
        -------
        pandas.DataFrame
            Duplicate candidate files ordered by size descending.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame()
        df = self._filtered_table(tbl, owner=owner, subdir=subdir)
        if df.empty:
            return df
        files = df[(df["fname"].notna()) & (df["bytes"] >= minsize)]
        dup_mask = files.duplicated(subset=["fname", "bytes"], keep=False)
        dups = files[dup_mask].sort_values(["bytes", "fname"], ascending=[False, True])
        if limit and limit > 0:
            dups = dups.head(limit)
        return dups.reset_index(drop=True)

    def find_duplicate_md5(
        self,
        table: str | None = None,
        minsize: int = 1,
        limit: int | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Identify exact duplicate files or directories sharing identical MD5 digests.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        minsize
            Minimum size in bytes.
        limit
            Optional maximum rows returned.
        owner
            Optional owner filter.
        subdir
            Optional subdirectory filter.

        Returns
        -------
        pandas.DataFrame
            Duplicate rows sharing non-empty MD5 checksums, ordered by size descending.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame()
        df = self._filtered_table(tbl, owner=owner, subdir=subdir)
        if df.empty:
            return df
        hashed = df[df["md5"].notna() & (df["md5"].astype(str) != "") & (df["bytes"] >= minsize)]
        dup_mask = hashed.duplicated(subset=["md5"], keep=False)
        dups = hashed[dup_mask].sort_values(["bytes", "md5"], ascending=[False, True])
        if limit and limit > 0:
            dups = dups.head(limit)
        return dups.reset_index(drop=True)

    def find_file_age_distribution(
        self,
        table: str | None = None,
        limit: int | None = None,
        owner: str | None = None,
        subdir: str | None = None,
        time_col: str = "atime",
    ) -> pd.DataFrame:
        """Build a per-directory histogram of file counts grouped by access/modified year.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Optional maximum number of directories returned.
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.
        time_col
            Timestamp column to bin (``"atime"``, ``"mtime"``, or ``"ctime"``).

        Returns
        -------
        pandas.DataFrame
            Pivot table indexed by ``path`` with integer year columns.
        """
        if time_col not in ("atime", "mtime", "ctime"):
            raise ValueError("time_col must be one of 'atime', 'mtime', 'ctime'.")
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame()
        df = self._filtered_table(tbl, owner=owner, subdir=subdir)
        if df.empty:
            return pd.DataFrame()
        work = df.copy()
        work["_year"] = pd.to_datetime(work[time_col], errors="coerce").dt.year
        work = work.dropna(subset=["_year"])
        if work.empty:
            return pd.DataFrame()
        work["_year"] = work["_year"].astype(int)
        piv = work.pivot_table(
            index="path", columns="_year", values="Id", aggfunc="count", fill_value=0
        )
        piv = piv.reindex(sorted(piv.columns), axis=1)
        piv = piv.sort_values(by=list(piv.columns), ascending=False)
        if limit and limit > 0:
            piv = piv.head(limit)
        return piv

    def find_longest_path(self, table: str | None = None, limit: int = 20) -> pd.DataFrame:
        """Return the longest full file/directory paths discovered in *table*.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Maximum number of paths returned.

        Returns
        -------
        pandas.DataFrame
            DataFrame with ``full_path`` and ``length`` ordered descending.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame(columns=["full_path", "length"])
        df = pd.read_sql_query(f"SELECT path, fname FROM [{tbl}]", self.engine)
        if df.empty:
            return pd.DataFrame(columns=["full_path", "length"])
        full = [
            os.path.join(str(p), str(f)) if pd.notna(f) and f else str(p)
            for p, f in zip(df["path"], df["fname"], strict=False)
        ]
        out = pd.DataFrame({"full_path": full})
        out["length"] = out["full_path"].str.len()
        return out.sort_values("length", ascending=False).head(limit).reset_index(drop=True)

    def find_objects_owned_by_dead_sids(
        self,
        table: str | None = None,
        limit: int | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Return files and folders owned by unresolved/deleted SIDs (``Dead*`` or ``S-1-5*``).

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Optional maximum rows returned.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Matching objects with dead SID ownership.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame()
        df = self._filtered_table(tbl, subdir=subdir)
        if df.empty:
            return df
        owners = df["owner"].fillna("").astype(str)
        mask = owners.str.startswith("Dead") | owners.str.startswith("S-1-5")
        out = df[mask]
        if limit and limit > 0:
            out = out.head(limit)
        return out.reset_index(drop=True)

    def find_objects_with_user_access(
        self,
        table: str | None = None,
        limit: int | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Return folders with direct ``User``-account ACL grants (instead of group-based ACLs).

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Optional maximum rows returned.
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Directories with direct user-level ACL entries.
        """
        tbl = self._resolve_table(table)
        if tbl is None or f"{tbl}{PERM_TABLE_SUFFIX}" not in self.tables:
            return pd.DataFrame()
        ptable = f"{tbl}{PERM_TABLE_SUFFIX}"
        where_sql, params = _build_where(
            owner=owner, subdir=subdir, table_alias="A", leading_and=True
        )
        limit_sql = f" LIMIT {int(limit)}" if limit and limit > 0 else ""
        qry = (
            f"SELECT A.path, A.owner, A.bytes, B.Domain, B.Name, B.Permission, B.ObjectType "
            f"FROM [{tbl}] A INNER JOIN [{ptable}] B ON A.Id = B.Id "
            f"WHERE A.fname IS NULL AND B.ObjectType = 'User' {where_sql} "
            f"ORDER BY A.path{limit_sql}"
        )
        return pd.read_sql_query(text(qry), self.engine, params=params)

    def find_open_access(
        self,
        table: str | None = None,
        subdir: str | None = None,
        open_accounts: Sequence[str] = BUILTIN_OPEN_ACCOUNTS,
        skip_files_report: bool = False,
    ) -> ParentChildResult:
        """Return a parent-vs-child ACL diff restricted to broad/builtin open accounts.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        subdir
            Optional subdirectory prefix filter.
        open_accounts
            Account names considered overly broad (defaults to :data:`~lanspector.constants.BUILTIN_OPEN_ACCOUNTS`).
        skip_files_report
            Omit file-vs-folder report when ``True``.

        Returns
        -------
        ParentChildResult
            Parent-vs-child report filtered to *open_accounts*.
        """
        return self.parent_vs_child_report(
            table=table,
            subdir=subdir,
            restrict_to=list(open_accounts),
            skip_files_report=skip_files_report,
        )

    def find_pii_by_content(
        self,
        table: str | None = None,
        limit: int | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Return files/directories with content-level PII hits harvested during crawling.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Optional maximum rows returned.
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            DataFrame with ``path``, ``fname``, ``owner``, ``keyword``, and ``snippet``.
        """
        tbl = self._resolve_table(table)
        pii_table = f"{tbl}{PII_TABLE_SUFFIX}" if tbl else ""
        words_table = f"{tbl}{PII_WORDS_TABLE_SUFFIX}" if tbl else ""
        if tbl is None or pii_table not in self.tables or words_table not in self.tables:
            return pd.DataFrame(columns=["path", "fname", "owner", "keyword", "snippet"])

        where_sql, params = _build_where(owner=owner, subdir=subdir, table_alias="A")
        limit_sql = f" LIMIT {int(limit)}" if limit and limit > 0 else ""
        qry = (
            f"SELECT A.path, A.fname, A.owner, W.keyword, P.snippet "
            f"FROM [{tbl}] A "
            f"INNER JOIN [{pii_table}] P ON A.Id = P.Id "
            f"INNER JOIN [{words_table}] W ON P.pii_wordId = W.pii_wordId "
            f"{where_sql} ORDER BY A.path, A.fname{limit_sql}"
        )
        return pd.read_sql_query(text(qry), self.engine, params=params)

    def find_pii_by_name(
        self,
        obj: str = "fname",
        table: str | None = None,
        limit: int | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Return files or directories whose path/name matches PII keyword heuristics.

        Parameters
        ----------
        obj
            Target scope: ``"fname"`` (files) or ``"path"`` (directories).
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Optional maximum rows returned.
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Matching objects with a ``PII_rank`` score ordered descending.
        """
        if obj not in ("fname", "path"):
            raise ValueError("obj must be 'fname' or 'path'.")
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame()
        df = self._filtered_table(tbl, owner=owner, subdir=subdir)
        if df.empty:
            return df
        sub = df[df["fname"].notna()].copy() if obj == "fname" else df[df["fname"].isna()].copy()
        if sub.empty:
            return sub
        sub["PII_rank"] = [
            count_pii_name_matches(str(p or ""), str(f or "") if pd.notna(f) else "")
            for p, f in zip(sub["path"], sub["fname"], strict=False)
        ]
        matched = sub[sub["PII_rank"] > 0].sort_values(
            ["PII_rank", "path"], ascending=[False, True]
        )
        if limit and limit > 0:
            matched = matched.head(limit)
        return matched.reset_index(drop=True)

    def find_users_files(
        self,
        user: str,
        table: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Return all crawled files and directories owned by *user*.

        Parameters
        ----------
        user
            Owner account name (case-insensitive).
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Rows owned by *user*.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame()
        return self._filtered_table(tbl, owner=user, subdir=subdir)

    def find_when_permissions_changed(
        self,
        subdir: str | None = None,
        mindate: str | datetime.datetime | None = None,
        maxdate: str | datetime.datetime | None = None,
    ) -> pd.DataFrame:
        """Scan all chronological crawls in this database and report every permission change.

        Parameters
        ----------
        subdir
            Optional subdirectory prefix filter.
        mindate
            Optional inclusive lower bound timestamp/date.
        maxdate
            Optional inclusive upper bound timestamp/date.

        Returns
        -------
        pandas.DataFrame
            Concatenated permission drift records with ``from_crawl`` and ``to_crawl`` columns.
        """
        crawls = self.crawls
        if mindate is not None:
            min_dt = _parse_date_bound(mindate)
            crawls = [c for c in crawls if (dt := _table_to_dt(c)) is None or dt >= min_dt]
        if maxdate is not None:
            max_dt = _parse_date_bound(maxdate)
            crawls = [c for c in crawls if (dt := _table_to_dt(c)) is None or dt <= max_dt]

        if len(crawls) < 2:
            return pd.DataFrame(
                columns=["from_crawl", "to_crawl", "path", "Domain", "Name", "before", "after"]
            )

        changes: list[pd.DataFrame] = []
        for prev_t, curr_t in itertools.pairwise(crawls):
            diff = self.find_permission_changes(table1=prev_t, table2=curr_t, subdir=subdir)
            if not diff.empty:
                diff.insert(0, "to_crawl", curr_t)
                diff.insert(0, "from_crawl", prev_t)
                changes.append(diff)

        if not changes:
            return pd.DataFrame(
                columns=["from_crawl", "to_crawl", "path", "Domain", "Name", "before", "after"]
            )
        return pd.concat(changes, ignore_index=True)

    def find_where_access_is_denied(
        self,
        table: str | None = None,
        subdir: str | None = None,
        dirs_only: bool = True,
    ) -> pd.DataFrame:
        """Return paths that could not be traversed because access was denied.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        subdir
            Optional subdirectory prefix filter.
        dirs_only
            Restrict results to directories when ``True``.

        Returns
        -------
        pandas.DataFrame
            Entries whose ``owner`` was recorded as ``"AccessDenied"``.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame()
        df = self._filtered_table(tbl, owner="AccessDenied", subdir=subdir)
        if dirs_only and not df.empty:
            df = df[df["fname"].isna()]
        return df.reset_index(drop=True)

    def find_where_acl_is_applied(
        self,
        acl_name: str,
        table: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Return all crawled objects granting permissions to *acl_name*.

        Parameters
        ----------
        acl_name
            Account or group name (case-insensitive).
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Matching object and permission rows.
        """
        tbl = self._resolve_table(table)
        if tbl is None or f"{tbl}{PERM_TABLE_SUFFIX}" not in self.tables:
            return pd.DataFrame()
        ptable = f"{tbl}{PERM_TABLE_SUFFIX}"
        extra_where, params = _build_where(subdir=subdir, table_alias="A", leading_and=True)
        params["acl_name"] = acl_name.lower()
        qry = (
            f"SELECT A.path, A.fname, A.owner, B.Domain, B.Name, B.Permission, B.ObjectType "
            f"FROM [{tbl}] A INNER JOIN [{ptable}] B ON A.Id = B.Id "
            f"WHERE LOWER(B.Name) = :acl_name {extra_where} ORDER BY A.path, A.fname"
        )
        return pd.read_sql_query(text(qry), self.engine, params=params)

    def find_where_acl_is_not_applied(
        self,
        acl_name: str,
        table: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Return directories that do *not* grant any permission to *acl_name*.

        Parameters
        ----------
        acl_name
            Account or group name (case-insensitive).
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            DataFrame with ``path`` column listing directories without *acl_name*.
        """
        all_dirs = self.list_of_directories(table=table, subdir=subdir)
        if all_dirs.empty:
            return all_dirs
        applied = self.find_where_acl_is_applied(acl_name, table=table, subdir=subdir)
        if applied.empty:
            return all_dirs
        applied_paths = set(applied["path"].astype(str))
        return all_dirs[~all_dirs["path"].astype(str).isin(applied_paths)].reset_index(drop=True)

    def find_where_user_has_access(
        self,
        username: str,
        table: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Find directories/files accessible to *username* directly or via AD group membership.

        Parameters
        ----------
        username
            User logon or account name.
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Accessible objects and the matching principal/permission.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame()
        principals = {username.lower()}
        members_df = self.summarize_acls(table=tbl, subdir=subdir)
        if members_df is not None and not members_df.empty and "member.logon" in members_df.columns:
            hits = members_df[
                members_df["member.logon"]
                .astype(str)
                .str.lower()
                .str.contains(re.escape(username.lower()))
            ]
            principals.update(hits["ACL"].astype(str).str.lower().tolist())

        frames = [
            self.find_where_acl_is_applied(p, table=tbl, subdir=subdir) for p in sorted(principals)
        ]
        non_empty = [f for f in frames if not f.empty]
        if not non_empty:
            return pd.DataFrame(
                columns=["path", "fname", "owner", "Domain", "Name", "Permission", "ObjectType"]
            )
        return pd.concat(non_empty, ignore_index=True).drop_duplicates().reset_index(drop=True)

    def get_latest_object_date(
        self,
        time_col: str = "atime",
        table: str | None = None,
    ) -> datetime.datetime | None:
        """Return the most recent timestamp in *time_col* across *table*.

        Parameters
        ----------
        time_col
            Timestamp column name (``"atime"``, ``"mtime"``, or ``"ctime"``).
        table
            Crawl table name (defaults to :attr:`latest_crawl`).

        Returns
        -------
        datetime.datetime or None
            Most recent parsed timestamp, or ``None`` if no valid timestamps exist.
        """
        if time_col not in ("atime", "mtime", "ctime"):
            raise ValueError("time_col must be one of 'atime', 'mtime', 'ctime'.")
        tbl = self._resolve_table(table)
        if tbl is None:
            return None
        with self.engine.connect() as conn:
            raw = conn.execute(text(f"SELECT MAX({time_col}) FROM [{tbl}]")).scalar()
        if raw is None:
            return None
        ts = pd.to_datetime(raw, errors="coerce")
        if pd.isna(ts):
            return None
        return ts.to_pydatetime()

    def get_storage_growth_rate(self) -> pd.DataFrame:
        """Calculate total storage bytes across all crawls stored in this database.

        Returns
        -------
        pandas.DataFrame
            DataFrame with ``crawl``, ``crawl_date``, ``bytes``, and ``delta_bytes``.
        """
        rows: list[dict[str, Any]] = []
        for tbl in self.crawls:
            rows.append(
                {
                    "crawl": tbl,
                    "crawl_date": _table_to_dt(tbl),
                    "bytes": self.get_total_storage(table=tbl),
                }
            )
        df = (
            pd.DataFrame.from_records(rows)
            if rows
            else pd.DataFrame(columns=["crawl", "crawl_date", "bytes"])
        )
        if not df.empty:
            df["delta_bytes"] = df["bytes"].diff().fillna(0).astype("int64")
        return df

    def get_total_storage(
        self,
        table: str | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> int:
        """Return total byte usage across *table* (avoiding double-counting dirs + files).

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        int
            Total size in bytes.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return 0
        has_files = self.number_of_files(table=tbl, owner=owner, subdir=subdir) > 0
        where_sql, params = _build_where(owner=owner, subdir=subdir)
        if has_files:
            clause = (
                f"{where_sql} AND fname IS NOT NULL" if where_sql else "WHERE fname IS NOT NULL"
            )
        else:
            clause = f"{where_sql} AND fname IS NULL" if where_sql else "WHERE fname IS NULL"
        with self.engine.connect() as conn:
            total = conn.execute(
                text(f"SELECT COALESCE(SUM(bytes), 0) FROM [{tbl}] {clause}"), params
            ).scalar()
        return int(total or 0)

    def head(self, n: int = 5, table: str | None = None) -> pd.DataFrame:
        """Return the first *n* rows of *table*.

        Parameters
        ----------
        n
            Number of rows to retrieve.
        table
            Crawl table name (defaults to :attr:`latest_crawl`).

        Returns
        -------
        pandas.DataFrame
            Leading rows from the crawl table.
        """
        return self.crawl(table=table, limit=n)

    def largest_directories(
        self,
        level: int = 1,
        table: str | None = None,
        limit: int | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Aggregate storage size by directory truncated to *level* levels below root.

        Parameters
        ----------
        level
            Directory depth below the crawl root to roll up to.
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Optional maximum rows returned.
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            DataFrame with ``path`` and ``size`` ordered by ``size`` descending.
        """
        sub_df = self.largest_subdirectories(table=table, owner=owner, subdir=subdir)
        if sub_df.empty:
            return pd.DataFrame(columns=["path", "size"])
        roots = self.crawl_root(table=table)
        root_parts = _split_path(roots[0]) if roots else []
        target_depth = len(root_parts) + max(0, level)

        def _truncate(p: str) -> str:
            parts = _split_path(p)
            sep = "\\" if "\\" in p and "/" not in p else os.sep
            prefix = sep if p.startswith(sep) else ""
            if p.startswith("\\\\"):
                prefix = "\\\\"
            return prefix + sep.join(parts[:target_depth])

        work = sub_df.copy()
        work["bucket"] = work["path"].astype(str).map(_truncate)
        grouped = (
            work.groupby("bucket", as_index=False)["size"].sum().rename(columns={"bucket": "path"})
        )
        grouped = grouped.sort_values("size", ascending=False)
        if limit and limit > 0:
            grouped = grouped.head(limit)
        return grouped.reset_index(drop=True)

    def largest_files(
        self,
        table: str | None = None,
        limit: int | None = 100,
        owner: str | None = None,
        subdir: str | None = None,
        strip_pathprefix: str | None = None,
    ) -> pd.DataFrame:
        """Return the largest files discovered in *table*.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Maximum number of files to return (``None`` or ``0`` for unlimited).
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.
        strip_pathprefix
            Optional path prefix to strip from ``path``.

        Returns
        -------
        pandas.DataFrame
            File rows sorted by ``bytes`` descending.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame()
        df = self._filtered_table(tbl, owner=owner, subdir=subdir)
        if df.empty:
            return df
        files = df[df["fname"].notna()].sort_values("bytes", ascending=False)
        if strip_pathprefix:
            prefix = _normalize_strip_prefix(strip_pathprefix)
            files = files.copy()
            files["path"] = files["path"].astype(str).str.replace(prefix, "", n=1, regex=False)
        if limit and limit > 0:
            files = files.head(limit)
        return files.reset_index(drop=True)

    def largest_subdirectories(
        self,
        table: str | None = None,
        limit: int | None = None,
        owner: str | None = None,
        subdir: str | None = None,
        max_atime: bool = False,
        strip_pathprefix: str | None = None,
    ) -> pd.DataFrame:
        """Aggregate immediate byte size (and optional latest ``atime``) per directory.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Optional maximum rows returned.
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.
        max_atime
            Include a ``max_atime`` column with the latest access timestamp per directory.
        strip_pathprefix
            Optional path prefix to strip from ``path``.

        Returns
        -------
        pandas.DataFrame
            DataFrame with ``path``, ``size``, and optionally ``max_atime``, sorted by size descending.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            cols = ["path", "size", "max_atime"] if max_atime else ["path", "size"]
            return pd.DataFrame(columns=cols)

        df = self._filtered_table(tbl, owner=owner, subdir=subdir)
        if df.empty:
            if subdir is not None:
                was_fqdn, alt_subdir = subdir_fqdn_to_hostname(subdir)
                if was_fqdn:
                    return self.largest_subdirectories(
                        table=tbl,
                        limit=limit,
                        owner=owner,
                        subdir=alt_subdir,
                        max_atime=max_atime,
                        strip_pathprefix=strip_pathprefix,
                    )
            cols = ["path", "size", "max_atime"] if max_atime else ["path", "size"]
            return pd.DataFrame(columns=cols)

        has_files = df["fname"].notna().any()
        work = df[df["fname"].notna()].copy() if has_files else df[df["fname"].isna()].copy()
        if work.empty:
            cols = ["path", "size", "max_atime"] if max_atime else ["path", "size"]
            return pd.DataFrame(columns=cols)

        if max_atime:
            work["atime"] = pd.to_datetime(work["atime"], errors="coerce")
            grouped = (
                work.groupby("path", as_index=False)
                .agg(size=("bytes", "sum"), max_atime=("atime", "max"))
                .sort_values("size", ascending=False)
            )
        else:
            grouped = (
                work.groupby("path", as_index=False)["bytes"]
                .sum()
                .rename(columns={"bytes": "size"})
                .sort_values("size", ascending=False)
            )

        if strip_pathprefix:
            prefix = _normalize_strip_prefix(strip_pathprefix)
            grouped["path"] = grouped["path"].astype(str).str.replace(prefix, "", n=1, regex=False)
        if limit and limit > 0:
            grouped = grouped.head(limit)
        return grouped.reset_index(drop=True)

    def largest_users(
        self,
        table: str | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Aggregate total storage size by file/directory owner.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            DataFrame with ``owner`` and ``bytes`` sorted descending.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame(columns=["owner", "bytes"])
        df = self._filtered_table(tbl, owner=owner, subdir=subdir)
        if df.empty:
            return pd.DataFrame(columns=["owner", "bytes"])
        has_files = df["fname"].notna().any()
        work = df[df["fname"].notna()] if has_files else df[df["fname"].isna()]
        if work.empty:
            return pd.DataFrame(columns=["owner", "bytes"])
        return (
            work.groupby("owner", as_index=False)["bytes"]
            .sum()
            .sort_values("bytes", ascending=False)
            .reset_index(drop=True)
        )

    @property
    def latest_crawl(self) -> str | None:
        """Return the most recent crawl table name, or ``None`` if database is empty."""
        crawls = self.crawls
        return crawls[-1] if crawls else None

    def list_of_crawls(self) -> pd.DataFrame:
        """Return the ``CRAWL_INFO`` table listing all recorded crawls.

        Returns
        -------
        pandas.DataFrame
            Crawl metadata table (synthesized from table names if ``CRAWL_INFO`` is absent).
        """
        if CRAWL_INFO_TABLE in self.tables:
            return pd.read_sql_table(CRAWL_INFO_TABLE, self.engine)
        return pd.DataFrame(
            {
                "table": self.crawls,
                "path": [self.crawl_root(t)[0] if self.crawl_root(t) else "" for t in self.crawls],
            }
        )

    def list_of_directories(
        self,
        subdir: str | None = None,
        owner: str | None = None,
        table: str | None = None,
    ) -> pd.DataFrame:
        """Return distinct directories discovered in *table*.

        Parameters
        ----------
        subdir
            Optional subdirectory prefix filter.
        owner
            Optional owner filter.
        table
            Crawl table name (defaults to :attr:`latest_crawl`).

        Returns
        -------
        pandas.DataFrame
            Single-column DataFrame with ``path`` sorted ascending.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame(columns=["path"])
        where_sql, params = _build_where(owner=owner, subdir=subdir)
        qry = f"SELECT DISTINCT path FROM [{tbl}] {where_sql} ORDER BY path"
        ret = pd.read_sql_query(text(qry), self.engine, params=params)
        if ret.empty and subdir is not None:
            was_fqdn, alt_subdir = subdir_fqdn_to_hostname(subdir)
            if was_fqdn:
                return self.list_of_directories(subdir=alt_subdir, owner=owner, table=tbl)
        return ret

    def list_open_share_properties(
        self,
        table: str | Sequence[str] | None = None,
        use_builtins: bool = True,
    ) -> pd.DataFrame | None:
        """Summarize share-level permissions, builtin NTFS exposure counts, and AD counts.

        Parameters
        ----------
        table
            Single crawl table name, list of table names, or ``None`` for all crawls.
        use_builtins
            Include :data:`~lanspector.constants.BUILTIN_OPEN_ACCOUNTS` NTFS counts.

        Returns
        -------
        pandas.DataFrame or None
            Multi-index column summary DataFrame, or ``None`` when no properties exist.
        """
        tables = (
            self.crawls if table is None else ([table] if isinstance(table, str) else list(table))
        )
        frames: list[pd.DataFrame] = []
        for tbl in tables:
            crawl_dt = _table_to_dt(tbl)
            sp = self.list_share_permissions(table=tbl, as_dictlookup=False)
            share_part: pd.DataFrame | None = None
            if isinstance(sp, pd.DataFrame) and not sp.empty:
                sp = sp.copy()
                sp["acl"] = (
                    sp["ACLDomain"].fillna("").astype(str) + "\\" + sp["ACLName"].astype(str)
                )
                piv = sp.pivot_table(
                    index=["server", "sharename"],
                    columns="acl",
                    values="permission",
                    aggfunc="first",
                ).reset_index()
                piv.insert(0, "Crawl Date", crawl_dt)
                piv.columns = pd.MultiIndex.from_tuples(
                    [("Share-Level", str(c)) for c in piv.columns],
                    names=["Source", "Quantity"],
                )
                share_part = piv

            ntfs_part: pd.DataFrame | None = None
            if use_builtins:
                counts = self.count_where_acl_is_applied(BUILTIN_OPEN_ACCOUNTS, table=tbl)
                if not counts.empty:
                    row_dict: dict[tuple[str, str], Any] = {
                        ("NTFS-Level", "Last Accessed"): self.get_latest_object_date(
                            "atime", table=tbl
                        )
                    }
                    for name, cnt in zip(counts["Name"], counts["N"], strict=False):
                        row_dict[("NTFS-Level", str(name))] = int(cnt)
                    ntfs_part = pd.DataFrame([row_dict])
                    ntfs_part.columns = pd.MultiIndex.from_tuples(
                        list(ntfs_part.columns), names=["Source", "Quantity"]
                    )

            ad_part: pd.DataFrame | None = None
            ad_df = self.summarize_acls(table=tbl)
            if (
                ad_df is not None
                and not ad_df.empty
                and {"Domain", "ACL", "member.logon"}.issubset(ad_df.columns)
            ):
                grouped = ad_df.groupby(["Domain", "ACL"], as_index=False).agg(
                    cnt=("member.logon", "count")
                )
                ad_dict = {
                    ("AD membership count", f"{rec['Domain']}\\{rec['ACL']}"): int(rec["cnt"])
                    for rec in grouped.to_dict("records")
                }
                ad_part = pd.DataFrame([ad_dict])
                ad_part.columns = pd.MultiIndex.from_tuples(
                    list(ad_part.columns), names=["Source", "Quantity"]
                )

            parts = [p for p in (share_part, ntfs_part, ad_part) if p is not None]
            if parts:
                frames.append(pd.concat(parts, axis=1))

        if not frames:
            return None
        return pd.concat(frames, ignore_index=True)

    def list_share_permissions(
        self,
        table: str | None = None,
        as_dictlookup: bool = False,
    ) -> pd.DataFrame | dict[str, pd.DataFrame]:
        """Return SMB share-level permissions stored in ``<table>_sp``.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        as_dictlookup
            When ``True``, return a dict mapping lowercase UNC root (``\\\\server\\share``)
            to a 1-row MultiIndex permission DataFrame.

        Returns
        -------
        pandas.DataFrame or dict[str, pandas.DataFrame]
            Raw share permissions DataFrame or UNC lookup dictionary.
        """
        tbl = self._resolve_table(table)
        sptable = f"{tbl}{SHARE_PERM_TABLE_SUFFIX}" if tbl else ""
        if tbl is None or sptable not in self.tables:
            return {} if as_dictlookup else pd.DataFrame()
        df = pd.read_sql_table(sptable, self.engine)
        if not as_dictlookup:
            return df
        if df.empty:
            return {}
        lookup: dict[str, pd.DataFrame] = {}
        for grp_key, grp in df.groupby(["server", "sharename"]):
            server, sharename = grp_key if isinstance(grp_key, tuple) else (str(grp_key), "")
            records = grp.to_dict("records")
            cols = [
                (f"Share-Level: {rec.get('ACLDomain') or 'BUILTIN'}", str(rec["ACLName"]))
                for rec in records
            ]
            vals = [
                bitmask_to_code(ntfs_to_bitmask(rec["permission"])) or str(rec["permission"])
                for rec in records
            ]
            one_row = pd.DataFrame(
                [vals], columns=pd.MultiIndex.from_tuples(cols, names=["Domain", "Name"])
            )
            lookup[f"\\\\{server}\\{sharename}".lower()] = one_row
        return lookup

    def nearest_crawl_to_date(
        self,
        date: str | datetime.date | datetime.datetime,
        max_delta: int | None = None,
    ) -> str | None:
        """Find the crawl table name closest to *date*.

        Parameters
        ----------
        date
            Target date (``YYYY-MM-DD`` string, :class:`datetime.date`, or :class:`datetime.datetime`).
        max_delta
            Optional maximum distance in days.

        Returns
        -------
        str or None
            Closest matching crawl table name, or ``None`` if none fall within *max_delta*.
        """
        return nearest_crawl_to_date(self.crawls, date=date, max_delta=max_delta)

    def new_directories(
        self,
        table1: str | None = None,
        table2: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Return directories present in *table2* that were absent in *table1*.

        Parameters
        ----------
        table1
            Earlier crawl table name.
        table2
            Later crawl table name.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Newly added directories.
        """
        t1, t2 = self._resolve_two_tables(table1, table2)
        d1 = set(self.list_of_directories(table=t1, subdir=subdir)["path"].astype(str))
        df2 = self._filtered_table(t2, subdir=subdir)
        dirs2 = df2[df2["fname"].isna()]
        return dirs2[~dirs2["path"].astype(str).isin(d1)].reset_index(drop=True)

    def new_files(
        self,
        table1: str | None = None,
        table2: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Return files present in *table2* that were absent in *table1*.

        Parameters
        ----------
        table1
            Earlier crawl table name.
        table2
            Later crawl table name.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Newly added files.
        """
        t1, t2 = self._resolve_two_tables(table1, table2)
        df1 = self._filtered_table(t1, subdir=subdir)
        df2 = self._filtered_table(t2, subdir=subdir)
        f1 = df1[df1["fname"].notna()]
        f2 = df2[df2["fname"].notna()]
        keys1 = set(zip(f1["path"].astype(str), f1["fname"].astype(str), strict=False))
        mask = [
            (str(p), str(f)) not in keys1 for p, f in zip(f2["path"], f2["fname"], strict=False)
        ]
        return f2.loc[mask].reset_index(drop=True)

    def number_of_directories(
        self,
        table: str | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> int:
        """Return count of crawled directories in *table*.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        int
            Number of directory entries.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return 0
        where_sql, params = _build_where(owner=owner, subdir=subdir)
        clause = f"{where_sql} AND fname IS NULL" if where_sql else "WHERE fname IS NULL"
        with self.engine.connect() as conn:
            val = conn.execute(text(f"SELECT COUNT(Id) FROM [{tbl}] {clause}"), params).scalar()
        return int(val or 0)

    def number_of_entitlements(self, table: str | None = None) -> int:
        """Return total permission entries stored in ``<table>_p``.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).

        Returns
        -------
        int
            Total count of entitlement rows.
        """
        tbl = self._resolve_table(table)
        if tbl is None or f"{tbl}{PERM_TABLE_SUFFIX}" not in self.tables:
            return 0
        with self.engine.connect() as conn:
            val = conn.execute(text(f"SELECT COUNT(*) FROM [{tbl}{PERM_TABLE_SUFFIX}]")).scalar()
        return int(val or 0)

    def number_of_files(
        self,
        table: str | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> int:
        """Return count of crawled files in *table*.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        int
            Number of file entries.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return 0
        where_sql, params = _build_where(owner=owner, subdir=subdir)
        clause = f"{where_sql} AND fname IS NOT NULL" if where_sql else "WHERE fname IS NOT NULL"
        with self.engine.connect() as conn:
            val = conn.execute(text(f"SELECT COUNT(Id) FROM [{tbl}] {clause}"), params).scalar()
        return int(val or 0)

    def number_of_objects(
        self,
        table: str | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> int:
        """Return total count of crawled directories and files in *table*.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        int
            Total crawled object count.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return 0
        where_sql, params = _build_where(owner=owner, subdir=subdir)
        with self.engine.connect() as conn:
            val = conn.execute(text(f"SELECT COUNT(Id) FROM [{tbl}] {where_sql}"), params).scalar()
        return int(val or 0)

    def oldest_entries(
        self,
        table: str | None = None,
        limit: int | None = 100,
        owner: str | None = None,
        subdir: str | None = None,
        time_col: str = "atime",
    ) -> pd.DataFrame:
        """Return crawled objects ordered oldest-first by *time_col*.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Maximum number of entries to return.
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.
        time_col
            Timestamp column to sort by (``"atime"``, ``"mtime"``, or ``"ctime"``).

        Returns
        -------
        pandas.DataFrame
            Oldest objects DataFrame.
        """
        if time_col not in ("atime", "mtime", "ctime"):
            raise ValueError("time_col must be one of 'atime', 'mtime', 'ctime'.")
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame()
        df = self._filtered_table(tbl, owner=owner, subdir=subdir)
        if df.empty:
            return df
        work = df.copy()
        work["_sort_ts"] = pd.to_datetime(work[time_col], errors="coerce")
        work = (
            work.dropna(subset=["_sort_ts"])
            .sort_values("_sort_ts", ascending=True)
            .drop(columns=["_sort_ts"])
        )
        if limit and limit > 0:
            work = work.head(limit)
        return work.reset_index(drop=True)

    def remove_crawl(self, table: str) -> None:
        """Drop *table* and its associated permission/PII/membership tables from SQLite.

        Parameters
        ----------
        table
            Crawl table name to remove.
        """
        existing = set(self.tables)
        to_drop = [table, *(f"{table}{sfx}" for sfx in AUXILIARY_TABLE_SUFFIXES)]
        with self.engine.begin() as conn:
            for name in to_drop:
                if name in existing:
                    conn.execute(text(f"DROP TABLE IF EXISTS [{name}]"))
            if CRAWL_INFO_TABLE in existing:
                conn.execute(
                    text(f"DELETE FROM [{CRAWL_INFO_TABLE}] WHERE [table] = :tbl"),
                    {"tbl": table},
                )

    def removed_directories(
        self,
        table1: str | None = None,
        table2: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Return directories present in *table1* that are missing from *table2*.

        Parameters
        ----------
        table1
            Earlier crawl table name.
        table2
            Later crawl table name.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Removed directories.
        """
        t1, t2 = self._resolve_two_tables(table1, table2)
        return self.new_directories(table1=t2, table2=t1, subdir=subdir)

    def removed_files(
        self,
        table1: str | None = None,
        table2: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Return files present in *table1* that are missing from *table2*.

        Parameters
        ----------
        table1
            Earlier crawl table name.
        table2
            Later crawl table name.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Removed files.
        """
        t1, t2 = self._resolve_two_tables(table1, table2)
        return self.new_files(table1=t2, table2=t1, subdir=subdir)

    def return_crawl_with_permissions(
        self,
        table: str | None = None,
        limit: int | None = None,
    ) -> pd.DataFrame:
        """Return crawled objects joined with their effective permissions.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        limit
            Optional maximum rows returned.

        Returns
        -------
        pandas.DataFrame
            Joined table with ``path``, ``fname``, ``owner``, ``Domain``, ``Name``,
            ``Permission``, ``ObjectType``.
        """
        tbl = self._resolve_table(table)
        if tbl is None or f"{tbl}{PERM_TABLE_SUFFIX}" not in self.tables:
            return pd.DataFrame(
                columns=["path", "fname", "owner", "Domain", "Name", "Permission", "ObjectType"]
            )
        ptable = f"{tbl}{PERM_TABLE_SUFFIX}"
        limit_sql = f" LIMIT {int(limit)}" if limit and limit > 0 else ""
        qry = (
            f"SELECT A.path, A.fname, A.owner, B.Domain, B.Name, B.Permission, B.ObjectType "
            f"FROM [{tbl}] A INNER JOIN [{ptable}] B ON A.Id = B.Id{limit_sql}"
        )
        return pd.read_sql_query(qry, self.engine)

    @property
    def tables(self) -> list[str]:
        """Return all SQLite table names in this database."""
        return inspect(self.engine).get_table_names()

    def total_usage(
        self,
        table: str | None = None,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Return total storage usage in GB as a single-row DataFrame.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        owner
            Optional owner filter.
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Single-row DataFrame with column ``size_gb`` and ``bytes``.
        """
        total_bytes = self.get_total_storage(table=table, owner=owner, subdir=subdir)
        return pd.DataFrame([{"bytes": total_bytes, "size_gb": total_bytes / (2**30)}])

    def users(self, table: str | None = None, subdir: str | None = None) -> pd.DataFrame:
        """Return distinct file/directory owners in *table*.

        Parameters
        ----------
        table
            Crawl table name (defaults to :attr:`latest_crawl`).
        subdir
            Optional subdirectory prefix filter.

        Returns
        -------
        pandas.DataFrame
            Single-column DataFrame with ``owner``.
        """
        tbl = self._resolve_table(table)
        if tbl is None:
            return pd.DataFrame(columns=["owner"])
        where_sql, params = _build_where(subdir=subdir)
        qry = f"SELECT DISTINCT owner FROM [{tbl}] {where_sql} ORDER BY owner"
        return pd.read_sql_query(text(qry), self.engine, params=params)

    def users_with_access_at_level(
        self,
        path: str,
        table: str | None = None,
    ) -> pd.DataFrame:
        """Return ACL principals with direct permissions on exact directory *path*.

        Parameters
        ----------
        path
            Exact directory path to inspect.
        table
            Crawl table name (defaults to :attr:`latest_crawl`).

        Returns
        -------
        pandas.DataFrame
            Principals and permissions applied directly on *path*.
        """
        tbl = self._resolve_table(table)
        if tbl is None or f"{tbl}{PERM_TABLE_SUFFIX}" not in self.tables:
            return pd.DataFrame(columns=["path", "Domain", "Name", "Permission", "ObjectType"])
        ptable = f"{tbl}{PERM_TABLE_SUFFIX}"
        norm = os.path.normcase(os.path.normpath(path))
        qry = (
            f"SELECT DISTINCT A.path, B.Domain, B.Name, B.Permission, B.ObjectType "
            f"FROM [{tbl}] A INNER JOIN [{ptable}] B ON A.Id = B.Id "
            f"WHERE A.fname IS NULL AND A.path = :path ORDER BY B.Domain, B.Name"
        )
        return pd.read_sql_query(text(qry), self.engine, params={"path": norm})

    def users_with_access_below_folder(
        self,
        subdir: str,
        table: str | None = None,
    ) -> pd.DataFrame:
        """Return distinct ACL principals with access anywhere beneath *subdir*.

        Parameters
        ----------
        subdir
            Directory prefix to query beneath.
        table
            Crawl table name (defaults to :attr:`latest_crawl`).

        Returns
        -------
        pandas.DataFrame
            Distinct principals with access under *subdir*.
        """
        return self.acls(table=table, subdir=subdir)

    # -- Internal helpers ---------------------------------------------------

    def _filtered_table(
        self,
        table: str,
        owner: str | None = None,
        subdir: str | None = None,
    ) -> pd.DataFrame:
        """Load *table* filtered by optional *owner* and *subdir*."""
        where_sql, params = _build_where(owner=owner, subdir=subdir)
        return pd.read_sql_query(
            text(f"SELECT * FROM [{table}] {where_sql}"), self.engine, params=params
        )

    def _resolve_table(self, table: str | None) -> str | None:
        """Resolve *table* or fall back to :attr:`latest_crawl`."""
        return table if table is not None else self.latest_crawl

    def _resolve_two_tables(self, table1: str | None, table2: str | None) -> tuple[str, str]:
        """Resolve a pair of crawl tables for comparison, defaulting to the latest two."""
        crawls = self.crawls
        if len(crawls) < 2 and (table1 is None or table2 is None):
            raise ValueError(
                f"At least two crawls are required for comparison (found {len(crawls)})."
            )
        t1 = table1 or crawls[-2]
        t2 = table2 or crawls[-1]
        return t1, t2


class MultiDB:
    """Aggregate analytics across multiple :class:`CrawlReader` SQLite databases.

    Parameters
    ----------
    databases
        Sequence of SQLite database paths (or a single comma-separated string).
    max_timedelta
        Maximum day offset when aligning crawl dates across databases.
    fail_on_missing
        Raise :class:`FileNotFoundError` if any database path does not exist.
    """

    def __init__(
        self,
        databases: str | pathlib.Path | Sequence[str | pathlib.Path],
        max_timedelta: int = 20,
        fail_on_missing: bool = True,
    ) -> None:
        if isinstance(databases, pathlib.Path):
            raw_paths = [databases]
        elif isinstance(databases, str):
            raw_paths = [pathlib.Path(p.strip()) for p in databases.split(",") if p.strip()]
        else:
            raw_paths = [pathlib.Path(p) for p in databases]

        self.max_timedelta = max_timedelta
        self.db_paths: list[pathlib.Path] = []
        self.list_of_crawls: list[list[str]] = []
        self.all_crawls: list[str] = []

        for path in raw_paths:
            if not path.exists():
                if fail_on_missing:
                    raise FileNotFoundError(f"Could not find LANspector database: {path}")
                logger.warning("Skipping missing database: {}", path)
                continue
            with CrawlReader(path) as reader:
                crawls = reader.crawls
            if not crawls:
                logger.warning("Skipping empty database with no crawls: {}", path)
                continue
            self.db_paths.append(path)
            self.list_of_crawls.append(crawls)
            self.all_crawls.extend(crawls)

        self.all_crawls = sorted(set(self.all_crawls))

    def __repr__(self) -> str:
        total_crawls = sum(len(c) for c in self.list_of_crawls)
        return f"<MultiDB: {len(self.db_paths)} DBs, {total_crawls} crawls>"

    @property
    def is_multidb(self) -> bool:
        """Return ``True`` since this instance aggregates multiple databases."""
        return True

    @property
    def latest_crawl(self) -> str | None:
        """Return the most recent crawl timestamp across all databases."""
        return self.all_crawls[-1] if self.all_crawls else None

    def list_methods(self) -> list[str]:
        """List public :class:`CrawlReader` analytics methods supported by :meth:`query`.

        Returns
        -------
        list[str]
            Sorted list of callable method names.
        """
        prefixes = (
            "acls",
            "count_",
            "crawl_root",
            "executive_summary",
            "find_",
            "get_",
            "largest_",
            "list_",
            "new_",
            "number_",
            "oldest_",
            "parent_vs_child_report",
            "removed_",
            "return_crawl",
            "summarize_",
            "total_usage",
            "users",
        )
        excluded = {"list_of_crawls"}
        return sorted(
            name
            for name, member in pyinspect.getmembers(CrawlReader, predicate=pyinspect.isfunction)
            if not name.startswith("_") and name not in excluded and name.startswith(prefixes)
        )

    def nearest_crawl_to_date(
        self,
        date: str | datetime.date | datetime.datetime,
        max_delta: int | None = None,
    ) -> str | None:
        """Find the nearest crawl timestamp across all managed databases.

        Parameters
        ----------
        date
            Target date or timestamp.
        max_delta
            Maximum difference in days (defaults to :attr:`max_timedelta`).

        Returns
        -------
        str or None
            Nearest matching crawl table name.
        """
        return nearest_crawl_to_date(
            self.all_crawls,
            date=date,
            max_delta=self.max_timedelta if max_delta is None else max_delta,
        )

    def query(
        self,
        method_name: str,
        concat_results: bool = True,
        **kwargs: Any,
    ) -> Any:
        """Invoke *method_name* on each underlying :class:`CrawlReader` and aggregate results.

        Parameters
        ----------
        method_name
            Name of a public :class:`CrawlReader` method.
        concat_results
            When ``True``, concatenate DataFrames, sum integers, and combine
            :class:`~lanspector.datatypes.ParentChildResult` / :class:`~lanspector.datatypes.ExecutiveSummary`.
        **kwargs
            Keyword arguments forwarded to each :class:`CrawlReader` call.

        Returns
        -------
        Any
            Aggregated result matching the return type of *method_name*.
        """
        if not hasattr(CrawlReader, method_name):
            raise AttributeError(f"CrawlReader has no method {method_name!r}")

        requested_table = kwargs.get("table")
        results: list[Any] = []
        for path in self.db_paths:
            with CrawlReader(path) as reader:
                call_kwargs = dict(kwargs)
                if requested_table is not None and requested_table not in reader.crawls:
                    dt = _table_to_dt(requested_table)
                    if dt is not None:
                        nearest = reader.nearest_crawl_to_date(dt, max_delta=self.max_timedelta)
                        if nearest is None:
                            continue
                        call_kwargs["table"] = nearest
                fn = getattr(reader, method_name)
                results.append(fn(**call_kwargs))

        if not concat_results or not results:
            return results

        first = results[0]
        if isinstance(first, int):
            return sum(int(r) for r in results)
        if isinstance(first, pd.DataFrame):
            non_empty = [r for r in results if isinstance(r, pd.DataFrame) and not r.empty]
            return pd.concat(non_empty, ignore_index=True) if non_empty else pd.DataFrame()
        if isinstance(first, ParentChildResult):
            dir_dfs = [r.dirs_df for r in results if r.dirs_df is not None and not r.dirs_df.empty]
            file_dfs = [
                r.files_df for r in results if r.files_df is not None and not r.files_df.empty
            ]
            return ParentChildResult(
                dirs_df=pd.concat(dir_dfs, ignore_index=True) if dir_dfs else None,
                files_df=pd.concat(file_dfs, ignore_index=True) if file_dfs else None,
            )
        if isinstance(first, ExecutiveSummary):
            return results
        return results


# ---------------------------------------------------------------------------
# Public module-level utilities (alphabetical)
# ---------------------------------------------------------------------------


def melt_parent_vs_child(df: pd.DataFrame) -> pd.DataFrame:
    """Unpivot a parent-vs-child permission matrix into long format.

    Parameters
    ----------
    df
        Wide parent-vs-child DataFrame indexed by ``path`` (or ``(path, fname)``)
        with ``(Domain, Name)`` MultiIndex columns or flattened ``Domain\\Name`` columns.

    Returns
    -------
    pandas.DataFrame
        Long-format DataFrame with ``path``, ``Domain``, ``Name``, and ``permission``.
    """
    if df.empty:
        return pd.DataFrame(columns=["path", "Domain", "Name", "permission"])

    work = df.copy()
    if isinstance(work.columns, pd.MultiIndex):
        stacked = work.stack(level=[0, 1], future_stack=True).dropna()
        out = stacked.reset_index()
        out.columns = [*list(work.index.names), "Domain", "Name", "permission"]
        return out

    id_cols = [c for c in ("path", "fname") if c in work.columns]
    if not id_cols:
        work = work.reset_index()
        id_cols = [c for c in ("path", "fname") if c in work.columns]
    melted = work.melt(id_vars=id_cols, var_name="principal", value_name="permission").dropna(
        subset=["permission"]
    )
    split_cols = melted["principal"].astype(str).str.split("\\", n=1, expand=True)
    melted["Domain"] = split_cols[0]
    melted["Name"] = split_cols[1] if split_cols.shape[1] > 1 else ""
    return melted[[*id_cols, "Domain", "Name", "permission"]].reset_index(drop=True)


def nearest_crawl_to_date(
    crawls: Sequence[str],
    date: str | datetime.date | datetime.datetime,
    max_delta: int | None = None,
) -> str | None:
    """Find the crawl timestamp string in *crawls* closest to *date*.

    Parameters
    ----------
    crawls
        Sequence of ``YYYYMMDDTHHMMSS`` table names.
    date
        Target date (string, :class:`datetime.date`, or :class:`datetime.datetime`).
    max_delta
        Optional maximum allowed distance in days.

    Returns
    -------
    str or None
        Best matching table name, or ``None`` if *crawls* is empty or outside *max_delta*.
    """
    if not crawls:
        return None
    target = _parse_date_bound(date)
    best_name: str | None = None
    best_delta: datetime.timedelta | None = None
    for name in crawls:
        dt = _table_to_dt(name)
        if dt is None:
            continue
        delta = abs(dt - target)
        if best_delta is None or delta < best_delta:
            best_delta = delta
            best_name = name
    if best_name is None or best_delta is None:
        return None
    if max_delta is not None and best_delta > datetime.timedelta(days=max_delta):
        return None
    return best_name


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _attach_share_permissions(
    obj: pd.DataFrame,
    share_lookup: dict[str, pd.DataFrame],
) -> pd.DataFrame:
    """Append share-level permission columns matched by UNC share root."""
    paths = [str(p) for p in obj.index.get_level_values(0)]
    matched_rows: list[pd.DataFrame] = []
    for p in paths:
        drive, _ = os.path.splitdrive(p)
        key = drive.rstrip("\\").lower()
        if key in share_lookup:
            matched_rows.append(share_lookup[key])
    if len(matched_rows) != len(paths):
        return obj
    share_df = pd.concat(matched_rows, ignore_index=True)
    share_df.index = obj.index
    return pd.concat([obj, share_df], axis=1)


def _build_where(
    owner: str | None = None,
    subdir: str | None = None,
    table_alias: str | None = None,
    leading_and: bool = False,
) -> tuple[str, dict[str, Any]]:
    """Build a parameterized SQL WHERE/AND clause for optional owner & subdir filters."""
    prefix = f"{table_alias}." if table_alias else ""
    clauses: list[str] = []
    params: dict[str, Any] = {}
    if subdir is not None:
        norm = os.path.normcase(os.path.normpath(subdir))
        clauses.append(f"SUBSTR({prefix}path, 1, :sub_len) = :sub_val")
        params["sub_len"] = len(norm)
        params["sub_val"] = norm
    if owner is not None:
        clauses.append(f"LOWER({prefix}owner) = :owner_val")
        params["owner_val"] = owner.lower()
    if not clauses:
        return "", params
    joined = " AND ".join(clauses)
    return (f"AND {joined}" if leading_and else f"WHERE {joined}"), params


def _is_backup_name(name: str) -> bool:
    """Return True if *name* matches any backup filename/directory regex."""
    return any(regex.search(name) is not None for regex in BACKUP_REGEXES)


def _normalize_strip_prefix(prefix: str) -> str:
    """Normalize a path prefix before stripping it from displayed paths."""
    return os.path.normcase(os.path.normpath(prefix))


def _parent_index(
    path: str,
    index: pd.Index,
    root: str,
    for_files: bool = False,
) -> str:
    """Resolve the closest ancestor directory present in *index*."""
    cleaned = path.rstrip("\\/") or path
    if cleaned == root:
        return root
    parent = cleaned if for_files else (os.path.dirname(cleaned).rstrip("\\/") or root)
    drive = os.path.splitdrive(cleaned)[0]
    while parent not in index:
        if parent in (root, drive) or not parent:
            return root
        next_parent = os.path.dirname(parent).rstrip("\\/")
        if next_parent == parent:
            return root
        parent = next_parent
    return parent


def _parse_date_bound(value: str | datetime.date | datetime.datetime) -> datetime.datetime:
    """Parse a date string, date, or datetime into a naive datetime."""
    if isinstance(value, datetime.datetime):
        return value.replace(tzinfo=None)
    if isinstance(value, datetime.date):
        return datetime.datetime(value.year, value.month, value.day)
    for fmt in (TIMESTAMP_FORMAT, "%Y-%m-%d", "%Y/%m/%d", "%Y%m%d"):
        try:
            return datetime.datetime.strptime(value, fmt)
        except ValueError:
            continue
    return pd.to_datetime(value).to_pydatetime().replace(tzinfo=None)


def _register_sqlite_functions(dbapi_conn: Any, _conn_record: Any) -> None:
    """Register custom SQLite scalar helpers (REGEXP, IS_BACKUP, PII_SCORE) on connect."""
    dbapi_conn.create_function(
        "REGEXP", 2, lambda expr, item: bool(re.search(expr, item or "", re.I))
    )
    dbapi_conn.create_function("IS_BACKUP", 1, lambda item: int(_is_backup_name(str(item or ""))))
    dbapi_conn.create_function("PII_SCORE", 2, lambda p, f: count_pii_name_matches(p, f))


def _split_path(path: str) -> list[str]:
    """Split a Windows or POSIX path into non-empty path segments."""
    return [p for p in re.split(r"[\\/]+", path) if p]


def _table_to_dt(tablename: str) -> datetime.datetime | None:
    """Parse a crawl timestamp table name into a datetime, or None if non-timestamped."""
    for fmt in (TIMESTAMP_FORMAT, "%Y%m%d"):
        try:
            return datetime.datetime.strptime(tablename, fmt)
        except ValueError:
            continue
    return None
