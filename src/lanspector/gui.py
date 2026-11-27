"""Optional Tkinter desktop GUI for LANspector (invoked via ``lanspector gui``)."""

from __future__ import annotations

import pathlib
import tempfile
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any

from loguru import logger

from lanspector.crawler import crawl
from lanspector.datatypes import ScanType
from lanspector.reader import CrawlReader
from lanspector.reporting import generate_fileshare_report
from lanspector.settings import GuiSettings
from lanspector.sunburst import export_sunburst_html


def launch_gui(settings: GuiSettings | None = None) -> int:
    """Start the interactive LANspector Tkinter desktop application.

    Parameters
    ----------
    settings
        Optional initial GUI configuration (pre-populated database and/or path).

    Returns
    -------
    int
        Exit status code (``0`` after normal window close).
    """
    cfg = settings or GuiSettings()
    app = LanSpectorGui(initial_db=cfg.database, initial_path=cfg.path)
    app.mainloop()
    return 0


class LanSpectorGui(tk.Tk):
    """Desktop Tkinter interface for crawling, summarizing, comparing, and charting shares.

    Parameters
    ----------
    initial_db
        Optional SQLite database path to pre-fill.
    initial_path
        Optional root directory path to pre-fill.
    """

    def __init__(
        self,
        initial_db: pathlib.Path | None = None,
        initial_path: pathlib.Path | None = None,
    ) -> None:
        super().__init__()
        self.title("LANspector")
        self.geometry("760x540")

        self.db_var = tk.StringVar(value=str(initial_db) if initial_db else "")
        self.crawl_path_var = tk.StringVar(value=str(initial_path) if initial_path else "")
        self.scantype_var = tk.StringVar(value="fd")
        self.perms_var = tk.BooleanVar(value=True)
        self.pii_var = tk.BooleanVar(value=False)
        self.limit_var = tk.IntVar(value=0)
        self.report_out_var = tk.StringVar(value="")
        self.selected_table_var = tk.StringVar(value="")
        self.table_a_var = tk.StringVar(value="")
        self.table_b_var = tk.StringVar(value="")

        self._build_layout()
        if self.db_var.get():
            self._refresh_crawl_tables()

    def _build_layout(self) -> None:
        """Construct the database bar, tabbed notebook, progress bar, and log pane."""
        top = ttk.LabelFrame(self, text="Crawl Database", padding=8)
        top.pack(fill="x", padx=10, pady=8)
        ttk.Label(top, text="Database (.db / .sqlite):").pack(side="left")
        ttk.Entry(top, textvariable=self.db_var, width=52).pack(
            side="left", padx=6, expand=True, fill="x"
        )
        ttk.Button(top, text="Browse...", command=self._browse_db).pack(side="left")

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=4)

        self._build_crawl_tab(nb)
        self._build_report_tab(nb)
        self._build_compare_tab(nb)
        self._build_sunburst_tab(nb)
        self._build_log_tab(nb)

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=10, pady=(4, 10))

    def _build_compare_tab(self, nb: ttk.Notebook) -> None:
        """Create the Compare Two Crawls tab."""
        frame = ttk.Frame(nb, padding=12)
        nb.add(frame, text="Compare Crawls")
        ttk.Label(frame, text="Earlier crawl:").grid(row=0, column=0, sticky="w", pady=4)
        self.combo_a = ttk.Combobox(frame, textvariable=self.table_a_var, width=32)
        self.combo_a.grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(frame, text="Later crawl:").grid(row=1, column=0, sticky="w", pady=4)
        self.combo_b = ttk.Combobox(frame, textvariable=self.table_b_var, width=32)
        self.combo_b.grid(row=1, column=1, sticky="w", padx=6)
        ttk.Button(frame, text="Compare", command=self._run_compare).grid(
            row=2, column=1, sticky="w", pady=10
        )

    def _build_crawl_tab(self, nb: ttk.Notebook) -> None:
        """Create the New Crawl tab."""
        frame = ttk.Frame(nb, padding=12)
        nb.add(frame, text="New Crawl")
        ttk.Label(frame, text="Root folder to crawl:").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.crawl_path_var, width=48).grid(row=0, column=1, padx=6)
        ttk.Button(frame, text="Browse...", command=self._browse_crawl_dir).grid(row=0, column=2)

        ttk.Label(frame, text="Scan type:").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Combobox(frame, textvariable=self.scantype_var, values=["fd", "d", "f"], width=10).grid(
            row=1, column=1, sticky="w", padx=6
        )
        ttk.Checkbutton(frame, text="Harvest permissions", variable=self.perms_var).grid(
            row=2, column=1, sticky="w", padx=6
        )
        ttk.Checkbutton(frame, text="Detect PII content", variable=self.pii_var).grid(
            row=3, column=1, sticky="w", padx=6
        )
        ttk.Label(frame, text="Object limit (0 = unlimited):").grid(
            row=4, column=0, sticky="w", pady=4
        )
        ttk.Spinbox(frame, from_=0, to=1_000_000, textvariable=self.limit_var, width=12).grid(
            row=4, column=1, sticky="w", padx=6
        )
        ttk.Button(frame, text="Run Crawl", command=self._run_crawl).grid(
            row=5, column=1, sticky="w", pady=12
        )

    def _build_log_tab(self, nb: ttk.Notebook) -> None:
        """Create the Log output tab."""
        frame = ttk.Frame(nb, padding=8)
        nb.add(frame, text="Log")
        self.log_text = scrolledtext.ScrolledText(frame, state="disabled", height=16)
        self.log_text.pack(fill="both", expand=True)

    def _build_report_tab(self, nb: ttk.Notebook) -> None:
        """Create the Summarize / Excel Audit Report tab."""
        frame = ttk.Frame(nb, padding=12)
        nb.add(frame, text="Summarize Crawl")
        ttk.Label(frame, text="Crawl selection:").grid(row=0, column=0, sticky="w", pady=4)
        self.combo_summary = ttk.Combobox(frame, textvariable=self.selected_table_var, width=32)
        self.combo_summary.grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(frame, text="Output Excel (.xlsx):").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(frame, textvariable=self.report_out_var, width=44).grid(row=1, column=1, padx=6)
        ttk.Button(frame, text="Save As...", command=self._browse_report_out).grid(row=1, column=2)
        ttk.Button(frame, text="Generate Excel Report", command=self._run_report).grid(
            row=2, column=1, sticky="w", pady=12
        )

    def _build_sunburst_tab(self, nb: ttk.Notebook) -> None:
        """Create the Interactive Plotly Sunburst tab."""
        frame = ttk.Frame(nb, padding=12)
        nb.add(frame, text="Storage Sunburst")
        ttk.Label(
            frame,
            text="Generate a standalone interactive Plotly sunburst HTML chart and open it in your browser.",
        ).pack(anchor="w", pady=6)
        ttk.Button(frame, text="Open Sunburst Chart", command=self._run_sunburst).pack(
            anchor="w", pady=8
        )

    def _append_log(self, message: str) -> None:
        """Append a status message to the Log tab safely from any thread."""

        def _insert() -> None:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", message + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        self.after(0, _insert)

    def _browse_crawl_dir(self) -> None:
        selected = filedialog.askdirectory(title="Select Directory to Crawl")
        if selected:
            self.crawl_path_var.set(selected)

    def _browse_db(self) -> None:
        selected = filedialog.askopenfilename(
            title="Select LANspector Database",
            filetypes=[("SQLite DB", "*.db *.sqlite *.sqlite3"), ("All files", "*.*")],
        )
        if selected:
            self.db_var.set(selected)
            self._refresh_crawl_tables()

    def _browse_report_out(self) -> None:
        selected = filedialog.asksaveasfilename(
            title="Save Excel Summary Report",
            defaultextension=".xlsx",
            filetypes=[("Excel Workbook", "*.xlsx")],
        )
        if selected:
            self.report_out_var.set(selected)

    def _refresh_crawl_tables(self) -> None:
        db_str = self.db_var.get().strip()
        if not db_str or not pathlib.Path(db_str).exists():
            return
        try:
            with CrawlReader(db_str) as reader:
                crawls = reader.crawls
        except Exception as exc:
            self._append_log(f"Failed to read database: {exc}")
            return
        self.combo_summary["values"] = crawls
        self.combo_a["values"] = crawls
        self.combo_b["values"] = crawls
        if crawls:
            self.selected_table_var.set(crawls[-1])
            self.table_b_var.set(crawls[-1])
            self.table_a_var.set(crawls[-2] if len(crawls) >= 2 else crawls[-1])

    def _run_background(self, target: Any, done_msg: str) -> None:
        """Execute *target* in a daemon thread while animating the progress bar."""
        self.progress.start(12)

        def _worker() -> None:
            try:
                target()
                self._append_log(done_msg)
                self.after(0, self._refresh_crawl_tables)
            except Exception as exc:
                logger.exception("GUI action failed")
                self._append_log(f"Error: {exc}")
                self.after(0, lambda err=str(exc): messagebox.showerror("LANspector Error", err))
            finally:
                self.after(0, self.progress.stop)

        threading.Thread(target=_worker, daemon=True).start()

    def _run_compare(self) -> None:
        db_str = self.db_var.get().strip()
        if not db_str:
            messagebox.showwarning("LANspector", "Please select a crawl database first.")
            return
        t1 = self.table_a_var.get() or None
        t2 = self.table_b_var.get() or None

        def _task() -> None:
            with CrawlReader(db_str) as reader:
                diffs = reader.compare_crawls(table1=t1, table2=t2)
            for key, df in diffs.items():
                self._append_log(f"{key}: {len(df)} rows")

        self._run_background(_task, "Comparison complete.")

    def _run_crawl(self) -> None:
        target_dir = self.crawl_path_var.get().strip()
        if not target_dir:
            messagebox.showwarning("LANspector", "Please select a folder to crawl.")
            return
        db_str = self.db_var.get().strip()
        if not db_str:
            db_str = filedialog.asksaveasfilename(
                title="Save Crawl Database As",
                defaultextension=".db",
                filetypes=[("SQLite DB", "*.db")],
            )
            if not db_str:
                return
            self.db_var.set(db_str)

        raw_scan = self.scantype_var.get()
        scantype: ScanType = raw_scan if raw_scan in ("d", "f", "fd") else "fd"
        perms = self.perms_var.get()
        pii = self.pii_var.get()
        limit = self.limit_var.get()

        def _task() -> None:
            res = crawl(
                path=target_dir,
                scantype=scantype,
                permissions=perms,
                fout=db_str,
                limit=limit,
                detect_pii_content=pii,
            )
            self._append_log(f"Crawled {res.objects_processed} objects into table {res.tablename}.")

        self._run_background(_task, f"Crawl saved to {db_str}")

    def _run_report(self) -> None:
        db_str = self.db_var.get().strip()
        if not db_str:
            messagebox.showwarning("LANspector", "Please select a crawl database first.")
            return
        out = self.report_out_var.get().strip()
        if not out:
            with tempfile.NamedTemporaryFile(
                prefix="lanspector_summary_", suffix=".xlsx", delete=False
            ) as tmp_file:
                out = tmp_file.name
        tbl = self.selected_table_var.get() or None

        def _task() -> None:
            written = generate_fileshare_report(db_str, out, table=tbl)
            self._append_log(f"Report written to {written}")

        self._run_background(_task, f"Excel report created: {out}")

    def _run_sunburst(self) -> None:
        db_str = self.db_var.get().strip()
        if not db_str:
            messagebox.showwarning("LANspector", "Please select a crawl database first.")
            return
        with tempfile.NamedTemporaryFile(
            prefix="lanspector_sunburst_", suffix=".html", delete=False
        ) as tmp_file:
            out = pathlib.Path(tmp_file.name)
        tbl = self.selected_table_var.get() or None

        def _task() -> None:
            written = export_sunburst_html(db_str, out, table=tbl, open_browser=True)
            self._append_log(f"Sunburst exported to {written}")

        self._run_background(_task, f"Opened sunburst chart: {out}")
