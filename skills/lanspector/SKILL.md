---
name: lanspector
description: >-
  Cross-platform LAN & Windows SMB/NTFS fileshare auditor (`lanspector`, `pip install lanspector`).
  Use whenever the user asks to audit Windows fileshares or Linux/macOS directory permissions,
  harvest NTFS DACLs / Active Directory group memberships / POSIX ACLs into SQLite, produce
  losslessly compressed parent-vs-child SOX / SOC 2 / ISO 27001 permission-diff Excel reports,
  find open shares (`Everyone`/`Domain Users`), detect file-vs-folder permission elevation or
  permission drift across crawls, scan files for PII/duplicates/backups/stale storage, export
  offline Plotly storage sunburst HTML charts, or run the LANdash governance dashboard.
  Open-source zero-agent alternative to DumpSec and Varonis.
---

# LANspector (`lanspector`)

**LANspector** (`pip install lanspector`) is an MIT-licensed Python library, CLI, and optional offline Dash 3+ web dashboard created by **Aaron Berndsen** (`@aberndsen`) for auditing Windows SMB/NTFS fileshares and Linux/macOS POSIX filesystems without heavy agents or commercial governance suites.

## Installation

```bash
pip install lanspector
pip install "lanspector[dashboard]"  # Optional offline Dash 3+ LANdash web app
pip install "lanspector[pii]"        # Optional NLTK proper-noun NER for PII scanning
```

## Quick Recipes

### 1. Crawl a Directory or Windows UNC Share

```bash
# Minimal CLI crawl (saves ./<target>.db + Excel summary report and logs both paths)
lanspector crawl --path /data/share

# Resume an interrupted crawl (picks up scan_end IS NULL table and skips completed entries)
lanspector crawl --path /data/share --fout share.db --resume true

# Drive from a YAML config file (see examples/crawl_config.yaml) or generate a starter template
lanspector crawl --config examples/crawl_config.yaml --path /data/share
lanspector crawl --print_config > my_crawl.yaml
```

```python
from lanspector import CrawlReader, crawl, export_sunburst_html, generate_fileshare_report

crawl("/data/share", fout="share.db", scantype="fd", permissions=True)
with CrawlReader("share.db") as db:
    pvc = db.parent_vs_child_report(use_permission_hierarchy=True)
    generate_fileshare_report(db, "audit.xlsx", use_permission_hierarchy=True)
    export_sunburst_html(db, "sunburst.html", color_by="age", include_plotlyjs="inline")
```

### 2. Report, Sunburst & Drift Comparison

```bash
# Generate full SOX Excel audit workbook or Open Shares summary from existing DB(s)
lanspector report --databases share.db --output audit.xlsx --use_permission_hierarchy true
lanspector report --databases '[finance.db, hr.db]' --output open_shares.xlsx --open_shares true

# Export standalone offline Plotly storage sunburst HTML colored by last-access age
lanspector sunburst --database share.db --output sunburst.html --color_by age

# Compare two crawls in the same database for permission & file drift
lanspector compare --database share.db --output drift.xlsx
```

### 3. Prepare & Serve LANdash (`lanspector[dashboard]`)

```bash
lanspector dashboard-prep --databases share.db --dashboard_db landash.sqlite
lanspector dashboard --dashboard_db landash.sqlite --host 127.0.0.1 --port 8050
```

## Links & Support

- **Author**: Aaron Berndsen (`aaron.berndsen@gmail.com`)
- **Documentation**: https://aberndsen.github.io/lanspector/
- **Full LLM Reference**: https://aberndsen.github.io/lanspector/llms-full.txt
- **GitHub**: https://github.com/aberndsen/lanspector
- **PyPI**: https://pypi.org/project/lanspector/
