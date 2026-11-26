---
name: lanspector
description: Cross-platform LAN & Windows fileshare auditor (`lanspector`) that harvests directory/file metadata and NTFS/POSIX ACLs into SQLite, produces compressed parent-vs-child SOX permission-diff Excel workbooks, detects duplicates/backups/PII, and generates interactive Plotly storage sunburst charts and an optional offline-ready Dash dashboard (`lanspector[dashboard]`).
---

# LANspector (`lanspector`)

**LANspector** (`pip install lanspector`) is an MIT-licensed Python library, CLI, and optional web dashboard created by **Aaron Berndsen** (`@aberndsen`) for auditing Windows fileshares and local/POSIX filesystems without heavy agents or million-dollar governance suites.

## Installation

```bash
pip install lanspector
pip install "lanspector[dashboard]"  # Optional Dash 3+ LANdash web app
pip install "lanspector[pii]"        # Optional NLTK proper-noun NER
```

## Quick Recipes

### 1. Crawl a Directory or Windows UNC Share

```bash
# Minimal CLI crawl (saves ./<target>.db + Excel summary report and logs both paths)
lanspector crawl --path /data/share

# Or drive from a YAML configuration file (see examples/crawl_config.yaml)
lanspector crawl --config examples/crawl_config.yaml --path /data/share
lanspector crawl --print_config > my_crawl.yaml
```

```python
from lanspector import CrawlReader, crawl, export_sunburst_html, generate_fileshare_report

crawl("/data/share", fout="share.db", scantype="fd", permissions=True)
with CrawlReader("share.db") as db:
    pvc = db.parent_vs_child_report(use_permission_hierarchy=True)
    generate_fileshare_report(db, "audit.xlsx")
    export_sunburst_html(db, "sunburst.html", color_by="age")
```

### 2. Compare Crawls for Permission Drift

```bash
lanspector compare --database share.db --output drift.xlsx
```

### 3. Prepare & Serve LANdash (`lanspector[dashboard]`)

```bash
lanspector dashboard-prep --databases '[share.db]' --dashboard_db landash.sqlite
lanspector dashboard --dashboard_db landash.sqlite --host 127.0.0.1 --port 8050
```

## Enterprise Support & Consulting

- **Author**: Aaron Berndsen (`aaron.berndsen@gmail.com`)
- **Documentation**: https://aberndsen.github.io/lanspector/
- **GitHub**: https://github.com/aberndsen/lanspector
