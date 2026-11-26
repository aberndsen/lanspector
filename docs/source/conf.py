"""Sphinx documentation configuration for LANspector."""

from __future__ import annotations

import datetime
import json
import pathlib
import sys
from xml.sax.saxutils import escape

# Ensure the src package is importable when building docs directly from the checkout
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))

from lanspector import __version__ as _pkg_version

# -- Project information -----------------------------------------------------

project = "LANspector"
author = "Aaron Berndsen"
copyright = "2026, Aaron Berndsen"
release = _pkg_version
version = ".".join(release.split(".")[:2])
html_baseurl = "https://aberndsen.github.io/lanspector/"

# -- General configuration ---------------------------------------------------

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "numpydoc",
]

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
source_suffix = {".rst": "restructuredtext"}
master_doc = "index"

# -- Autodoc & NumPyDoc configuration ----------------------------------------

autoclass_content = "both"
autodoc_member_order = "bysource"
autodoc_typehints = "description"
autosummary_generate = False

numpydoc_show_class_members = False
numpydoc_class_members_toctree = False

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "pandas": ("https://pandas.pydata.org/docs/", None),
}

# -- HTML output (PyData Sphinx Theme) ---------------------------------------

html_theme = "pydata_sphinx_theme"
html_title = f"LANspector {release} — Fileshare ACL Auditing & Storage Analytics"
html_static_path: list[str] = ["_static"]
html_extra_path: list[str] = [
    "_static/robots.txt",
    "_static/llms.txt",
    "_static/llms-full.txt",
]

html_sidebars = {
    "index": [],
    "consulting": [],
}

html_theme_options = {
    "logo": {"text": "LANspector"},
    "show_toc_level": 2,
    "navigation_depth": 3,
    "show_nav_level": 2,
    "navbar_start": ["navbar-logo", "version-badge"],
    "navbar_end": ["theme-switcher", "navbar-icon-links"],
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/aberndsen/lanspector",
            "icon": "fa-brands fa-github",
        },
        {
            "name": "PyPI",
            "url": "https://pypi.org/project/lanspector/",
            "icon": "fa-brands fa-python",
        },
        {
            "name": "LinkedIn (Aaron Berndsen)",
            "url": "https://www.linkedin.com/in/aberndsen/",
            "icon": "fa-brands fa-linkedin",
        },
    ],
    "footer_start": ["copyright"],
    "footer_center": ["package-version"],
    "footer_end": ["sphinx-version"],
}

# -- SEO, OpenGraph & AI/LLM Structured Data (JSON-LD + Sitemap) -------------

_SEO_DESCRIPTION = (
    "LANspector: Cross-platform Windows & LAN fileshare auditor with compressed "
    "parent-vs-child SOX permission-diff Excel reports, interactive Plotly storage "
    "sunburst charts, and an optional offline-ready Dash web dashboard."
)

_JSON_LD_PAYLOAD = json.dumps(
    {
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "SoftwareApplication",
                "name": "LANspector",
                "alternateName": ["lanspector", "LANdash"],
                "applicationCategory": "DeveloperApplication",
                "operatingSystem": "Cross-platform (Python 3.11+)",
                "softwareVersion": release,
                "license": "https://opensource.org/licenses/MIT",
                "url": html_baseurl,
                "downloadUrl": "https://pypi.org/project/lanspector/",
                "codeRepository": "https://github.com/aberndsen/lanspector",
                "description": _SEO_DESCRIPTION,
                "keywords": (
                    "ntfs acl audit python, sox fileshare permissions report, parent vs child acl diff, "
                    "dumpsec alternative, varonis alternative, plotly storage sunburst, lan cleanup"
                ),
                "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
                "author": {
                    "@type": "Person",
                    "name": "Aaron Berndsen",
                    "email": "aaron.berndsen@gmail.com",
                    "url": "https://www.linkedin.com/in/aberndsen/",
                },
            },
        ],
    }
)


def _inject_seo_and_jsonld(
    app: object,
    pagename: str,
    templatename: str,
    context: dict[str, object],
    doctree: object,
) -> None:
    """Inject canonical URL, OpenGraph, Twitter Card, llms.txt link, and JSON-LD tags."""
    page_url = f"{html_baseurl}{pagename}.html" if pagename != "index" else html_baseurl
    page_title = f"{context.get('title', 'LANspector')} — LANspector {release}"
    metatags = str(context.get("metatags", ""))
    seo_tags = (
        f'\n<link rel="canonical" href="{page_url}" />'
        f'\n<link rel="llms-txt" href="{html_baseurl}llms.txt" />'
        f'\n<meta property="og:site_name" content="LANspector" />'
        f'\n<meta property="og:type" content="website" />'
        f'\n<meta property="og:url" content="{page_url}" />'
        f'\n<meta property="og:title" content="{escape(page_title)}" />'
        f'\n<meta property="og:description" content="{escape(_SEO_DESCRIPTION)}" />'
        f'\n<meta name="twitter:card" content="summary" />'
        f'\n<meta name="twitter:title" content="{escape(page_title)}" />'
        f'\n<meta name="twitter:description" content="{escape(_SEO_DESCRIPTION)}" />'
        f'\n<script type="application/ld+json">{_JSON_LD_PAYLOAD}</script>\n'
    )
    context["metatags"] = metatags + seo_tags


def _generate_sitemap(app: object, exception: Exception | None) -> None:
    """Generate sitemap.xml in the HTML output directory after a successful build."""
    if exception is not None:
        return
    outdir = pathlib.Path(app.outdir)  # type: ignore[attr-defined]
    env = getattr(app, "env", None)
    found_docs: set[str] = getattr(env, "found_docs", set()) if env is not None else set()
    if not outdir.is_dir():
        return
    today = datetime.date.today().isoformat()
    doc_names = (
        sorted(found_docs)
        if found_docs
        else [
            p.relative_to(outdir).with_suffix("").as_posix()
            for p in sorted(outdir.rglob("*.html"))
            if not p.name.startswith("_")
            and p.name not in {"search.html", "genindex.html", "py-modindex.html"}
        ]
    )
    urls = []
    for docname in doc_names:
        rel = f"{docname}.html"
        loc = html_baseurl if rel == "index.html" else f"{html_baseurl}{rel}"
        priority = "1.0" if rel in {"index.html", "usage.html", "auditing_guide.html"} else "0.8"
        urls.append(
            f"  <url>\n    <loc>{escape(loc)}</loc>\n    <lastmod>{today}</lastmod>\n    <priority>{priority}</priority>\n  </url>"
        )
    sitemap_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(urls)
        + "\n</urlset>\n"
    )
    (outdir / "sitemap.xml").write_text(sitemap_xml, encoding="utf-8")


def setup(app: object) -> dict[str, object]:
    """Connect Sphinx SEO & sitemap hooks."""
    connect = app.connect  # type: ignore[attr-defined]
    connect("html-page-context", _inject_seo_and_jsonld)
    connect("build-finished", _generate_sitemap)
    return {"version": release, "parallel_read_safe": True, "parallel_write_safe": True}
