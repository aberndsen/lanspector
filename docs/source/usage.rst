.. meta::
   :description: LANspector CLI and YAML configuration guide: crawl Windows SMB shares or POSIX folders with crash-resume, generate SOX Excel audit workbooks, compare snapshots, and serve LANdash.
   :keywords: lanspector cli, crawl windows shares python, resume filesystem crawl, yaml audit config, jsonargparse cli, excel fileshare report, smb share enumeration

Usage Guide
===========

Installation
------------

Install from PyPI using ``pip`` or ``uv``:

.. code-block:: bash

   pip install lanspector
   # Optional extras
   pip install "lanspector[dashboard]"  # Dash 3+ LANdash web app
   pip install "lanspector[pii]"        # Optional NLTK proper-noun NER

CLI Subcommands
---------------

LANspector exposes a unified CLI powered by ``jsonargparse`` and typed dataclasses in
:mod:`lanspector.settings`. Run ``lanspector <subcommand> --help`` for detailed flag
descriptions.

.. list-table:: Subcommands & Required Arguments
   :header-rows: 1
   :widths: 18 28 54

   * - Subcommand
     - Required Arguments
     - Default Outputs & Purpose
   * - ``crawl``
     - ``--path <dir>`` *or* ``--driver <file>``
     - Saves ``./<target>.db`` (if ``--fout`` omitted) and ``<fout_stem>_<timestamp>.xlsx`` (``--summarize true`` by default); logs full output paths.
   * - ``report``
     - ``--databases '[a.db]'``
     - Writes ``lanspector_report.xlsx`` (override with ``--output``).
   * - ``sunburst``
     - ``--database <a.db>``
     - Writes standalone offline ``lanspector_sunburst.html`` (override with ``--output``).
   * - ``compare``
     - ``--database <a.db>``
     - Prints diff counts and optionally writes ``--output drift.xlsx``.
   * - ``dashboard-prep``
     - ``--databases '[a.db]'``
     - Aggregates crawl databases into a LANdash SQLite store (default ``landash.sqlite``). Run before ``dashboard``.
   * - ``dashboard``
     - *(none; defaults to ``landash.sqlite``)*
     - Serves LANdash locally at ``http://127.0.0.1:8050`` from a store built by ``dashboard-prep``.
   * - ``gui``
     - *(none)*
     - Launches the optional Tkinter desktop GUI.
   * - ``shares``
     - ``--servers`` or ``--domains``
     - Lists Windows SMB shares (optionally writes ``--output`` CSV/Excel).

.. code-block:: bash

   # Minimal crawl: creates ./finance.db and ./finance_<timestamp>.xlsx and logs their paths
   lanspector crawl --path /data/finance

   # Resume an interrupted crawl in an existing SQLite database (skips completed paths)
   lanspector crawl --path /data/finance --fout finance.db --resume true

   # Explicit paths + interactive Plotly sunburst HTML
   lanspector crawl --path /data/finance --fout finance.db --sunburst_html sunburst.html

   lanspector report --databases '[finance.db]' --output audit.xlsx
   lanspector sunburst --database finance.db --output sunburst.html --color_by age
   lanspector compare --database finance.db --output drift.xlsx
   lanspector dashboard-prep --databases '[finance.db]' --dashboard_db landash.sqlite
   lanspector dashboard --dashboard_db landash.sqlite --port 8050
   lanspector gui --database finance.db
   lanspector shares --servers '[filesrv01]'

Configuration Files (``--config`` & ``--print_config``)
-------------------------------------------------------

Because the CLI is backed by ``jsonargparse``, **every subcommand supports YAML or JSON
configuration files** via ``--config <path>``. Any flag passed on the command line overrides
the value in the config file.

Sample configuration files live in the repository's ``examples/`` directory:

* ``examples/crawl_config.yaml`` — Annotated single-share crawl configuration
* ``examples/report_config.yaml`` — Multi-database Excel audit report configuration
* ``examples/driver_shares.txt`` — Batch multi-share / server / domain driver file

You can also generate a complete starter YAML config for any subcommand with ``--print_config``:

.. code-block:: bash

   lanspector crawl --print_config > my_crawl.yaml
   lanspector crawl --config my_crawl.yaml --path /data/finance

Example ``examples/crawl_config.yaml``:

.. literalinclude:: ../../examples/crawl_config.yaml
   :language: yaml

Example ``examples/report_config.yaml``:

.. literalinclude:: ../../examples/report_config.yaml
   :language: yaml

Batch Crawling with a Driver File
---------------------------------

Create a plain text driver file listing one target per line (blank lines and ``#`` comments are ignored):

.. code-block:: text

   # Local or UNC paths
   \\filesrv01\finance
   \\filesrv02\actuarial

   # Fileserver hostname (Windows: crawls all non-admin shares)
   filesrv03

   # Domain discovery (Windows: enumerates domain computers and their shares)
   DN: CORP

Then run:

.. code-block:: bash

   lanspector crawl --driver shares.txt --driver_out ./crawls --summarize true

Stepwise "Peeling Away the Layers"
----------------------------------

On large fileshares, start with ``--limit 100`` or ``--max_depth 2`` to remediate share-level and
top-level NTFS entitlements first, then progressively increase depth in subsequent crawls stored
in the same SQLite database.
