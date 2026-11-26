# Contributing to LANspector

Contributions, bug reports, and feature requests are welcome via GitHub issues and pull requests.

## Development Setup

LANspector uses [`uv`](https://docs.astral.sh/uv/) for dependency management, `ruff` for formatting/linting, `ty` for static type checking, `pytest` + `assertpy` for unit tests, and `sphinx` (`pydata-sphinx-theme` + `numpydoc`) for documentation.

```bash
git clone https://github.com/aberndsen/lanspector.git
cd lanspector
git checkout -b feat/my-change
make bootstrap
```

## Coding Standards

- Follow PEP 8 / `ruff` formatting (100-character line length).
- Add complete type annotations (`from __future__ import annotations`) checked by `ty`.
- Use NumPyDoc docstrings (`Parameters` and `Returns` sections on public functions/methods without duplicating type hints in parameter descriptions; concise one-liners for simple internal helpers).
- Place the primary public routines at the top of each module, followed by supporting functions sorted alphabetically.

## Running Checks Before Opening a Pull Request

Run the full local CI suite before pushing:

```bash
make static-check   # ruff format/check + ty check
make dynamic-check  # pytest with coverage + sphinx HTML docs build
make build-package  # hatchling sdist + wheel build
```

Or run everything end-to-end with:

```bash
make ci
```
