UV ?= uv
UV_SYNC_FLAGS ?=
VENV ?= .venv
BIN := $(VENV)/bin

DOCS_SRC ?= docs/source
DOCS_BUILD ?= docs/build/html
SPHINXOPTS ?=

LINT_TARGETS := src tests docs/source/conf.py
TYPECHECK_TARGETS := src tests

.DEFAULT_GOAL := help

.PHONY: help bootstrap lint format typecheck static-check test docs dynamic-check build-package build ci clean distclean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

bootstrap: ## Create the virtual environment and install lanspector + dev dependencies
	$(UV) sync --all-groups $(UV_SYNC_FLAGS)

lint: ## Check code formatting and linting with ruff
	$(BIN)/ruff format --check $(LINT_TARGETS)
	$(BIN)/ruff check $(LINT_TARGETS)

format: ## Auto-format code and fix lint issues with ruff
	$(BIN)/ruff format $(LINT_TARGETS)
	$(BIN)/ruff check --fix $(LINT_TARGETS)

typecheck: ## Run static type checking with ty
	$(BIN)/ty check $(TYPECHECK_TARGETS)

static-check: lint typecheck ## Run all static checks (lint + type-hint)

test: ## Run the pytest suite with coverage
	$(BIN)/pytest

docs: ## Build Sphinx HTML documentation
	$(BIN)/sphinx-build -b html $(SPHINXOPTS) $(DOCS_SRC) $(DOCS_BUILD)

dynamic-check: test docs ## Run dynamic checks (test suite + docs build)

build-package: ## Build sdist and wheel distributions into dist/
	$(UV) build

build: docs build-package ## Build documentation and lanspector package

ci: bootstrap static-check dynamic-check build ## Run full CI pipeline

clean: ## Remove build artifacts, docs output, and test/lint caches
	rm -rf dist build docs/build htmlcov coverage_html_report
	rm -rf .pytest_cache .ruff_cache .mypy_cache .ty_cache .eggs
	rm -f .coverage .coverage.* coverage.xml
	find . -path ./$(VENV) -prune -o -type d -name "__pycache__" -exec rm -rf {} +
	find . -path ./$(VENV) -prune -o -type d -name "*.egg-info" -exec rm -rf {} +
	find . -path ./$(VENV) -prune -o -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete

distclean: clean ## Remove all cruft plus the virtual environment (.venv)
	rm -rf $(VENV)
