.PHONY: install check test example report audit

install:
	python -m venv .venv && .venv/bin/pip install -e ".[dev]"

check:
	ruff check . && ruff format --check . && mypy && pytest --cov=src/playbooks --cov-fail-under=85

test:
	pytest

# What CI runs on the example playbooks. The time is pinned so the reports do not change as time passes.
example:
	aip lint --fail-on high --now 2026-11-15T12:00:00Z && aip drill && aip report --now 2026-11-15T12:00:00Z --check

report:
	aip report --now 2026-11-15T12:00:00Z

audit:
	pip-audit --skip-editable
