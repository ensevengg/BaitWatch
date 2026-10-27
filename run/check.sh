#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
uv sync --frozen --extra dev
uv run ruff check run tests/run
uv run ruff format --check run tests/run
case "${1:-all}" in
  all) uv run pytest -m "not gpu" tests/run ;;
  unit) uv run pytest -m "not docker and not gpu" tests/run ;;
  *) echo "usage: bash run/check.sh [all|unit]" >&2; exit 64 ;;
esac
