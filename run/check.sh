#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python="${BAITWATCH_PYTHON:-python3}"
"$python" -m ruff check run tests/run tests/e2e
"$python" -m ruff format --check run tests/run tests/e2e
case "${1:-all}" in
  all) "$python" -m pytest -m "not gpu" tests/run tests/e2e ;;
  unit) "$python" -m pytest -m "not docker and not gpu" tests/run ;;
  *) echo "usage: bash run/check.sh [all|unit]" >&2; exit 64 ;;
esac
