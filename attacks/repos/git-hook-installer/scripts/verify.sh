#!/bin/sh
set -eu

python -m compileall -q ledger_tools
python -m pytest -q
