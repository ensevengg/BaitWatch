#!/bin/sh
set -eu

python -m compileall -q crucible_log
python -m pytest -q
