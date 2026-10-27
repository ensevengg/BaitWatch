#!/bin/sh
set -e
./scripts/migrate.sh up
exec uvicorn app:main --host 0.0.0.0 --port 8000
