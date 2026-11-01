#!/usr/bin/env bash
set -euo pipefail

START_SECONDS=$SECONDS
RUN_TESTS=0
case "${1:-}" in
  "") ;;
  --tests) RUN_TESTS=1 ;;
  *) echo "usage: bash run/setup.sh [--tests]" >&2; exit 64 ;;
esac
if [ "$#" -gt 1 ]; then
  echo "usage: bash run/setup.sh [--tests]" >&2
  exit 64
fi

cd "$(dirname "$0")/.."

fail() {
  echo "setup: $*" >&2
  exit 1
}

# Prints the IDs, or fails if Docker cannot list them: empty output must mean none.
list_labelled() {
  local kind="$1" filter="$2" out
  if [ "$kind" = containers ]; then
    out="$(docker ps -aq --filter "label=$filter")" || fail "could not list containers ($filter)"
  else
    out="$(docker network ls -q --filter "label=$filter")" || fail "could not list networks ($filter)"
  fi
  printf '%s' "$out"
}

echo "==> Preflight"
[ "$(uname -s)" = "Linux" ] || fail "Linux is required (found $(uname -s))"
command -v docker >/dev/null 2>&1 || fail "docker is not on PATH; install Docker Engine 28 or later"
docker info >/dev/null 2>&1 || fail "the Docker daemon is not reachable (docker info failed)"
SERVER_VERSION="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
[ -n "$SERVER_VERSION" ] || fail "could not read the Docker server version"
SERVER_MAJOR="${SERVER_VERSION%%.*}"
case "$SERVER_MAJOR" in
  ''|*[!0-9]*) fail "could not parse the Docker server version: $SERVER_VERSION" ;;
esac
[ "$SERVER_MAJOR" -ge 28 ] || fail "Docker Engine 28 or later is required (found server $SERVER_VERSION)"
# The sandbox connects through DOCKER_HOST or the default socket and ignores CLI contexts.
if [ -z "${DOCKER_HOST:-}" ]; then
  DOCKER_CONTEXT_NAME="$(docker context show)" || fail "could not read the active Docker context"
  [ "$DOCKER_CONTEXT_NAME" = default ] \
    || fail "the active Docker context is '$DOCKER_CONTEXT_NAME', but the sandbox ignores contexts; set DOCKER_HOST to its endpoint or run 'docker context use default'"
fi
command -v uv >/dev/null 2>&1 || fail "uv is not on PATH; install it from https://docs.astral.sh/uv/ and re-run"

echo "==> Installing locked dependencies"
uv sync --frozen --extra dev --extra cpu

echo "==> Pulling test images"
docker pull alpine:3.20
docker pull python:3.12-alpine
SINK_IMAGE="$(uv run --no-sync python -I -c 'from run.cage import SINK_IMAGE; print(SINK_IMAGE)')"
if ! docker image inspect "$SINK_IMAGE" >/dev/null 2>&1; then
  echo "==> Pinned sink image not resolved locally; pulling it by digest"
  docker pull "$SINK_IMAGE"
fi
docker image inspect "$SINK_IMAGE" >/dev/null 2>&1 || fail "pinned sink image still does not resolve locally: $SINK_IMAGE"

echo "==> Building the cage image"
uv run --no-sync python -m run.cage build

echo "==> Smoke scan (http-exfil fixture, scripted decoy)"
SMOKE_DIR="$(mktemp -d)"
trap 'rm -rf "$SMOKE_DIR"' EXIT
REPORT="$SMOKE_DIR/verdict.json"
SCAN_STATUS=0
uv run --no-sync baitwatch scan tests/e2e/fixtures/http-exfil \
  --llm scripted:tests/e2e/scripts/http-exfil.json \
  --json "$REPORT" || SCAN_STATUS=$?
SCAN_LABEL="$(uv run --no-sync python -I -c 'from run.sandbox import SCAN_LABEL; print(SCAN_LABEL)')"
if [ "$SCAN_STATUS" -ne 5 ]; then
  # Report only: another scan may own these, so nothing is removed here.
  STRAY_CONTAINERS="$(list_labelled containers "$SCAN_LABEL")"
  STRAY_NETWORKS="$(list_labelled networks "$SCAN_LABEL")"
  if [ -n "$STRAY_CONTAINERS$STRAY_NETWORKS" ]; then
    echo "setup: scan-labelled resources exist; inspect with: docker ps -a --filter label=$SCAN_LABEL" \
      "and docker network ls --filter label=$SCAN_LABEL" >&2
  fi
  fail "smoke scan expected exit 5 (BLOCK), got $SCAN_STATUS"
fi
uv run --no-sync python -I - "$REPORT" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
if report.get("verdict") != "BLOCK":
    raise SystemExit(f"smoke scan verdict is {report.get('verdict')!r}, expected 'BLOCK'")
if not report.get("run", {}).get("http_hits"):
    raise SystemExit("smoke scan recorded no HTTP sink hits")
codes = {error.get("code") for error in report.get("run", {}).get("errors", [])}
if "STAGING_CLEANUP" in codes:
    raise SystemExit("smoke scan could not remove its staged copy (STAGING_CLEANUP)")
PY
SCAN_ID="$(uv run --no-sync python -I - "$REPORT" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["run"]["scan_id"])
PY
)"
LEFT_CONTAINERS="$(list_labelled containers "$SCAN_LABEL=$SCAN_ID")"
[ -z "$LEFT_CONTAINERS" ] || fail "smoke scan left containers behind ($SCAN_LABEL=$SCAN_ID)"
LEFT_NETWORKS="$(list_labelled networks "$SCAN_LABEL=$SCAN_ID")"
[ -z "$LEFT_NETWORKS" ] || fail "smoke scan left networks behind ($SCAN_LABEL=$SCAN_ID)"
rm -rf "$SMOKE_DIR"
trap - EXIT

if [ "$RUN_TESTS" -eq 1 ]; then
  echo "==> Full RUN checks"
  bash run/check.sh
fi

echo "setup: OK in $((SECONDS - START_SECONDS))s"
