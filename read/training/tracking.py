"""Optional MLflow logging for training runs and gate reports.

Talks to an MLflow tracking server over its REST API (stdlib only, so the
training venv needs no mlflow install). Off unless a tracking URI is given via
``--mlflow-uri`` or ``MLFLOW_TRACKING_URI``. Never fails a run: the first
error prints one warning and turns logging off.

Backfill finished runs and gate reports from the files they left behind:

    python -m read.training.tracking --uri URI train  LOG [LOG ...]
    python -m read.training.tracking --uri URI gate   REPORT.json [...]
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

TRAIN_EXPERIMENT = "baitwatch-v17"
GATE_EXPERIMENT = "baitwatch-v17-gate"
_BAD_KEY = re.compile(r"[^\w./\- :]")
_STEP_RE = re.compile(r"^epoch (\d+) step (\d+)/(\d+) loss ([\d.]+)")
_DONE_RE = re.compile(r"^epoch (\d+) done: (\{.*\})")


def resolve_uri(uri: str | None) -> str | None:
    return (uri or os.environ.get("MLFLOW_TRACKING_URI") or "").rstrip("/") or None


def _key(name: str) -> str:
    return _BAD_KEY.sub("_", name)


class MlflowRun:
    def __init__(self, uri: str, run_id: str):
        self.uri, self.run_id, self.alive = uri, run_id, True

    @classmethod
    def start(cls, uri: str | None, experiment: str, run_name: str,
              params: dict | None = None, tags: dict | None = None) -> MlflowRun | None:
        uri = resolve_uri(uri)
        if uri is None:
            return None
        try:
            exp = _call(uri, "GET", "experiments/get-by-name", {"experiment_name": experiment})
            exp_id = exp["experiment"]["experiment_id"] if exp else _call(
                uri, "POST", "experiments/create", {"name": experiment, "tags": [
                    {"key": "mlflow.experimentKind", "value": "custom_model_development"}]}
            )["experiment_id"]
            run = _call(uri, "POST", "runs/create", {
                "experiment_id": exp_id, "run_name": run_name, "start_time": _now_ms(),
                "tags": [{"key": k, "value": str(v)} for k, v in (tags or {}).items()]})
            run_id = run["run"]["info"]["run_id"]
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException) as e:
            print(f"mlflow: logging off ({uri}: {e})", file=sys.stderr, flush=True)
            return None
        out = cls(uri, run_id)
        if params:
            out.log_params(params)
        if out.alive:
            print(f"mlflow: {uri}/#/experiments/{exp_id}/runs/{out.run_id}", flush=True)
        return out

    def log_params(self, params: dict) -> None:
        items = [{"key": _key(k), "value": str(v)[:6000]} for k, v in params.items()]
        for i in range(0, len(items), 100):
            self._batch(params=items[i:i + 100])

    def log_metrics(self, metrics: dict, step: int = 0) -> None:
        ts = _now_ms()
        items = [{"key": _key(k), "value": float(v), "timestamp": ts, "step": int(step)}
                 for k, v in metrics.items() if isinstance(v, (int, float)) and v == v]
        for i in range(0, len(items), 1000):
            self._batch(metrics=items[i:i + 1000])

    def finish(self, ok: bool = True) -> None:
        self._send("runs/update", {"run_id": self.run_id, "end_time": _now_ms(),
                                   "status": "FINISHED" if ok else "FAILED"})

    def _batch(self, **body) -> None:
        self._send("runs/log-batch", {"run_id": self.run_id, **body})

    def _send(self, path: str, body: dict) -> None:
        if not self.alive:
            return
        try:
            _call(self.uri, "POST", path, body)
        except (OSError, ValueError, http.client.HTTPException) as e:
            self.alive = False
            print(f"mlflow: logging off ({e})", file=sys.stderr, flush=True)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _call(uri: str, method: str, path: str, body: dict) -> dict | None:
    url = f"{uri}/api/2.0/mlflow/{path}"
    data = None
    if method == "GET":
        url += "?" + "&".join(f"{k}={urllib.request.quote(str(v))}" for k, v in body.items())
    else:
        data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        if e.code == 404 and method == "GET":
            return None
        raise ValueError(f"{e.code} {e.read()[:200]!r}") from e


def val_metrics(val: dict) -> dict:
    return {f"val/{k}": v for k, v in val.items()}


def gate_metrics(report: dict) -> dict:
    g = report.get("at_gate_threshold") or {}
    out = {"held_out_recall": report.get("held_out_recall_at_gate"),
           "gate_pass": float(bool(report.get("gate_pass")))}
    for k in ("threshold", "gold_recall", "aditya_recall", "suite_recall", "agent_file_fpr",
              "corpus_file_fpr", "all_benign_fpr"):
        out[k] = g.get(k)
    return out


def log_gate_report(uri: str | None, report: dict, name: str) -> None:
    run = MlflowRun.start(uri, GATE_EXPERIMENT, name,
                          params={"model": report.get("model"), "window": report.get("window"),
                                  "decoders": report.get("decoders")})
    if run:
        run.log_metrics(gate_metrics(report))
        run.finish()


def backfill_train_log(uri: str | None, log: Path) -> None:
    """Replay a finished ``train_<name>.log`` (step losses + per-epoch val)."""
    lines = log.read_text(errors="replace").splitlines()
    steps = [m for m in map(_STEP_RE.match, lines) if m]
    dones = [m for m in map(_DONE_RE.match, lines) if m]
    if not steps:
        return
    total, epochs = int(steps[-1][3]), max(len(dones), int(steps[-1][1]))
    run = MlflowRun.start(uri, TRAIN_EXPERIMENT, log.stem.removeprefix("train_"),
                          params={"log": str(log), "total_steps": total},
                          tags={"backfilled": "true"})
    if run is None:
        return
    for m in steps:
        run.log_metrics({"train/loss": float(m[4]), "epoch": int(m[1])}, step=int(m[2]))
    for m in dones:
        val = json.loads(m[2].replace("'", '"'))
        run.log_metrics(val_metrics(val), step=round(total * int(m[1]) / epochs))
    run.finish(ok=not any(line.startswith("Traceback") for line in lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.training.tracking")
    parser.add_argument("--uri", default=None, help="default: $MLFLOW_TRACKING_URI")
    parser.add_argument("kind", choices=("train", "gate"))
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args(argv)
    if resolve_uri(args.uri) is None:
        parser.error("no tracking URI (--uri or MLFLOW_TRACKING_URI)")
    for p in map(Path, args.paths):
        if args.kind == "train":
            backfill_train_log(args.uri, p)
        else:
            log_gate_report(args.uri, json.loads(p.read_text()), p.stem)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
