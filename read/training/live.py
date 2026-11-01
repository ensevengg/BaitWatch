"""Live training page: a watcher that feeds a static HTML dashboard.

No server: the watcher rewrites ``live_data.js`` next to ``index.html`` every
few seconds, and the page re-loads that script in place (script tags work on
file://, fetch does not). Open the printed path in a browser.

It finds the running trainer through /proc (stdout fd -> log file, cmdline ->
--out-dir / --epochs, etimes -> elapsed), so nothing has to be passed in. A
trainer whose stdout is a terminal has no log to read: pass ``--log``.
Finished runs are read back from the reports directory.

    python -m read.training.live [--reports ~/.local/share/baitwatch/reports/v17] [--log LOG]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from pathlib import Path

HOME = Path.home() / ".local/share/baitwatch"
STEP_RE = re.compile(r"^epoch (\d+) step (\d+)/(\d+) loss ([\d.]+)")
DONE_RE = re.compile(r"^epoch (\d+) done: (\{.*\})")
STAGES = (("read.training.train", "training"), ("read.training.tune_threshold", "tuning"),
          ("read.training.eval_v17", "gate eval"), ("read.data.v17.build", "building data"))


def _procs() -> list[dict]:
    out = []
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            argv = (d / "cmdline").read_bytes().split(b"\0")
            argv = [a.decode(errors="replace") for a in argv if a]
            if not argv or "python" not in Path(argv[0]).name:
                continue
            module = next((argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-m"), "")
            stage = next((s for m, s in STAGES if module == m), None)
            if stage is None:
                continue
            log = os.readlink(d / "fd/1")
            if not Path(log).is_file():     # a tty would block the read; pipes have no path
                log = None
            etimes = int(subprocess.run(["ps", "-o", "etimes=", "-p", d.name],
                                        capture_output=True, text=True).stdout.strip() or 0)
            out.append({"pid": int(d.name), "stage": stage, "argv": argv, "log": log,
                        "elapsed_s": etimes})
        except (OSError, ValueError):
            continue
    return out


def _arg(argv: list[str], name: str, default: str | None = None) -> str | None:
    for i, a in enumerate(argv[:-1]):
        if a == name:
            return argv[i + 1]
    return default


def parse_train_log(path: Path | None) -> dict:
    steps, vals, total, failed = [], [], None, False
    try:
        text = path.read_text(errors="replace") if path else ""
    except OSError:
        return {"steps": [], "val": [], "total_steps": None, "failed": False}
    for line in text.splitlines():
        m = STEP_RE.match(line)
        if m:
            ep, st, total, loss = int(m[1]), int(m[2]), int(m[3]), float(m[4])
            steps.append({"epoch": ep, "step": st, "loss": loss})
            continue
        m = DONE_RE.match(line)
        if m:
            try:
                v = json.loads(m[2].replace("'", '"'))
            except json.JSONDecodeError:
                v = {}
            vals.append({"epoch": int(m[1]), "loss": v.get("loss"),
                         "ap": v.get("average_precision"), "recall": v.get("recall@0.5"),
                         "precision": v.get("precision@0.5"), "fpr": v.get("fpr@0.5")})
        if line.startswith("Traceback"):
            failed = True
    return {"steps": steps, "val": vals, "total_steps": total, "failed": failed,
            "tail": text.splitlines()[-6:] if failed else []}


def gpu() -> dict | None:
    q = "name,memory.used,memory.total,utilization.gpu,temperature.gpu,power.draw"
    try:
        line = subprocess.run(["nvidia-smi", f"--query-gpu={q}", "--format=csv,noheader,nounits"],
                              capture_output=True, text=True, timeout=5).stdout.strip().splitlines()[0]
    except (OSError, IndexError, subprocess.TimeoutExpired):
        return None
    name, *nums = [x.strip() for x in line.split(",")]
    if len(nums) != 5:
        return None

    def num(x: str) -> float | None:     # "[N/A]", "[Not Supported]", ""
        try:
            return float(x)
        except ValueError:
            return None

    used, total, util, temp, power = map(num, nums)
    return {"name": name, "mem_used": used, "mem_total": total, "util": util,
            "temp": temp, "power": power}


def gate_reports(reports: Path) -> list[dict]:
    rows = []
    for p in sorted(reports.glob("*.json")):
        try:
            r = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        g = r.get("at_gate_threshold")
        if not g:
            continue
        rows.append({"name": p.stem.replace("baseline_", ""), "held_out": r.get("held_out_recall_at_gate"),
                     "gold": g.get("gold_recall"), "suite": g.get("suite_recall"),
                     "aditya": g.get("aditya_recall"), "fpr": g.get("all_benign_fpr"),
                     "threshold": g.get("threshold"), "pass": r.get("gate_pass"),
                     "mtime": p.stat().st_mtime})
    rows.sort(key=lambda r: r["mtime"])
    return rows


def snapshot(reports: Path, log_override: Path | None = None) -> dict:
    procs = _procs()
    train = next((p for p in procs if p["stage"] == "training"), None)
    run: dict = {"status": "idle", "stage": None}
    if train:
        log = log_override or (Path(train["log"]) if train["log"] else None)
        out_dir = _arg(train["argv"], "--out-dir")
        run = {"status": "running", "stage": "training", "log": str(log) if log else None,
               "model": Path(out_dir).name if out_dir else None,
               "epochs": int(_arg(train["argv"], "--epochs", "3")),
               "lr": _arg(train["argv"], "--lr"), "base": Path(_arg(train["argv"], "--base-model",
                                                                    "Llama-Prompt-Guard-2-22M")).name,
               "elapsed_s": train["elapsed_s"], **parse_train_log(log)}
    else:
        logs = sorted(reports.glob("train_*.log"), key=lambda p: p.stat().st_mtime)
        if logs:
            log = logs[-1]
            parsed = parse_train_log(log)
            other = next((p for p in procs if p["stage"] != "training"), None)
            model = log.stem.replace("train_", "")
            status = "failed" if parsed["failed"] else ("running" if other else "finished")
            run = {"status": status, "stage": other["stage"] if other else None, "log": str(log),
                   "model": model, "epochs": None, "elapsed_s": None, **parsed}
    s = run.get("steps") or []
    if run.get("status") == "running" and run.get("stage") == "training" and s and run.get("total_steps"):
        done = s[-1]["step"]
        rate = done / max(1, run["elapsed_s"])
        run["rate"] = rate
        run["eta_s"] = (run["total_steps"] - done) / rate if rate else None
    return {"updated": time.strftime("%H:%M:%S"), "ts": time.time(), "run": run, "gpu": gpu(),
            "others": [{"stage": p["stage"], "pid": p["pid"], "elapsed_s": p["elapsed_s"]}
                       for p in procs if p["stage"] != "training"],
            "gates": gate_reports(reports), "target": {"recall": 0.96, "fpr": 0.005}}


def write_atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.training.live")
    parser.add_argument("--reports", default=str(HOME / "reports/v17"))
    parser.add_argument("--out", default=str(HOME / "reports/live"))
    parser.add_argument("--every", type=float, default=4.0)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--log", default=None,
                        help="training log, for a trainer whose stdout is not a file")
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_atomic(out / "index.html", (Path(__file__).parent / "live.html").read_text())
    print(f"open file://{out / 'index.html'}", flush=True)
    while True:
        data = snapshot(Path(args.reports), Path(args.log) if args.log else None)
        write_atomic(out / "live_data.js", "window.LIVE = " + json.dumps(data) + ";\n")
        if args.once:
            return 0
        time.sleep(args.every)


if __name__ == "__main__":
    raise SystemExit(main())
