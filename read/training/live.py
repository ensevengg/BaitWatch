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
          ("read.training.eval_v17", "gate eval"), ("read.training.eval_redteam", "red-team eval"),
          ("read.data.v17.build", "building data"))
STAMPED_RE = re.compile(r"^\d{4}-\d\d-\d\dT")
TRAIN_MARK_RE = re.compile(r"^\S+ train (\S+)")


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
    steps, vals, total, failed, last_step = [], [], None, False, 0
    try:
        text = path.read_text(errors="replace") if path else ""
    except OSError:
        return {"steps": [], "val": [], "total_steps": None, "failed": False}
    for line in text.splitlines():
        m = STEP_RE.match(line)
        if m:
            ep, st, total, loss = int(m[1]), int(m[2]), int(m[3]), float(m[4])
            # A chain appends every run to one log: show only the newest run.
            if not steps or st <= last_step:
                steps, vals, failed = [], [], False
            last_step = st
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


def gate_reports(reports: Path, prefix: str = "") -> list[dict]:
    rows = []
    for p in sorted(reports.glob("*.json")):
        try:
            r = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        g = r.get("at_gate_threshold")
        if not g:
            continue
        name = prefix + p.stem if prefix else p.stem.replace("baseline_", "")
        rows.append({"name": name, "held_out": r.get("held_out_recall_at_gate"),
                     "gold": g.get("gold_recall"), "suite": g.get("suite_recall"),
                     "aditya": g.get("aditya_recall"), "fpr": g.get("all_benign_fpr"),
                     "threshold": g.get("threshold"), "pass": r.get("gate_pass"),
                     "mtime": p.stat().st_mtime})
    rows.sort(key=lambda r: r["mtime"])
    return rows


def redteam_reports(root: Path, prefix: str = "") -> list[dict]:
    """GLM red-team results: one row per model, zcode and opencode sets side by side."""
    rows: dict[str, dict] = {}
    for p in root.glob("*_*.json"):
        name, _, rt_set = p.stem.rpartition("_")
        if rt_set not in ("zcode", "opencode"):
            continue
        try:
            a = json.loads(p.read_text())["at_flag"]
        except (OSError, json.JSONDecodeError, KeyError):
            continue
        r = rows.setdefault(name, {"name": prefix + name, "mtime": 0.0})
        r[rt_set] = {"recall": a["recall"]["all"]["rate"], "ff": a["false_flag"]["all"]["rate"]}
        r["threshold"] = a.get("threshold")
        r["mtime"] = max(r["mtime"], p.stat().st_mtime)
    return sorted(rows.values(), key=lambda r: r["mtime"])


def chain_log(reports: Path, lines: int = 14, extra: tuple[Path, ...] = ()) -> dict | None:
    """Tail of the newest chain log: the stage-by-stage view of a chained job."""
    # A queued chain's log exists (empty) before it starts: skip it.
    found = [*reports.glob("run_*.log"), *(p for d in extra for p in d.glob("chain*.log"))]
    logs = sorted((p for p in found if _has_stages(p)), key=lambda p: p.stat().st_mtime)
    if not logs:
        return None
    try:
        text = logs[-1].read_text(errors="replace").splitlines()
    except OSError:
        return None
    # Chain logs that also carry trainer stdout: keep the time-stamped stage lines.
    stamped = [line for line in text if STAMPED_RE.match(line)]
    text = stamped or text
    return {"name": logs[-1].name, "lines": text[-lines:], "mtime": logs[-1].stat().st_mtime}


def _has_stages(path: Path) -> bool:
    """False for a queued chain's log, which exists but is still empty."""
    try:
        return path.stat().st_size > 0
    except OSError:
        return False


def _chain_model(text: str, fallback: str) -> str:
    marks = [m[1] for m in map(TRAIN_MARK_RE.match, text.splitlines()) if m]
    return marks[-1] if marks else fallback


def snapshot(reports: Path, log_override: Path | None = None,
             extra: tuple[Path, ...] = ()) -> dict:
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
        chains = [p for d in extra for p in d.glob("chain*.log") if parse_train_log(p)["steps"]]
        logs = sorted((*reports.glob("train_*.log"), *chains), key=lambda p: p.stat().st_mtime)
        if logs:
            log = logs[-1]
            parsed = parse_train_log(log)
            other = next((p for p in procs if p["stage"] != "training"), None)
            model = log.stem.replace("train_", "")
            if log in chains:
                model = _chain_model(log.read_text(errors="replace"), model)
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
            "gates": sorted((*gate_reports(reports),
                             *(r for d in extra for r in gate_reports(d, f"{d.name}/"))),
                            key=lambda r: r["mtime"]),
            "target": {"recall": 0.96, "fpr": 0.005},
            "redteam": sorted((*redteam_reports(reports.parent / "redteam"),
                               *(r for d in extra for r in redteam_reports(d, f"{d.name}/"))),
                              key=lambda r: r["mtime"]),
            "chain": chain_log(reports, extra=extra),
            "log_mtime": _mtime(run.get("log"))}


def _mtime(path: str | None) -> float | None:
    try:
        return Path(path).stat().st_mtime if path else None
    except OSError:
        return None


def serve(out: Path, host: str, port: int) -> None:
    """Static server for the page, so it also refreshes in viewers that block file:// scripts."""
    import functools
    import threading
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

    class Handler(SimpleHTTPRequestHandler):
        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def log_message(self, *a):
            pass

    httpd = ThreadingHTTPServer((host, port), functools.partial(Handler, directory=str(out)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()


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
    parser.add_argument("--serve", type=int, default=None, metavar="PORT",
                        help="also serve the page on http://HOST:PORT")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--extra-reports", action="append", default=[], metavar="DIR",
                        help="another folder of gate/red-team JSONs and chain*.log; repeatable")
    parser.add_argument("--log", default=None,
                        help="training log, for a trainer whose stdout is not a file")
    args = parser.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_atomic(out / "index.html", (Path(__file__).parent / "live.html").read_text())
    print(f"open file://{out / 'index.html'}", flush=True)
    if args.serve:
        serve(out, args.host, args.serve)
        print(f"open http://{args.host}:{args.serve}/", flush=True)
    while True:
        data = snapshot(Path(args.reports), Path(args.log) if args.log else None,
                        tuple(Path(d) for d in args.extra_reports))
        write_atomic(out / "live_data.js", "window.LIVE = " + json.dumps(data) + ";\n")
        if args.once:
            return 0
        time.sleep(args.every)


if __name__ == "__main__":
    raise SystemExit(main())
