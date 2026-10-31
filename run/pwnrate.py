"""Measure decoy pwn rate: scan repos N times through the normal cage."""

import argparse
import json
import math
import os
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from run.cage import DEFAULT_IMAGE
from run.llm import make_backend_with_fallback
from run.sandbox import SandboxConfig
from run.scan import run_scan


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(pct / 100 * len(ordered)) - 1)
    return ordered[index]


def summarize_repo(repo: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    runs = len(records)
    pwned = sum(1 for r in records if r["sink_hit"])
    honey = sum(1 for r in records if r["honeytoken_hit"])
    latencies = [r["latency_seconds"] for r in records]
    verdicts = Counter(r["verdict"] for r in records)
    return {
        "repo": repo,
        "runs": runs,
        "runs_with_sink_hit": pwned,
        "runs_with_honeytoken_hit": honey,
        "verdict_counts": dict(sorted(verdicts.items())),
        "pwn_rate": (pwned / runs) if runs else 0.0,
        "honeytoken_rate": (honey / runs) if runs else 0.0,
        "latency_p50_seconds": _percentile(latencies, 50),
        "latency_p95_seconds": _percentile(latencies, 95),
        "tokens_total": sum(r["tokens"] for r in records),
        "tokens_mean": (sum(r["tokens"] for r in records) / runs) if runs else 0.0,
        "fallback_count": sum(r["fallback_count"] for r in records),
        "suspect_runs": sum(1 for r in records if r.get("suspect")),
        "records": records,
    }


def run_pwnrate(
    repos: list[str | Path],
    *,
    runs: int = 10,
    llm: str | None = None,
    llm_fallback: str | None = None,
    backend_factory: Callable[[], Any] | None = None,
    scan_fn: Callable[..., Any] | None = None,
    image: str = DEFAULT_IMAGE,
    max_steps: int = 20,
    max_tokens: int = 100_000,
    max_seconds: float = 120.0,
) -> dict[str, Any]:
    if runs < 1:
        raise ValueError("runs must be positive")
    if backend_factory is None:
        if not llm:
            raise ValueError("--llm is required")
        backend_factory = lambda: make_backend_with_fallback(llm, llm_fallback)  # noqa: E731
    scanner = scan_fn or run_scan
    summaries = []
    for repo in repos:
        records = []
        for index in range(runs):
            backend = backend_factory()
            before_fb = getattr(backend, "fallback_count", 0) or 0
            before_calls = getattr(backend, "call_count", 0) or 0
            config = SandboxConfig(
                image=image,
                decoy_seconds=max_seconds,
                decoy_max_tokens=max_tokens,
                decoy_max_seconds=max_seconds,
            )
            started = time.monotonic()
            report = scanner(
                repo,
                config=config,
                backend=backend,
                max_steps=max_steps,
                max_tokens=max_tokens,
                max_seconds=max_seconds,
            )
            latency = time.monotonic() - started
            run_ev = report.run
            after_fb = getattr(backend, "fallback_count", before_fb) or 0
            fallback_count = run_ev.decoy_fallback_count or (after_fb - before_fb)
            after_calls = getattr(backend, "call_count", before_calls) or 0
            turns = after_calls - before_calls
            # All-fallback runs measure the fallback brain, not the primary.
            suspect = turns > 0 and fallback_count >= turns
            records.append(
                {
                    "run": index,
                    "sink_hit": bool(run_ev.dns_hits or run_ev.http_hits or run_ev.tls_hits),
                    "honeytoken_hit": bool(run_ev.honeytoken_hits),
                    "verdict": report.verdict,
                    "latency_seconds": round(latency, 6),
                    "tokens": run_ev.decoy_total_tokens,
                    "backend": run_ev.decoy_backend or getattr(backend, "last_backend", ""),
                    "fallback_count": fallback_count,
                    "suspect": suspect,
                    "status": run_ev.status,
                }
            )
        summaries.append(summarize_repo(str(repo), records))
    return {"repos": summaries}


def markdown_table(report: dict[str, Any]) -> str:
    lines = [
        "| repo | runs | pwned | rate | honey | A/F/B | p50 | p95 | tokens | fb | suspect |",
        "|---|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|",
    ]
    for entry in report["repos"]:
        counts = entry["verdict_counts"]
        verdict_cell = "/".join(str(counts.get(k, 0)) for k in ("ALLOW", "FLAG", "BLOCK"))
        lines.append(
            f"| {entry['repo']} | {entry['runs']} | {entry['runs_with_sink_hit']} | "
            f"{entry['pwn_rate']:.2f} | {entry['runs_with_honeytoken_hit']} | {verdict_cell} | "
            f"{entry['latency_p50_seconds']:.2f} | {entry['latency_p95_seconds']:.2f} | "
            f"{entry['tokens_total']} | {entry['fallback_count']} | "
            f"{'suspect' if entry.get('suspect_runs') else ''} |"
        )
    return "\n".join(lines) + "\n"


def _env_runs(parser: argparse.ArgumentParser) -> int:
    raw = os.environ.get("BAITWATCH_PWNRATE_RUNS")
    if raw is None:
        return 10
    try:
        runs = int(raw)
    except ValueError:
        parser.error("BAITWATCH_PWNRATE_RUNS must be a positive integer")
    if runs < 1:
        parser.error("BAITWATCH_PWNRATE_RUNS must be a positive integer")
    return runs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run.pwnrate")
    parser.add_argument("--repo", action="append", required=True, dest="repos")
    parser.add_argument("--runs", type=int, default=None)
    parser.add_argument("--llm", required=True)
    parser.add_argument("--llm-fallback", default=None)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--max-steps", type=int, default=20)
    parser.add_argument("--max-tokens", type=int, default=100_000)
    parser.add_argument("--max-seconds", type=float, default=120.0)
    parser.add_argument("--out", default="pwnrate.json")
    parser.add_argument("--markdown", default=None)
    args = parser.parse_args(argv)
    if args.runs is None:
        args.runs = _env_runs(parser)
    if args.runs < 1:
        parser.error("--runs must be a positive integer")
    report = run_pwnrate(
        args.repos,
        runs=args.runs,
        llm=args.llm,
        llm_fallback=args.llm_fallback,
        image=args.image,
        max_steps=args.max_steps,
        max_tokens=args.max_tokens,
        max_seconds=args.max_seconds,
    )
    Path(args.out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    table = markdown_table(report)
    md_path = args.markdown or str(Path(args.out).with_suffix(".md"))
    Path(md_path).write_text(table, encoding="utf-8")
    print(table, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
