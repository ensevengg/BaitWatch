"""Real-world eval suite: documented attack classes vs a benign repo zoo.

Measures, per case, with the pinned detector (judge off, decoders on):

- attacks (suite/attacks/*): caught? which file/layer/decoder, max score
- benign  (suite/benign/*):  any false flags, max score
- latency per case, plus optional quick-mode comparison (--quick)

Writes read/results/suite_report.json and prints tables. Run:
    python -m read.evalsuite [--quick]

This module is the measurement harness for the debrief and for the GPU
regression test (tests/read/test_realworld_suite.py); the fixtures are
hand-written recreations of documented real-world incidents — every payload
targets *.example or 10.13.37.0/24 per the safety-lint rule.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from read.config import ReadConfig, config_from_model_config
from read.scan import scan

SUITE_DIR = Path(__file__).resolve().parents[1] / "tests" / "read" / "fixtures" / "suite"
RESULTS = Path(__file__).resolve().parents[1] / "read" / "results"

ATTACK_DESCS = {
    "cursor-rules-backdoor": "rules-file backdoor, zero-width-hidden payload",
    "mcp-tool-poisoning": "MCP tool-description poisoning (Invariant Labs 2025)",
    "postmark-style-bcc": "silent Bcc exfil in mail lib (postmark-mcp class)",
    "npm-postinstall-worm": "postinstall curl|bash (Shai-Hulud npm-worm class)",
    "workflow-secret-exfil": "GitHub Actions secrets exfil (workflow injection)",
    "git-hook-installer": "git hook installer (roadmap attack class)",
    "fake-install-phish": "curl|sh installer + token phishing README",
    "dependency-confusion": "dependency confusion / slopsquat mirror",
    "issue-bait-injection": "agent-targeted bait inside a mirrored issue",
    "trojan-source-bidi": "Trojan Source bidi override (CVE-2021-42574)",
    "vs-ascii-smuggling": "variation-selector ASCII smuggling",
    "license-check-ransom": "fake policy that social-engineers the agent",
}


def run_suite(quick: bool = False, suite_dir: Path | None = None) -> dict:
    suite_dir = suite_dir or SUITE_DIR
    cfg = config_from_model_config(ReadConfig.quick() if quick else ReadConfig())
    cfg.judge.enabled = False

    cases = []
    for expected in ("attacks", "benign"):
        root = suite_dir / expected
        for case_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            t0 = time.perf_counter()
            result = scan(case_dir, cfg)
            elapsed = time.perf_counter() - t0
            flagged_files = sorted({f.file for f in result.flagged})
            decoders = sorted({f.decoder for f in result.flagged if f.decoder})
            layers = sorted({f.layer for f in result.flagged})
            cases.append({
                "case": case_dir.name,
                "expected": "attack" if expected == "attacks" else "benign",
                "caught": bool(result.flagged),
                # surfaced = at least one finding of any status (flagged or
                # review-band) — nothing silently clean
                "surfaced": len(result.flagged) > 0 or result.stats.reviewed > 0,
                "n_reviewed": result.stats.reviewed,
                "flagged_files": flagged_files,
                "n_flagged_files": len(flagged_files),
                "n_findings": len(result.flagged),
                "max_score": round(result.max_score, 3),
                "decoders": decoders,
                "layers": layers,
                "files": result.stats.files_scanned,
                "chunks": result.stats.chunks_scored,
                "latency_s": round(elapsed, 3),
                "truncated": result.stats.truncated_scan,
                "views_dropped": result.stats.views_dropped,
            })

    attacks = [c for c in cases if c["expected"] == "attack"]
    benign = [c for c in cases if c["expected"] == "benign"]
    caught = [c for c in attacks if c["caught"]]
    surfaced = [c for c in attacks if c["surfaced"]]
    benign_flag_files = sum(c["n_flagged_files"] for c in benign)
    benign_flag_cases = sum(1 for c in benign if c["caught"])
    return {
        "mode": "quick" if quick else "full",
        "model": cfg.model_path and str(cfg.model_path) or "pinned",
        "cases": cases,
        "summary": {
            "attack_cases": len(attacks),
            "attacks_caught": len(caught),
            "attacks_surfaced": len(surfaced),
            "attack_recall_by_case": round(len(caught) / max(1, len(attacks)), 3),
            "benign_cases": len(benign),
            "benign_cases_flagged": benign_flag_cases,
            "benign_files_total": sum(c["files"] for c in benign),
            "benign_files_flagged": benign_flag_files,
            "benign_file_fpr": round(benign_flag_files / max(1, sum(c["files"] for c in benign)), 4),
            "attack_latency_mean_s": round(sum(c["latency_s"] for c in attacks) / max(1, len(attacks)), 3),
            "benign_latency_mean_s": round(sum(c["latency_s"] for c in benign) / max(1, len(benign)), 3),
        },
        "attack_descriptions": ATTACK_DESCS,
    }


def print_report(report: dict) -> None:
    print(f"\n=== mode: {report['mode']} ===")
    print(f"{'case':26} {'exp':7} {'caught':6} {'files':5} {'max':>5}  {'decoders':18} {'lat_s':>6}")
    for c in report["cases"]:
        mark = "✓" if (c["caught"] if c["expected"] == "attack" else not c["caught"]) else "✗"
        print(f"{c['case']:26} {c['expected']:7} {mark:6} "
              f"{c['n_flagged_files']:>2}/{c['files']:<3} {c['max_score']:>5.2f}  "
              f"{','.join(c['decoders']) or '-':18} {c['latency_s']:>6.2f}")
    s = report["summary"]
    print(f"\nattack recall (cases): {s['attacks_caught']}/{s['attack_cases']}"
          f" = {s['attack_recall_by_case']:.0%}")
    print(f"benign false-flag cases: {s['benign_cases_flagged']}/{s['benign_cases']}"
          f" · files: {s['benign_files_flagged']}/{s['benign_files_total']}"
          f" = {s['benign_file_fpr']:.1%}")
    print(f"mean latency: attacks {s['attack_latency_mean_s']}s · benign {s['benign_latency_mean_s']}s")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.evalsuite")
    parser.add_argument("--quick", action="store_true",
                        help="also run + report the quick (inline-hook) preset")
    parser.add_argument("--out", default=str(RESULTS / "suite_report.json"))
    args = parser.parse_args(argv)

    report = run_suite(quick=False)
    print_report(report)
    if args.quick:
        quick_report = run_suite(quick=True)
        print_report(quick_report)
        report["quick"] = quick_report
    RESULTS.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nreport written: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
