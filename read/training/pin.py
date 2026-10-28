"""Pin a trained checkpoint: verify its hash and publish read/model_config.json.

The pin file is what ``read.scan`` reads for the checkpoint path and the
operating thresholds, and what tests/read/test_metrics.py uses as the
regression guard: the quality gates recorded here (min recall / max FPR) must
keep holding on the demo machine for every later checkpoint.

Quality gates follow the roadmap's "no drop vs the previous checkpoint" rule:
by default they are the *previously pinned* checkpoint's measured recall/FPR
(read from the existing pin file before it is overwritten) — never numbers
derived from the checkpoint being pinned, which would pass by construction.
A hard ceiling of 2% benign file FPR is applied only when explicitly
requested (``--hard-fpr-ceiling``). Explicit ``--min-recall``/``--max-fpr``
still override the derived gates.

    python -m read.training.pin <checkpoint> [--tag v1]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

from read.config import MODEL_CONFIG_PATH

# Hard benign-file FPR ceiling, applied only on explicit request
# (--hard-fpr-ceiling). It is NOT the InjecAgent recall bar: that 85% bar is
# for held-out novel attacks, and InjecAgent recall is not held to it here.
HARD_MAX_FILE_FPR = 0.02


def _previous_measured() -> tuple[float | None, float | None]:
    """(recall, file FPR) measured for the currently pinned checkpoint."""
    try:
        prev = json.loads(MODEL_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, None
    gates = prev.get("quality_gates", {}) if isinstance(prev, dict) else {}
    measured = gates.get("measured", {}) if isinstance(gates, dict) else {}
    recall = measured.get("recall_injected_response",
                          gates.get("min_recall_injected_response"))
    fpr = measured.get("file_fpr", gates.get("max_benign_file_fpr"))
    return (float(recall) if recall is not None else None,
            float(fpr) if fpr is not None else None)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pin(checkpoint: Path, tag: str, min_recall: float | None = None,
        max_fpr: float | None = None, results_path: Path | None = None,
        hard_fpr_ceiling: bool = False) -> dict:
    checkpoint = Path(checkpoint).resolve()
    weights = checkpoint / "model.safetensors"
    thresholds_path = checkpoint / "thresholds.json"
    meta_path = checkpoint / "checkpoint_meta.json"
    missing = [str(p) for p in (weights, thresholds_path, meta_path) if not p.exists()]
    if missing:
        raise FileNotFoundError(
            f"checkpoint incomplete, missing {missing} — run tune_threshold first")

    thresholds = json.loads(thresholds_path.read_text(encoding="utf-8"))
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    sha = sha256_file(weights)

    # Read the previous pin before anything overwrites it: its measured
    # numbers are the default gates ("no drop vs the previous checkpoint").
    prev_recall, prev_fpr = _previous_measured()
    explicit_fpr = max_fpr

    gates: dict = {}
    if results_path is not None and Path(results_path).exists():
        results = json.loads(Path(results_path).read_text(encoding="utf-8"))
        recall = results.get("injecagent", {}).get("overall", {}).get("recall_injected_response")
        fpr = results.get("benign_corpus", {}).get("file_fpr")
        # Recorded for information only — never turned into the gate itself.
        gates["measured"] = {"recall_injected_response": recall, "file_fpr": fpr}
    if min_recall is None:
        min_recall = prev_recall
    if max_fpr is None:
        max_fpr = prev_fpr
    if hard_fpr_ceiling and explicit_fpr is None:
        max_fpr = (min(max_fpr, HARD_MAX_FILE_FPR) if max_fpr is not None
                   else HARD_MAX_FILE_FPR)
    if min_recall is not None:
        gates["min_recall_injected_response"] = min_recall
    if max_fpr is not None:
        gates["max_benign_file_fpr"] = max_fpr

    pin_doc = {
        "tag": tag,
        "checkpoint_path": str(checkpoint),
        "checkpoint_sha256": sha,
        "base_model": meta.get("base_model"),
        "base_model_sha256": meta.get("base_model_sha256"),
        "mode": meta.get("mode"),
        "trained_at": meta.get("finished_at"),
        "smoke": meta.get("smoke", False),
        "thresholds": {
            "flag_threshold": thresholds["flag_threshold"],
            "review_low": thresholds["review_low"],
            "hard_high": thresholds.get("hard_high", 0.9),
        },
        "quality_gates": gates,
        "pinned_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    MODEL_CONFIG_PATH.write_text(json.dumps(pin_doc, indent=2), encoding="utf-8")
    print(f"pinned {tag}: {checkpoint}")
    print(f"  sha256 {sha}")
    print(f"  thresholds {pin_doc['thresholds']}")
    if gates:
        print(f"  gates {gates}")
    return pin_doc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.training.pin")
    parser.add_argument("checkpoint")
    parser.add_argument("--tag", default="v1")
    parser.add_argument("--min-recall", type=float, default=None)
    parser.add_argument("--max-fpr", type=float, default=None)
    parser.add_argument("--hard-fpr-ceiling", action="store_true",
                        help="also cap the benign-file FPR gate at 2%% "
                             "(explicit --max-fpr still overrides)")
    parser.add_argument("--results", default=None,
                        help="metrics JSON from read.training.evaluate "
                             "(its numbers are recorded, not turned into gates)")
    args = parser.parse_args(argv)
    try:
        pin(Path(args.checkpoint), args.tag,
            min_recall=args.min_recall, max_fpr=args.max_fpr,
            results_path=Path(args.results) if args.results else None,
            hard_fpr_ceiling=args.hard_fpr_ceiling)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
