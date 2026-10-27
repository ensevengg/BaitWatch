"""Pin a trained checkpoint: verify its hash and publish read/model_config.json.

The pin file is what ``read.scan`` reads for the checkpoint path and the
operating thresholds, and what tests/read/test_metrics.py uses as the
regression guard: the quality gates recorded here (min recall / max FPR) must
keep holding on the demo machine for every later checkpoint.

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


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pin(checkpoint: Path, tag: str, min_recall: float | None = None,
        max_fpr: float | None = None, results_path: Path | None = None) -> dict:
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

    gates: dict = {}
    if results_path is not None and Path(results_path).exists():
        results = json.loads(Path(results_path).read_text(encoding="utf-8"))
        recall = results.get("injecagent", {}).get("overall", {}).get("recall_injected_response")
        fpr = results.get("benign_corpus", {}).get("file_fpr")
        if min_recall is None and recall is not None:
            min_recall = round(recall - 0.02, 3)   # small honest margin
        if max_fpr is None and fpr is not None:
            max_fpr = round(fpr + 0.005, 3)
        gates["measured"] = {"recall_injected_response": recall, "file_fpr": fpr}
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
    parser.add_argument("--results", default=None,
                        help="metrics JSON from read.training.evaluate for gate derivation")
    args = parser.parse_args(argv)
    try:
        pin(Path(args.checkpoint), args.tag,
            min_recall=args.min_recall, max_fpr=args.max_fpr,
            results_path=Path(args.results) if args.results else None)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
