"""Tune the operating threshold on the validation split — never on test.

Chooses:
- flag_threshold: the score cutoff maximizing F2 (recall-weighted) subject to
  a chunk-level benign false-positive rate <= --max-fpr (default 2%, the
  roadmap's benign-corpus bar, applied here as a chunk-level proxy).
- review_low: the 95th percentile of benign val scores — the uncertain band
  handed to the judge — clamped to stay a real band below the flag threshold.

Writes thresholds.json next to the checkpoint so ``read.training.pin`` can
publish them into read/model_config.json.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from read.data.schema import SPLIT_VAL, read_parquet
from read.detector import Detector


def tune(scores: np.ndarray, labels: np.ndarray, max_fpr: float = 0.02,
         floor: float = 0.05, ceiling: float = 0.95) -> dict:
    benign = scores[labels == 0]
    attack = scores[labels == 1]
    grid = np.round(np.arange(floor, ceiling + 1e-9, 0.01), 2)

    best = None
    for t in grid:
        fp = float((benign >= t).mean())
        if fp > max_fpr:
            continue
        tp = float((attack >= t).mean())
        precision = tp * len(attack) / max(1e-9, tp * len(attack) + fp * len(benign))
        f2 = 5 * precision * tp / max(1e-9, 4 * precision + tp)
        if best is None or f2 > best["f2"]:
            best = {"flag_threshold": float(t), "f2": f2, "recall": tp, "fpr": fp,
                    "precision": precision}
    if best is None:
        # No cutoff satisfies the FPR bar — report the least-bad option loudly.
        t = float(grid[np.argmin([(benign >= g).mean() for g in grid])])
        best = {"flag_threshold": t, "f2": None, "recall": float((attack >= t).mean()),
                "fpr": float((benign >= t).mean()), "constraint_met": False}
    else:
        best["constraint_met"] = True

    p95 = float(np.percentile(benign, 95)) if len(benign) else floor
    review_low = float(min(max(p95, floor), best["flag_threshold"] - 0.05))
    review_low = max(review_low, 0.01)
    return {
        "flag_threshold": best["flag_threshold"],
        "review_low": round(review_low, 3),
        "hard_high": 0.9,
        "selection": best,
        "val_chunks": int(len(scores)),
        "val_benign": int(len(benign)),
        "val_attack": int(len(attack)),
    }


def tune_checkpoint(checkpoint: Path, data_dir: Path, max_fpr: float = 0.02,
                    batch_size: int = 64) -> dict:
    rows = [r for r in read_parquet(Path(data_dir) / f"{SPLIT_VAL}.parquet")]
    det = Detector(checkpoint, batch_size=batch_size)
    scores = det.scores([r.text for r in rows])
    labels = np.array([r.label for r in rows], dtype=int)
    result = tune(scores, labels, max_fpr=max_fpr)
    out = Path(checkpoint) / "thresholds.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.training.tune_threshold")
    parser.add_argument("checkpoint")
    parser.add_argument("--data-dir",
                        default=str(Path.home() / ".local/share/baitwatch/data"))
    parser.add_argument("--max-fpr", type=float, default=0.02)
    args = parser.parse_args(argv)
    result = tune_checkpoint(Path(args.checkpoint), Path(args.data_dir),
                             max_fpr=args.max_fpr)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
