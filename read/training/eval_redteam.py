"""Score a model on the GLM red-team set (read.data.v17.redteam).

Reports recall and false-flag rate at the pinned flag threshold and at the
judge band floor (review_low), split by category, shape (snippet / whole
file) and strength. Judge off, decoders on, same scan config as eval_v17.

    python -m read.training.eval_redteam --model <dir> --set <built set> --out report.json
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from read.config import load_model_config, resolve_model_path
from read.detector import Detector
from read.training import eval_v17
from read.training.eval_v17 import PLUGIN_ROOT, _cfg, load_decoders, scan_cases


def _rate(xs: list[bool]) -> float | None:
    return round(sum(xs) / len(xs), 4) if xs else None


def summarize(rows: list[dict], t: float) -> dict:
    """Recall and false-flag rate at threshold ``t``.

    An attack with no score counts as a miss. A harmless file with no score was
    never evaluated, so it stays out of the false-flag rate.
    """
    groups: dict[str, list[bool]] = defaultdict(list)
    for r in rows:
        if r["label"] != 1 and r["score"] is None:
            continue
        hit = r["score"] is not None and r["score"] >= t
        side = "recall" if r["label"] == 1 else "false_flag"
        lang = "en" if r["lang"] == "en" else "other"
        for key in ("all", r["intent"], f"{r['intent']}/{r['shape']}", f"shape:{r['shape']}",
                    f"strength:{r['strength']}", f"lang:{lang}"):
            groups[f"{side}|{key}"].append(hit)
    out: dict = {"threshold": t}
    for k in sorted(groups):
        side, key = k.split("|")
        out.setdefault(side, {})[key] = {"rate": _rate(groups[k]), "n": len(groups[k])}
    out["missed"] = [r["case"] for r in rows if r["label"] == 1
                     and (r["score"] is None or r["score"] < t)]
    out["false_flags"] = [r["case"] for r in rows if r["label"] == 0
                          and r["score"] is not None and r["score"] >= t]
    return out


def resolve_thresholds(flag: float | None, review: float | None, model: Path | None,
                       pinned: dict) -> tuple[float, float]:
    """Command line first, then an explicit model's own thresholds, then the pin."""
    own: dict = {}
    if model is not None and (model / "thresholds.json").exists():
        own = json.loads((model / "thresholds.json").read_text(encoding="utf-8"))
    found = {**pinned, **own}
    if flag is None and "flag_threshold" not in found:
        raise ValueError("no flag threshold found: pass --flag or pin a model")
    if review is None and "review_low" not in found:
        raise ValueError("no review threshold found: pass --review or pin a model")
    return (float(found["flag_threshold"]) if flag is None else flag,
            float(found["review_low"]) if review is None else review)


def evaluate(model: Path, root: Path, flag: float, review: float) -> dict:
    eval_v17.DECODERS = load_decoders(PLUGIN_ROOT)
    cfg = _cfg(model)
    det = Detector(model, batch_size=32)
    cases = json.loads((root / "cases.json").read_text())
    scores = {**scan_cases(root / "attack", det, cfg), **scan_cases(root / "benign", det, cfg)}
    rows, unscanned = [], []
    for c in cases:
        s = scores.get(c["case"], {}).get(c["file"])
        if s is None:
            unscanned.append(c["case"])
        rows.append({**c, "score": s})

    return {"model": str(model), "set": str(root), "n": len(rows),
            "unscanned": unscanned, "at_flag": summarize(rows, flag), "at_review": summarize(rows, review),
            "rows": rows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.training.eval_redteam")
    parser.add_argument("--model", default=None, help="checkpoint dir (default: pinned)")
    parser.add_argument("--set", required=True, help="a set built by read.data.v17.redteam")
    parser.add_argument("--flag", type=float, default=None)
    parser.add_argument("--review", type=float, default=None)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    pinned = (load_model_config() or {}).get("thresholds", {})
    model = resolve_model_path(args.model)
    try:
        flag, review = resolve_thresholds(args.flag, args.review,
                                          model if args.model else None, pinned)
    except ValueError as exc:
        parser.error(str(exc))
    rep = evaluate(model, Path(args.set), flag, review)
    Path(args.out).write_text(json.dumps(rep, indent=1, ensure_ascii=False))
    for name in ("at_flag", "at_review"):
        b = rep[name]
        print(f"{name} t={b['threshold']}: recall {b['recall']['all']} "
              f"false_flag {b.get('false_flag', {}).get('all')}")
        for k, v in b["recall"].items():
            if k != "all":
                print(f"  {k:32s} {v['rate']}  (n={v['n']})")
    print("unscanned:", rep["unscanned"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
