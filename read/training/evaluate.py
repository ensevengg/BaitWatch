"""Evaluation: the numbers that go in the demo, all from non-training data.

- InjecAgent (frozen, attacks-only): recall on raw attacker instructions and on
  the realistic variant — the instruction embedded in the tool response —
  across all four case files (dh/ds x base/enhanced), with per-Attack-Type
  breakdown on the base sets.
- Benign corpus (local clones, see read.data.benign_corpus): file-level FPR
  through the *shipped* pipeline (decoders on, judge off).
- Test split: per-source precision/recall/F1 at the pinned threshold.

    python -m read.training.evaluate <checkpoint> --out read/results/v1_metrics.json
"""

from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path

import numpy as np

from read.chunking import Chunker
from read.config import ReadConfig
from read.data.schema import SPLIT_TEST, read_parquet
from read.decoders import builtin_decoders, produce_views
from read.detector import Detector
from read.walk import walk

INJECAGENT_DIR = Path(__file__).resolve().parents[2] / "injectionagent" / "InjecAgent" / "data"
CASE_FILES = {
    "dh_base": "test_cases_dh_base.json",
    "dh_enhanced": "test_cases_dh_enhanced.json",
    "ds_base": "test_cases_ds_base.json",
    "ds_enhanced": "test_cases_ds_enhanced.json",
}


def _injected_response(item: dict) -> str:
    resp = item.get("Tool Response") or item["Tool Response Template"].replace(
        "<Attacker Instruction>", item["Attacker Instruction"])
    return resp


def injecagent_recall(det: Detector, threshold: float) -> dict:
    out: dict = {"variants": {}, "by_attack_type_base": {}}
    raw_texts, raw_ok = [], 0
    resp_texts, resp_ok = [], 0
    per_type = defaultdict(lambda: [0, 0])

    for variant, fname in CASE_FILES.items():
        p = INJECAGENT_DIR / fname
        if not p.exists():
            continue
        items = json.loads(p.read_text(encoding="utf-8"))
        batch_raw = [it["Attacker Instruction"] for it in items]
        batch_resp = [_injected_response(it) for it in items]
        s_raw = det.scores(batch_raw)
        s_resp = det.scores(batch_resp)
        k_raw = int((s_raw >= threshold).sum())
        k_resp = int((s_resp >= threshold).sum())
        out["variants"][variant] = {
            "n": len(items),
            "recall_raw": round(k_raw / len(items), 4),
            "recall_injected_response": round(k_resp / len(items), 4),
        }
        raw_texts.extend(batch_raw)
        raw_ok += k_raw
        resp_texts.extend(batch_resp)
        resp_ok += k_resp
        if variant.endswith("base"):
            for it, s in zip(items, s_resp):
                per_type[it.get("Attack Type", "unknown")][0] += 1
                per_type[it.get("Attack Type", "unknown")][1] += int(s >= threshold)

    total = len(raw_texts) or 1
    out["overall"] = {
        "n": total,
        "recall_raw": round(raw_ok / total, 4),
        "recall_injected_response": round(resp_ok / total, 4),
        "mean_score_raw": round(float(np.mean(det.scores(raw_texts))) if raw_texts else 0.0, 4),
    }
    out["by_attack_type_base"] = {
        k: {"n": v[0], "recall_injected_response": round(v[1] / v[0], 4)}
        for k, v in sorted(per_type.items())
    }
    return out


def benign_fpr(det: Detector, chunker: Chunker, corpus_dir: Path,
               threshold: float, max_file_bytes: int = 262_144) -> dict:
    files = walk(corpus_dir).files
    chunk_texts: list[str] = []
    chunk_owner: list[str] = []
    for f in files:
        raw = f.path.read_bytes()[:max_file_bytes]
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            continue
        views = produce_views(text, builtin_decoders())
        for v in views:
            chunks, _ = chunker.chunk(v.text, f.rel_path, view=v.decoder or "original")
            for c in chunks:
                chunk_texts.append(c.text)
                chunk_owner.append(f.rel_path)

    if not chunk_texts:
        return {"files": 0, "error": "no scannable files"}
    scores = det.scores(chunk_texts)
    per_file = defaultdict(float)
    for owner, s in zip(chunk_owner, scores):
        per_file[owner] = max(per_file[owner], float(s))
    flagged_files = [name for name, s in per_file.items() if s >= threshold]
    flagged_chunks = int((scores >= threshold).sum())
    return {
        "files": len(files),
        "chunks": len(chunk_texts),
        "flagged_files": len(flagged_files),
        "file_fpr": round(len(flagged_files) / max(1, len(files)), 4),
        "chunk_fpr": round(flagged_chunks / len(chunk_texts), 4),
        "flagged_file_list": flagged_files[:20],
    }


def test_split_metrics(det: Detector, data_dir: Path, threshold: float) -> dict:
    rows = read_parquet(Path(data_dir) / f"{SPLIT_TEST}.parquet")
    if not rows:
        return {}
    scores = det.scores([r.text for r in rows])
    labels = np.array([r.label for r in rows])
    preds = (scores >= threshold).astype(int)

    def prf(pred, truth):
        tp = int(((pred == 1) & (truth == 1)).sum())
        fp = int(((pred == 1) & (truth == 0)).sum())
        fn = int(((pred == 0) & (truth == 1)).sum())
        p = tp / max(1, tp + fp)
        r = tp / max(1, tp + fn)
        f1 = 2 * p * r / max(1e-9, p + r)
        return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
                "support": int(len(truth))}

    by_source = defaultdict(lambda: ([], []))
    for r, p, l in zip(rows, preds, labels):
        by_source[r.source][0].append(p)
        by_source[r.source][1].append(l)
    return {
        "threshold": threshold,
        "overall": prf(preds, labels),
        "by_source": {src: prf(np.array(ps), np.array(ls))
                      for src, (ps, ls) in sorted(by_source.items())},
    }


def evaluate(checkpoint: Path, data_dir: Path, corpus_dir: Path | None,
             thresholds: dict | None = None, batch_size: int = 64) -> dict:
    cfg = ReadConfig()
    th = thresholds or {}
    flag = float(th.get("flag_threshold", cfg.flag_threshold))

    det = Detector(checkpoint, batch_size=batch_size)
    chunker = Chunker(det.tokenizer, window_tokens=cfg.window_tokens,
                      overlap_tokens=cfg.overlap_tokens)

    started = time.time()
    result = {
        "checkpoint": str(checkpoint),
        "thresholds": th,
        "computed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "injecagent": injecagent_recall(det, flag),
        "test_split": test_split_metrics(det, Path(data_dir), flag),
    }
    if corpus_dir is not None and Path(corpus_dir).exists():
        result["benign_corpus"] = benign_fpr(det, chunker, Path(corpus_dir), flag)
    result["elapsed_s"] = round(time.time() - started, 1)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.training.evaluate")
    parser.add_argument("checkpoint")
    parser.add_argument("--data-dir",
                        default=str(Path.home() / ".local/share/baitwatch/data"))
    parser.add_argument("--corpus-dir", default=None,
                        help="local clone of the benign corpus (optional)")
    parser.add_argument("--thresholds", default=None,
                        help="path to thresholds.json (defaults to checkpoint's)")
    parser.add_argument("--out", default=None, help="write the JSON report here")
    args = parser.parse_args(argv)

    th_path = Path(args.thresholds) if args.thresholds else Path(args.checkpoint) / "thresholds.json"
    th = json.loads(th_path.read_text(encoding="utf-8")) if th_path.exists() else None
    result = evaluate(Path(args.checkpoint), Path(args.data_dir),
                      Path(args.corpus_dir) if args.corpus_dir else None, th)
    text = json.dumps(result, indent=2)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"written: {args.out}")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
