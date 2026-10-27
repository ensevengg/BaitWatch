"""Evaluation: the numbers that go in the demo, all from non-training data.

- InjecAgent (frozen, attacks-only): recall on raw attacker instructions and on
  the realistic variant — the instruction embedded in the tool response —
  across all four case files (dh/ds x base/enhanced), with per-Attack-Type
  breakdown on the base sets.
- Benign corpus (local clones, see read.data.benign_corpus): file- and
  repo-level FPR through the *shipped* pipeline — ``read.scan`` itself
  (decoders, blob masking, caps; judge off), one scan per corpus repo.
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
from read.config import ReadConfig, config_from_model_config
from read.data.schema import SPLIT_TEST, read_parquet
from read.detector import Detector

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


def benign_fpr(det: Detector, chunker: Chunker | None, corpus_dir: Path,
               threshold: float, review_low: float | None = None) -> dict:
    """FPR through ``read.scan`` (judge off), one scan per corpus repo.

    ``corpus_dir`` holding repo directories is scanned repo by repo (the
    hook's unit of decision); a directory with files at its top level is
    scanned as a single repo. ``chunker`` is unused (kept for callers).
    """
    from read.scan import scan

    corpus_dir = Path(corpus_dir)
    cfg = config_from_model_config(ReadConfig())
    cfg.judge.enabled = False
    cfg.walker.max_files = 1_000_000
    cfg.flag_threshold = threshold
    if review_low is not None:
        cfg.review_low = review_low
    has_top_files = any(p.is_file() for p in corpus_dir.iterdir())
    repos = [corpus_dir] if has_top_files else sorted(
        p for p in corpus_dir.iterdir() if p.is_dir() and not p.name.startswith("."))

    files = chunks = flagged_chunks = band_chunks = 0
    flagged_files: list[str] = []
    per_repo: dict[str, dict] = {}
    for repo in repos:
        result = scan(repo, cfg, detector=det)
        prefix = "" if repo == corpus_dir else f"{repo.name}/"
        repo_flagged = sorted({prefix + f.file for f in result.flagged})
        flagged_files.extend(repo_flagged)
        files += result.stats.files_scanned
        chunks += result.stats.chunks_scored
        flagged_chunks += len(result.flagged)
        band_chunks += result.stats.reviewed
        per_repo[repo.name] = {
            "files": result.stats.files_scanned,
            "flagged_files": len(repo_flagged),
            "review_band_chunks": result.stats.reviewed,
            "elapsed_s": result.stats.elapsed_s,
        }
    if not files:
        return {"files": 0, "error": "no scannable files"}
    return {
        "files": files,
        "chunks": chunks,
        "flagged_files": len(flagged_files),
        "file_fpr": round(len(flagged_files) / files, 4),
        "chunk_fpr": round(flagged_chunks / max(1, chunks), 4),
        "repos": len(repos),
        "repos_flagged": sum(1 for r in per_repo.values() if r["flagged_files"]),
        "review_band_chunks": band_chunks,
        "per_repo": per_repo,
        "flagged_file_list": flagged_files[:40],
    }


def test_split_metrics(det: Detector, data_dir: Path, threshold: float) -> dict:
    rows = read_parquet(Path(data_dir) / f"{SPLIT_TEST}.parquet")
    if not rows:
        return {}
    scores = det.scores([r.text for r in rows])
    labels = np.array([r.label for r in rows])
    preds = (scores >= threshold).astype(int)

    def prf(pred, truth):
        """P/R/F1 when the slice has attacks; FPR when it has benign rows.

        A benign-only source (e.g. opencodeinstruct) has no recall to speak
        of — reporting P=R=0 there read as a failure; its FPR is the number.
        """
        tp = int(((pred == 1) & (truth == 1)).sum())
        fp = int(((pred == 1) & (truth == 0)).sum())
        fn = int(((pred == 0) & (truth == 1)).sum())
        n_pos, n_neg = int((truth == 1).sum()), int((truth == 0).sum())
        out = {"support": int(len(truth)), "attacks": n_pos, "benign": n_neg}
        if n_pos:
            p = tp / max(1, tp + fp)
            r = tp / n_pos
            out.update(precision=round(p, 4), recall=round(r, 4),
                       f1=round(2 * p * r / max(1e-9, p + r), 4))
        if n_neg:
            out["fpr"] = round(fp / n_neg, 4)
        return out

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
        result["benign_corpus"] = benign_fpr(det, chunker, Path(corpus_dir), flag,
                                             review_low=th.get("review_low"))
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
