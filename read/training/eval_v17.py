"""v1.7 gate: file-level recall on held-out attacks at <=0.5% harmless-file FPR.

Every set is scanned with the real ``read.scan`` (decoders, blob masking,
chunking; judge off) and every chunk score is kept, so recall and FPR can be
read at any threshold afterwards:

- gold:      hand-written attacks + harmless lookalikes (read.data.v17.gold)
- suite:     tests/read/fixtures/suite (attack and benign cases)
- aditya:    the five attack-slice repos, answer keys removed
- corpus:    the benign FPR corpus (10 repos) + TEST_REPOS carriers

The gate threshold is the lowest one at which harmless files flagged stay
<= 0.5% over corpus + gold-benign + suite-benign; recall is then reported
for gold, suite and aditya attacks at that threshold and at the model's own.

    python -m read.training.eval_v17 --model <ckpt> --out <json>
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np

import sys

from read.config import ReadConfig, WalkerConfig
from read.decoders import builtin_decoders, load_external_decoders
from read.detector import Detector
from read.scan import scan
from read.training.tracking import log_gate_report

HOME = Path.home() / ".local/share/baitwatch"
REPO = Path(__file__).resolve().parents[2]
TARGET_FPR = 0.005
TARGET_RECALL = 0.96
PLUGIN_ROOT = HOME / "v17_raw/aditya_plugin"
DECODERS: list | None = None


def load_decoders(plugin_root: Path | None) -> list:
    """Built-ins plus Aditya's plugin (staged from his branch until it merges)."""
    decs = builtin_decoders()
    if plugin_root and (plugin_root / "attacks/decoders.py").exists():
        sys.path.insert(0, str(plugin_root))
        decs.extend(load_external_decoders(search_root=plugin_root))
    return decs


WINDOW = (448, 64)        # (window_tokens, overlap_tokens); --window overrides


def _cfg(model: Path, max_files: int = 5_000) -> ReadConfig:
    window, overlap = WINDOW
    cfg = ReadConfig(model_path=model, flag_threshold=1.01, review_low=0.0,
                     score_cache=False, on_file_error="skip",
                     window_tokens=window, overlap_tokens=overlap,
                     # same token coverage per file as the 448-token default
                     max_chunks_per_file=max(64, round(64 * 384 / (window - overlap))))
    cfg.judge.enabled = False
    cfg.walker = WalkerConfig(max_files=max_files)
    return cfg


def file_scores(target: Path, det: Detector, cfg: ReadConfig) -> dict[str, float]:
    """Max chunk score per file the scan reported (files with no chunk are absent)."""
    res = scan(target, cfg, detector=det, decoders=DECODERS)
    out: dict[str, float] = {}
    for f in res:
        if f.layer == "system":
            continue
        out[f.file] = max(out.get(f.file, 0.0), float(f.score))
    return out


def scan_cases(root: Path, det: Detector, cfg: ReadConfig) -> dict[str, dict[str, float]]:
    return {d.name: file_scores(d, det, cfg)
            for d in sorted(p for p in root.iterdir() if p.is_dir())}


def threshold_at_fpr(benign_scores: np.ndarray, target: float) -> float:
    """Smallest threshold with FPR <= target (scores >= t are flagged)."""
    s = np.sort(benign_scores)[::-1]
    k = int(np.floor(target * len(s)))       # allowed false positives
    if k >= len(s):
        return 0.0
    return float(np.nextafter(s[k], 1.0)) if k < len(s) else 0.0


def recall_at(scores: list[float], t: float) -> float:
    return float(np.mean([x >= t for x in scores])) if scores else float("nan")


def evaluate(model: Path, own_threshold: float | None, corpus_max_files: int = 800,
             plugin_root: Path | None = PLUGIN_ROOT) -> dict:
    global DECODERS
    started = time.time()
    DECODERS = load_decoders(plugin_root)
    det = Detector(model, batch_size=32)
    cfg = _cfg(model)

    gold_root = HOME / "gold_v17"
    gold_cases = json.loads((gold_root / "cases.json").read_text())
    gold_scores = {**scan_cases(gold_root / "attack", det, cfg),
                   **scan_cases(gold_root / "benign", det, cfg)}
    # A file the scan never reported (walker skip, key mismatch) is a miss if
    # it is an attack and left out of the harmless pool otherwise; both are
    # listed under "unscanned" so a silent mismatch shows up in the report.
    unscanned: dict[str, list[str]] = {"gold": [], "aditya": [], "agent_files": []}
    gold_attack, gold_benign, gold_rows = [], [], []
    for c in gold_cases:
        s = gold_scores.get(c["case"], {}).get(c["file"])
        if s is None:
            unscanned["gold"].append(c["case"])
            if c["label"] != 1:
                gold_rows.append({**c, "score": None})
                continue
            s = 0.0
        gold_rows.append({**c, "score": s})
        (gold_attack if c["label"] == 1 else gold_benign).append(s)

    suite_root = REPO / "tests/read/fixtures/suite"
    suite_attack = {k: max(v.values(), default=0.0)
                    for k, v in scan_cases(suite_root / "attacks", det, cfg).items()}
    suite_benign_files = [s for v in scan_cases(suite_root / "benign", det, cfg).values()
                          for s in v.values()]

    aditya_root = HOME / "v17_raw/aditya_repos"
    aditya = {}
    if aditya_root.exists():
        for repo in sorted(p for p in aditya_root.iterdir() if p.is_dir()):
            manifest = json.loads((repo / ".manifest.json").read_text())
            scores = file_scores(repo / "tree", det, cfg)
            for e in manifest["entries"]:
                key = f'{repo.name}:{e["file"]}'
                if e["file"] not in scores:
                    unscanned["aditya"].append(key)
                aditya[key] = scores.get(e["file"], 0.0)

    corpus_files: dict[str, float] = {}
    corpus_cfg = _cfg(model, max_files=corpus_max_files)
    for root in (HOME / "benign-corpus", HOME / "v17_raw/carriers/test"):
        for repo in sorted(p for p in root.iterdir() if p.is_dir()):
            for f, s in file_scores(repo, det, corpus_cfg).items():
                corpus_files[f"{repo.name}:{f}"] = s

    # Held-out real agent files (repos never trained on): the harmless voice
    # users hit most, scored one file at a time.
    agent_files: dict[str, float] = {}
    lock_path = HOME / "v17_raw/agentfiles/agentfiles_lock.json"
    if lock_path.exists():
        from read.data.v17.agentfiles import PERMISSIVE, split_for_repo
        from read.data.v17.sources import TEST_REPOS, TRAIN_REPOS
        lock = json.loads(lock_path.read_text())
        for key, meta in sorted(lock["files"].items()):
            if (meta.get("license") in PERMISSIVE
                    and split_for_repo(meta["repo"], TRAIN_REPOS, TEST_REPOS) == "test_planted"):
                path = HOME / "v17_raw/agentfiles/files" / meta["local"]
                scores = file_scores(path, det, cfg)
                if not scores:
                    unscanned["agent_files"].append(key)
                    continue
                agent_files[key] = max(scores.values())

    benign_all = np.array(list(corpus_files.values()) + list(agent_files.values())
                          + gold_benign + suite_benign_files)
    t_gate = threshold_at_fpr(benign_all, TARGET_FPR)

    def block(t: float) -> dict:
        return {
            # Unrounded: rounding down could flag files the 0.5% budget excludes.
            "threshold": t,
            "gold_recall": recall_at(gold_attack, t),
            "gold_missed": [r["case"] for r in gold_rows if r["label"] == 1 and r["score"] < t],
            "suite_recall": recall_at(list(suite_attack.values()), t),
            "suite_missed": [k for k, v in suite_attack.items() if v < t],
            "aditya_recall": recall_at(list(aditya.values()), t),
            "aditya_missed": [k for k, v in aditya.items() if v < t],
            "corpus_file_fpr": float(np.mean([s >= t for s in corpus_files.values()])),
            "agent_file_fpr": (float(np.mean([s >= t for s in agent_files.values()]))
                               if agent_files else None),
            "flagged_agent_files": sorted(k for k, v in agent_files.items() if v >= t)[:40],
            "gold_benign_fpr": recall_at(gold_benign, t),
            "suite_benign_fpr": recall_at(suite_benign_files, t),
            "all_benign_fpr": float(np.mean(benign_all >= t)),
            "flagged_corpus_files": sorted(k for k, v in corpus_files.items() if v >= t)[:60],
        }

    gate = block(t_gate)
    held_out = gold_attack + list(aditya.values())
    report = {
        "model": str(model),
        "decoders": [d.name for d in DECODERS],
        "window": list(WINDOW),
        "targets": {"recall": TARGET_RECALL, "file_fpr": TARGET_FPR},
        "counts": {"gold_attack": len(gold_attack), "gold_benign": len(gold_benign),
                   "suite_attack": len(suite_attack), "suite_benign_files": len(suite_benign_files),
                   "aditya_payload_files": len(aditya), "corpus_files": len(corpus_files),
                   "heldout_agent_files": len(agent_files),
                   **{f"unscanned_{k}": len(v) for k, v in unscanned.items()}},
        "unscanned": unscanned,
        "at_gate_threshold": gate,
        "held_out_recall_at_gate": recall_at(held_out, t_gate),
        "gate_pass": bool(recall_at(held_out, t_gate) >= TARGET_RECALL),
        "gold_scores": gold_rows,
        # Per-file max scores, so review-band sizes can be read at any cutoff.
        "file_scores": {"corpus": corpus_files, "agent_files": agent_files,
                        "suite_benign": suite_benign_files, "suite_attack": suite_attack,
                        "aditya": aditya},
        "elapsed_s": round(time.time() - started, 1),
    }
    if own_threshold is not None:
        report["at_own_threshold"] = block(own_threshold)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.training.eval_v17")
    parser.add_argument("--model", required=True)
    parser.add_argument("--threshold", type=float, default=None,
                        help="the model's own flag threshold (default: thresholds.json)")
    parser.add_argument("--out", required=True)
    parser.add_argument("--corpus-max-files", type=int, default=800)
    parser.add_argument("--window", type=int, nargs=2, default=None, metavar=("TOKENS", "OVERLAP"),
                        help="scan window (default 448 64, the scanner's)")
    parser.add_argument("--mlflow-uri", default=None,
                        help="also log the gate numbers to MLflow (default: $MLFLOW_TRACKING_URI)")
    args = parser.parse_args(argv)
    global WINDOW
    if args.window:
        WINDOW = tuple(args.window)
    model = Path(args.model)
    own = args.threshold
    if own is None and (model / "thresholds.json").exists():
        own = json.loads((model / "thresholds.json").read_text())["flag_threshold"]
    report = evaluate(model, own, args.corpus_max_files)
    Path(args.out).write_text(json.dumps(report, indent=2))
    log_gate_report(args.mlflow_uri, report, Path(args.out).stem)
    g = report["at_gate_threshold"]
    print(json.dumps({"gate_threshold": g["threshold"], "held_out_recall": report["held_out_recall_at_gate"],
                      "gold_recall": g["gold_recall"], "suite_recall": g["suite_recall"],
                      "aditya_recall": g["aditya_recall"], "all_benign_fpr": g["all_benign_fpr"],
                      "gate_pass": report["gate_pass"], "counts": report["counts"],
                      "own": {k: report.get("at_own_threshold", {}).get(k) for k in
                              ("threshold", "gold_recall", "suite_recall", "aditya_recall",
                               "all_benign_fpr")}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
