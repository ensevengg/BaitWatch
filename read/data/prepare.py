"""Build the training seed set: parquet splits with dedupe done before splitting.

Sources (all licensed, see read/docs/DATA.md; download scripts live with the
raw paths below — no raw data is ever committed to the repo):

- prodnull (prompt-injection-repo-dataset, Apache-2.0): 5,671 repo-file-voice
  rows {text, label} — the only source whose malicious rows sound like repo
  files, so its ~2.9k malicious rows carry a lot of weight.
- llmail-inject (MIT): dict keyed by email text -> {attack_attempt}. True=1,
  False=0, Unclear dropped. Attacks are subsampled (they dwarf everything).
- OpenCodeInstruct (CC-BY-4.0): benign code voice from the ``output`` column.

Dedupe (roadmap D2): exact on normalized text, then near-duplicate via
banded MinHash over word 3-gram shingles (Jaccard >= 0.9) — always across the
whole pool, before any split, so no near-copy straddles train/val/test.

Splits: stratified 80/10/10 by (source, label) with a fixed seed.
muse_spark rows (Muse Spark pilot, D2) can be passed via --extra-train; they
are forced to train/val only — the schema rejects them in test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from read.data.schema import (SPLIT_TEST, SPLIT_TRAIN, SPLIT_VAL, Row,
                              normalize_for_dedupe, read_jsonl,
                              text_sha256, write_parquet)

_DATA_ROOT = Path(os.environ.get("BAITWATCH_DATA_ROOT", str(Path.home() / "hf_datasets")))

DEFAULT_RAW_DIRS = {
    "prodnull": _DATA_ROOT / "prompt-injection-repo-dataset" / "train.jsonl",
    "llmail": _DATA_ROOT / "microsoft-llmail-inject-challenge" / "data",
    "opencodeinstruct": _DATA_ROOT / "NVIDIA-OpencodeInstruct" / "data",
}


# -- source loaders ----------------------------------------------------------

def load_prodnull(path: Path) -> list[Row]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            rows.append(Row(text=d["text"], label=int(d["label"]),
                            source="prodnull", split=SPLIT_TRAIN))
    return rows


def load_llmail(data_dir: Path, max_attacks: int, seed: int) -> list[Row]:
    by_key: dict[str, dict] = {}
    for phase in (1, 2):
        p = data_dir / f"labelled_unique_submissions_phase{phase}.json"
        data = json.loads(p.read_text(encoding="utf-8"))
        for text, v in data.items():
            if isinstance(text, str) and text.strip():
                aa = v.get("attack_attempt")
                if isinstance(aa, list):
                    aa = aa[0] if aa else "Unclear"
                by_key[text] = {"phase": phase, "attack_attempt": aa,
                                "reason": v.get("reason")}

    benign = [Row(t, 0, "llmail", SPLIT_TRAIN) for t, v in by_key.items()
              if v["attack_attempt"] == "False"]
    attacks = [(t, v) for t, v in by_key.items() if v["attack_attempt"] == "True"]

    # Stratify the attack subsample by challenge phase + reason.
    strata: dict[tuple, list] = defaultdict(list)
    for t, v in attacks:
        strata[(v["phase"], str(v.get("reason")))].append(t)
    rng = random.Random(seed)
    picked: list[str] = []
    per_stratum = Counter()
    if attacks:
        take = min(max_attacks, len(attacks))
        weights = {k: len(v) for k, v in strata.items()}
        total = sum(weights.values())
        for k, v in strata.items():
            n = round(take * weights[k] / total)
            per_stratum[k] = n
            picked.extend(rng.sample(v, min(n, len(v))))
    attack_rows = [Row(t, 1, "llmail", SPLIT_TRAIN) for t in picked]
    return benign + attack_rows


def load_opencodeinstruct(data_dir: Path, max_rows: int, seed: int) -> list[Row]:
    import pyarrow.parquet as pq

    shards = sorted(data_dir.glob("train-*.parquet"))
    if not shards:
        return []
    texts: list[str] = []
    for shard in shards:
        if len(texts) >= max_rows * 3:
            break
        col = pq.read_table(shard, columns=["output"]).column("output").to_pylist()
        texts.extend(t for t in col if isinstance(t, str) and 64 <= len(t) <= 4_000)
    rng = random.Random(seed)
    rng.shuffle(texts)
    return [Row(t, 0, "opencodeinstruct", SPLIT_TRAIN) for t in texts[:max_rows]]


# -- dedupe -------------------------------------------------------------------

_SHINGLE_K = 3          # word 3-grams
_SIG_LEN = 64
_BANDS, _ROWS = 16, 4   # 16x4 catches Jaccard >= ~0.9 with few false candidates
_MERSENNE = (1 << 61) - 1


def _shingle_hashes(text: str) -> np.ndarray:
    words = normalize_for_dedupe(text).split()
    grams = (" ".join(words[i: i + _SHINGLE_K]) for i in range(max(1, len(words) - _SHINGLE_K + 1)))
    return np.fromiter(
        (int.from_bytes(hashlib.blake2b(g.encode("utf-8"), digest_size=8).digest(), "big")
         for g in grams),
        dtype=np.uint64)


class MinHashDeduper:
    def __init__(self, threshold: float = 0.9, seed: int = 42):
        self.threshold = threshold
        rng = np.random.default_rng(seed)
        self.a = rng.integers(1, _MERSENNE, size=_SIG_LEN, dtype=np.uint64)
        self.b = rng.integers(0, _MERSENNE, size=_SIG_LEN, dtype=np.uint64)
        self._buckets: dict[bytes, list[int]] = defaultdict(list)
        self._sigs: list[np.ndarray] = []
        self._shingles: list[set[bytes]] = []

    def signature(self, hashes: np.ndarray) -> np.ndarray:
        if hashes.size == 0:
            return np.zeros(_SIG_LEN, dtype=np.uint64)
        return ((self.a[None, :] * hashes[: , None] + self.b[None, :]) % np.uint64(_MERSENNE)).min(axis=0)

    def match(self, text: str) -> bool:
        """Query-only: does text near-duplicate anything already indexed?"""
        sh = {h.tobytes() for h in _shingle_hashes(text)}
        sig = self.signature(_shingle_hashes(text))
        for band in range(_BANDS):
            key = sig[band * _ROWS: (band + 1) * _ROWS].tobytes()
            for other in self._buckets.get(key, ()):
                inter = len(sh & self._shingles[other])
                union = len(sh | self._shingles[other])
                if union and inter / union >= self.threshold:
                    return True
        return False

    def add(self, text: str) -> None:
        """Index text for future match() queries."""
        sig = self.signature(_shingle_hashes(text))
        idx = len(self._sigs)
        self._sigs.append(sig)
        self._shingles.append({h.tobytes() for h in _shingle_hashes(text)})
        for band in range(_BANDS):
            key = sig[band * _ROWS: (band + 1) * _ROWS].tobytes()
            self._buckets[key].append(idx)

    def is_duplicate(self, text: str) -> bool:
        dup = self.match(text)
        if not dup:
            self.add(text)
        return dup


def dedupe(rows: list[Row]) -> tuple[list[Row], dict]:
    """Exact pass first, then near-dup; first occurrence wins."""
    seen_exact: set[str] = set()
    stage1: list[Row] = []
    exact_dups = 0
    for r in rows:
        h = text_sha256(r.text)
        if h in seen_exact:
            exact_dups += 1
            continue
        seen_exact.add(h)
        stage1.append(r)

    near = MinHashDeduper()
    kept: list[Row] = []
    near_dups = 0
    for r in stage1:
        if near.is_duplicate(r.text):
            near_dups += 1
            continue
        kept.append(r)
    stats = {"input_rows": len(rows), "exact_duplicates": exact_dups,
             "near_duplicates": near_dups, "kept": len(kept)}
    return kept, stats


# -- splitting ----------------------------------------------------------------

def stratified_split(rows: list[Row], seed: int = 42,
                     fracs=(0.8, 0.1, 0.1)) -> list[Row]:
    """80/10/10 stratified by (source, label). muse_spark never in test."""
    rng = random.Random(seed)
    strata: dict[tuple, list[Row]] = defaultdict(list)
    for r in rows:
        r.split = SPLIT_TRAIN
        strata[(r.source, r.label)].append(r)

    for key, group in strata.items():
        rng.shuffle(group)
        n = len(group)
        n_val = int(n * fracs[1])
        n_test = 0 if key[0] == "muse_spark" else int(n * fracs[2])
        for r in group[:n_val]:
            r.split = SPLIT_VAL
        for r in group[n_val: n_val + n_test]:
            r.split = SPLIT_TEST
    return rows


def _sha256_file(path: Path) -> str:
    path = Path(path)
    if path.is_dir():
        h = hashlib.sha256()
        for child in sorted(path.rglob("*")):
            if child.is_file():
                h.update(child.name.encode("utf-8"))
                h.update(_sha256_file(child).encode("utf-8"))
        return h.hexdigest()
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# -- main ---------------------------------------------------------------------

def build_seed_set(out_dir: Path, raw: dict[str, Path] | None = None,
                   llmail_max_attacks: int = 10_000, opencode_max: int = 4_000,
                   seed: int = 42,
                   extra_train: list[Path] | None = None) -> dict:
    raw = raw or DEFAULT_RAW_DIRS
    started = time.time()
    rows: list[Row] = []
    sources_meta: dict[str, dict] = {}

    prodnull_path = Path(raw["prodnull"])
    if prodnull_path.exists():
        r = load_prodnull(prodnull_path)
        rows.extend(r)
        sources_meta["prodnull"] = {"rows": len(r), "path": str(prodnull_path)}
    else:
        print(f"warning: prodnull not found at {prodnull_path}", file=sys.stderr)

    llmail_dir = Path(raw["llmail"])
    if llmail_dir.exists():
        r = load_llmail(llmail_dir, llmail_max_attacks, seed)
        rows.extend(r)
        n_attack = sum(1 for x in r if x.label == 1)
        sources_meta["llmail"] = {"rows": len(r), "attacks": n_attack,
                                  "benign": len(r) - n_attack, "path": str(llmail_dir)}
    else:
        print(f"warning: llmail not found at {llmail_dir}", file=sys.stderr)

    oc_path = Path(raw["opencodeinstruct"])
    if oc_path.exists():
        r = load_opencodeinstruct(oc_path, opencode_max, seed)
        rows.extend(r)
        sources_meta["opencodeinstruct"] = {"rows": len(r), "path": str(oc_path)}
    else:
        print(f"warning: opencodeinstruct not found at {oc_path}", file=sys.stderr)

    for extra in (extra_train or []):
        r = read_jsonl(extra)
        for row in r:
            if row.split == SPLIT_TEST:
                raise ValueError(f"{extra}: extra rows must not target the test split")
            row.split = SPLIT_TRAIN
        rows.extend(r)
        sources_meta[f"extra:{extra.name}"] = {"rows": len(r), "path": str(extra)}

    kept, dedupe_stats = dedupe(rows)
    stratified_split(kept, seed=seed)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    splits = {SPLIT_TRAIN: [], SPLIT_VAL: [], SPLIT_TEST: []}
    for r in kept:
        splits[r.split].append(r)
    for name, group in splits.items():
        write_parquet(group, out_dir / f"{name}.parquet")

    manifest = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "seed": seed,
        "sources": sources_meta,
        "dedupe": dedupe_stats,
        "counts": {name: {"rows": len(g),
                          "label_1": sum(1 for r in g if r.label == 1),
                          "by_source": dict(Counter(r.source for r in g))}
                   for name, g in splits.items()},
        "input_hashes": {k: _sha256_file(v) for k, v in raw.items()
                         if Path(v).exists()},
        "elapsed_s": round(time.time() - started, 1),
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def merge_extra_train(data_dir: Path, extra_files: list[Path], out_dir: Path) -> dict:
    """Add extra rows (muse_spark pilot, obfuscation rows, patches) to the
    training split ONLY — val and test parquets are copied through untouched so
    every model version is measured on the identical frozen splits."""
    from read.data.schema import read_parquet, write_parquet

    data_dir, out_dir = Path(data_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    train = read_parquet(data_dir / "train.parquet")
    for split in ("val", "test"):
        write_parquet(read_parquet(data_dir / f"{split}.parquet"), out_dir / f"{split}.parquet")

    existing_hashes = {text_sha256(r.text) for r in train}
    near = MinHashDeduper()
    for split in ("train", "val", "test"):
        # Near-dups must not straddle splits, so val/test index as references
        # (query-only) even though only train grows.
        for r in read_parquet(data_dir / f"{split}.parquet"):
            near.add(r.text)
    added, dropped = 0, 0
    for path in (extra_files or []):
        for row in read_jsonl(path):
            if row.split == SPLIT_TEST:
                raise ValueError(f"{path}: extra rows must not target the test split")
            row.split = SPLIT_TRAIN
            if text_sha256(row.text) in existing_hashes or near.match(row.text):
                dropped += 1
                continue
            train.append(row)
            existing_hashes.add(text_sha256(row.text))
            added += 1
    write_parquet(train, out_dir / "train.parquet")
    manifest = {
        "merged_from": str(data_dir),
        "extra_files": [str(p) for p in (extra_files or [])],
        "train_rows_before": len(train) - added,
        "added": added,
        "dropped_as_duplicate": dropped,
        "train_rows_after": len(train),
        "val_test_untouched": True,
    }
    (out_dir / "merge_manifest.json").write_text(json.dumps(manifest, indent=2),
                                                 encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="read.data.prepare", description="Build BaitWatch training splits")
    parser.add_argument("--out-dir",
                        default=str(Path.home() / ".local/share/baitwatch/data"))
    parser.add_argument("--llmail-max-attacks", type=int, default=10_000)
    parser.add_argument("--opencode-max", type=int, default=4_000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--extra-train", nargs="*", default=[],
                        help="JSONL files (e.g. muse_spark rows) merged into train only")
    parser.add_argument("--merge-mode", action="store_true",
                        help="copy --data-dir splits to --out-dir with --extra-train "
                             "merged into train; val/test are left untouched")
    parser.add_argument("--data-dir", default=None,
                        help="source split dir for --merge-mode")
    args = parser.parse_args(argv)
    if args.merge_mode:
        manifest = merge_extra_train(Path(args.data_dir),
                                     [Path(p) for p in args.extra_train],
                                     Path(args.out_dir))
        print(json.dumps(manifest, indent=2))
        return 0
    manifest = build_seed_set(
        Path(args.out_dir),
        llmail_max_attacks=args.llmail_max_attacks,
        opencode_max=args.opencode_max,
        seed=args.seed,
        extra_train=[Path(p) for p in args.extra_train],
    )
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
