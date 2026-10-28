"""Leakage check: prove the frozen eval sets are not in the training parquet.

Roadmap D2, moved *before* any number is reported: check the training splits
against InjecAgent (the frozen eval set) and against any additional frozen
payload list (Aditya's attack seeds, D3: "hash-check that none of Aditya's
attack-repo payloads are in your training parquet").

The real-world suite's attack fixtures (tests/read/fixtures/suite/attacks)
are frozen too — every line of >= 8 words, every long spaceless line (e.g.
CJK text), and every whole file — so suite results can only be reported for
models that never trained on them.

A row counts as leaked when its normalized text matches a frozen text exactly,
or shares word 3-gram Jaccard >= 0.8 with one. Exact matches are reported
separately from fuzzy ones because they mean different failure modes.

Usage:
    python -m read.data.leakage --data-dir <dir> [--extra-frozen file.json ...]
Exit 0 when clean, 3 when any leak is found.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from read.data.prepare import MinHashDeduper, _shingle_hashes
from read.data.schema import normalize_for_dedupe, read_parquet, text_sha256

INJECAGENT_DIR = Path(__file__).resolve().parents[2] / "injectionagent" / "InjecAgent" / "data"
SUITE_ATTACKS_DIR = (Path(__file__).resolve().parents[2] / "tests" / "read" / "fixtures"
                     / "suite" / "attacks")
TEST_CASE_FILES = (
    "test_cases_dh_base.json", "test_cases_dh_enhanced.json",
    "test_cases_ds_base.json", "test_cases_ds_enhanced.json",
)


def _is_frozen_line(line: str, min_line_words: int) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    normalized = normalize_for_dedupe(stripped)
    if not normalized:
        return False   # e.g. a line of variation selectors erases to nothing
    if len(normalized.split()) >= min_line_words:
        return True
    # Lines without spaces (CJK text normalizes to one or a few long
    # "words") are frozen by length instead, so non-English payloads stay
    # frozen even when punctuation splits them into several tokens.
    if len(stripped) >= 20 and any(
            "\u3400" <= c <= "\u4dbf" or "\u4e00" <= c <= "\u9fff"
            or "\uf900" <= c <= "\ufaff" or "\u3040" <= c <= "\u30ff"
            or "\uac00" <= c <= "\ud7af" for c in stripped):
        return True
    return " " not in normalized and len(normalized) >= 20


def suite_attack_texts(suite_dir: Path = SUITE_ATTACKS_DIR,
                       min_line_words: int = 8) -> list[str]:
    """Whole files and every long line of the suite's attack fixtures.

    Only lines of >= ``min_line_words`` words (or long spaceless lines) are
    frozen individually: shorter lines are common phrases ("Commit messages
    follow Conventional Commits." appears in a fixture and in ordinary benign
    repos) and flag false leaks. Whole files are always frozen.
    """
    texts: list[str] = []
    if not suite_dir.exists():
        return texts
    for path in sorted(p for p in suite_dir.rglob("*") if p.is_file()):
        try:
            body = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if body.strip():
            texts.append(body)
        texts.extend(ln.strip() for ln in body.splitlines()
                     if _is_frozen_line(ln, min_line_words))
    return texts


def frozen_texts(extra: list[Path] | None = None,
                 include_suite: bool = True) -> dict[str, list[str]]:
    """The texts that must never appear (even nearly) in a training split."""
    out: dict[str, list[str]] = {"injecagent": []}
    if include_suite:
        out["suite_attacks"] = suite_attack_texts()
    for name in TEST_CASE_FILES:
        p = INJECAGENT_DIR / name
        if not p.exists():
            continue
        for item in json.loads(p.read_text(encoding="utf-8")):
            instr = item.get("Attacker Instruction")
            if isinstance(instr, str) and instr.strip():
                out["injecagent"].append(instr)
            resp = item.get("Tool Response")
            if isinstance(resp, str) and resp.strip():
                out["injecagent"].append(resp)
    for path in (extra or []):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        texts = data if isinstance(data, list) else data.get("payloads", [])
        out[f"extra:{Path(path).name}"] = [t for t in texts if isinstance(t, str)]
    return {k: v for k, v in out.items() if v}


def check_rows(rows, frozen: dict[str, list[str]],
               jaccard_threshold: float = 0.8) -> dict:
    """Leakage check over in-memory rows (see :func:`check_split`)."""
    rows = list(rows)
    hash_to_frozen: dict[str, list[tuple[str, int]]] = {}
    tri_to_frozen: dict[bytes, set[tuple[str, int]]] = {}
    frozen_shingles: dict[tuple[str, int], set[bytes]] = {}
    frozen_norm: dict[tuple[str, int], str] = {}
    for group, texts in frozen.items():
        for idx, t in enumerate(texts):
            if not normalize_for_dedupe(t):
                continue   # erases to nothing: cannot match a training row
            gid = (group, idx)
            hash_to_frozen.setdefault(text_sha256(t), []).append(gid)
            sh = {h.tobytes() for h in _shingle_hashes(t)}
            frozen_shingles[gid] = sh
            frozen_norm[gid] = normalize_for_dedupe(t)
            for s in sh:
                tri_to_frozen.setdefault(s, set()).add(gid)

    exact: dict[str, list] = {k: [] for k in frozen}
    fuzzy: dict[str, list] = {k: [] for k in frozen}

    for i, r in enumerate(rows):
        row_norm = normalize_for_dedupe(r.text)
        row_sh = {h.tobytes() for h in _shingle_hashes(r.text)}

        hit = hash_to_frozen.get(text_sha256(r.text))
        if hit:
            for group, idx in hit:
                exact[group].append({"split_row": i, "label": r.label})
            continue

        # Candidate frozen texts = those sharing shingles with this row.
        shares: dict[tuple[str, int], int] = {}
        for s in row_sh:
            for gid in tri_to_frozen.get(s, ()):  # usually empty
                shares[gid] = shares.get(gid, 0) + 1
        if not shares:
            continue
        for gid, inter in sorted(shares.items(), key=lambda kv: -kv[1])[:50]:
            group, idx = gid
            union = len(row_sh | frozen_shingles[gid])
            if inter / union >= jaccard_threshold:
                fuzzy[group].append({"split_row": i, "label": r.label,
                                     "jaccard": round(inter / union, 3)})
            elif frozen_norm[gid] and frozen_norm[gid] in row_norm:
                # Payload embedded inside a longer training row.
                exact[group].append({"split_row": i, "label": r.label,
                                     "embedded": True})
    return {
        "rows": len(rows),
        "exact_leaks": {k: v for k, v in exact.items() if v},
        "fuzzy_leaks": {k: v for k, v in fuzzy.items() if v},
        "clean": not any(exact.values()) and not any(fuzzy.values()),
    }


def check_split(parquet_path: Path, frozen: dict[str, list[str]],
                jaccard_threshold: float = 0.8) -> dict:
    """Fast two-sided check over one parquet split.

    An inverted index over frozen word 3-grams narrows every row to a handful
    of candidate frozen texts before any Jaccard math runs, so the full sweep
    is O(total shingles) instead of O(rows x frozen).
    """
    report = check_rows(read_parquet(parquet_path), frozen, jaccard_threshold)
    return {"parquet": str(parquet_path), **report}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.data.leakage")
    parser.add_argument("--data-dir",
                        default=str(Path.home() / ".local/share/baitwatch/data"))
    parser.add_argument("--splits", nargs="*", default=["train", "val", "test"])
    parser.add_argument("--extra-frozen", nargs="*", default=[],
                        help="JSON files with extra frozen payloads (e.g. attack seeds)")
    parser.add_argument("--report", help="write the JSON report here")
    args = parser.parse_args(argv)

    frozen = frozen_texts([Path(p) for p in args.extra_frozen])
    if not frozen:
        print("error: no frozen eval texts found (InjecAgent missing?)", file=sys.stderr)
        return 2
    print(f"frozen texts: " + ", ".join(f"{k}={len(v)}" for k, v in frozen.items()))

    reports = []
    clean = True
    for split in args.splits:
        p = Path(args.data_dir) / f"{split}.parquet"
        if not p.exists():
            print(f"warning: {p} not found, skipping", file=sys.stderr)
            continue
        report = check_split(p, frozen)
        reports.append(report)
        status = "CLEAN" if report["clean"] else "LEAKED"
        clean &= report["clean"]
        print(f"{split}: {status} ({report['rows']} rows)")

    payload = {"clean": clean, "splits": reports}
    if args.report:
        Path(args.report).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if not clean:
        print("FAIL: leakage detected — rebuild the seed set before reporting any number.")
        return 3
    print("PASS: no leakage between training splits and frozen eval sets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
