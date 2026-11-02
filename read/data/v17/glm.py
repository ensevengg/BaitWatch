"""GLM-written training rows, kept apart from the GLM red-team test set.

Raw batches come from the same brief as the red-team set plus a training
addendum, written in a workspace that never held the test set. Rows are
dropped when they were rejected in label review, share a 7-word run with any
Muse batch, gold text or red-team test text, or near-duplicate an earlier row.

Two shapes:
- snippets: planted into TRAIN_REPOS carriers exactly like the Muse snippets.
- woven files: whole files with the attack inside their own flow. Every
  scanner window that holds the attack span is label 1, the same file with
  the attack lines removed gives a label-0 twin, and every window that misses
  the span is label 0. Windows that cut the span partially are dropped.

GLM rows only go to train/val: their held-out check is the red-team set.
"""

from __future__ import annotations

import json
import random
from collections import Counter
from pathlib import Path

from read.chunking import Chunker
from read.data.v17.carriers import CarrierPool
from read.data.v17.redteam import _dedupe, load_raw, reference_shingles, shingles
from read.data.v17.snippets import Snippet, fill_placeholders, stable_unit
from read.decoders import mask_blobs

SPAN_MIN_FRACTION = 0.8
FILE_FILLS = 2          # placeholder fills per woven file
VAL_FRAC = 0.1
_SEP = "\x00"


def redteam_shingles(raw_dirs: list[Path]) -> set:
    """Every text in the red-team raw batches: snippets, attack lines, whole files."""
    ref: set = set()
    for root in raw_dirs:
        for d in sorted(p for p in Path(root).iterdir() if (p / "snippets.jsonl").is_file()):
            for line in (d / "snippets.jsonl").read_text(encoding="utf-8").splitlines():
                if line.strip():
                    ref |= shingles(json.loads(line)["text"])
            files = d / "files.jsonl"
            if not files.is_file():
                continue
            for line in files.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                r = json.loads(line)
                ref |= shingles(r["attack_text"])
                body = d / "files" / r["id"] / r["filename"]
                if body.is_file():
                    ref |= shingles(body.read_text(encoding="utf-8"))
    return ref


def load_glm(raw: Path, muse_dir: Path, redteam_dirs: list[Path],
             exclude: set[str]) -> tuple[list[dict], list[dict], dict]:
    ref = reference_shingles(muse_dir) | redteam_shingles(redteam_dirs)
    snippets, files, dropped = load_raw(raw, ref)
    snippets = [r for r in snippets if r["src"] not in exclude]
    files = [r for r in files if r["src"] not in exclude]
    seen: set = set()
    dd: list[dict] = []
    snippets = _dedupe(snippets, "text", seen, dd)
    files = _dedupe(files, "attack_text", seen, dd)
    stats = {"snippets": len(snippets), "files": len(files),
             "excluded_in_review": len(exclude),
             "dropped": dict(Counter(d["drop"] for d in dropped + dd))}
    return snippets, files, stats


def split_of(src: str) -> str:
    return "val" if stable_unit("v17-glm:" + src) < VAL_FRAC else "train"


def to_snippet(r: dict) -> Snippet:
    kinds = r["file_kinds"]
    kinds = [kinds] if isinstance(kinds, str) else list(kinds)
    return Snippet(sid="glm-" + r["src"], label=int(r["label"]), intent=r["category"],
                   voice=r.get("strength", "plain") if r["label"] == 1 else "plain",
                   lang=r.get("lang", "en"), form=r.get("form", "prose"),
                   file_kinds=kinds, text=r["text"].strip("\n"), batch="glm",
                   group=split_of(r["src"]))


def _fill_parts(parts: list[str], rng: random.Random) -> list[str]:
    """One placeholder fill shared by all parts, so the file stays coherent."""
    joined = _SEP.join(parts).replace(
        "{version}", f"{rng.randint(1, 6)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}")
    return fill_placeholders(joined, rng).split(_SEP)


def _line_bounds(text: str, a: int, b: int) -> tuple[int, int]:
    la = text.rfind("\n", 0, a) + 1
    lb = text.find("\n", b)
    return la, (len(text) if lb == -1 else lb + 1)


def woven_file(out, chunker: Chunker, f: dict, rng: random.Random, stats: Counter,
               fills: int = FILE_FILLS) -> None:
    body, atk_raw = f["body"], f["attack_text"].strip()
    i = body.find(atk_raw)
    if i < 0:
        stats["glm_file_attack_not_found"] += 1
        return
    split, label = split_of(f["src"]), int(f["label"])
    meta = dict(sid="glm-" + f["src"], intent=f["category"], kind=f["filename"],
                lang=f.get("lang", "en"), voice=f.get("strength", "na"))
    for k in range(fills):
        pre, atk, post = _fill_parts([body[:i], atk_raw, body[i + len(atk_raw):]], rng)
        text = mask_blobs(pre + atk + post)
        a = text.find(atk)
        if a < 0:
            stats["glm_file_span_masked"] += 1
            continue
        b = a + len(atk)
        chunks, _ = chunker.chunk(text, f["filename"], line_offset=None, max_chunks=10_000)
        hits = 0
        for c in chunks:
            ov = max(0, min(b, c.end_char) - max(a, c.start_char))
            span = b - a
            if ov >= span or (span > 0 and ov / span >= SPAN_MIN_FRACTION):
                if out.add(c.text, label, "v17_glm_file", split, role="woven", plant=k, **meta):
                    stats[f"glm_file_span_{label}"] += 1
                hits += 1
            elif ov == 0:
                if out.add(c.text, 0, "v17_glm_file", split, role="woven_context",
                           plant=k, **meta):
                    stats["glm_file_context_0"] += 1
            else:
                stats["glm_file_partial_dropped"] += 1
        if not hits:
            stats["glm_file_span_not_windowed"] += 1
        if label == 1:
            la, lb = _line_bounds(text, a, b)
            clean = text[:la] + text[lb:]
            twins, _ = chunker.chunk(clean, f["filename"], line_offset=None, max_chunks=10_000)
            twin = next((c for c in twins if c.start_char <= la < c.end_char),
                        twins[-1] if twins else None)
            if twin is not None and out.add(twin.text, 0, "v17_glm_file", split, role="twin",
                                            plant=k, **meta):
                stats["glm_file_twin_0"] += 1
        if k == 0 and out.add(atk, label, "v17_bare", split, role="bare", **meta):
            stats[f"glm_file_bare_{label}"] += 1


def add_glm(out, chunker: Chunker, plant_snippet, train_pool: CarrierPool,
            raw: Path, muse_dir: Path, redteam_dirs: list[Path], exclude: set[str],
            plants: dict[int, int], rng: random.Random, stats: Counter) -> dict:
    """Plant GLM snippets and ingest woven files; returns load stats."""
    snippets, files, load_stats = load_glm(raw, muse_dir, redteam_dirs, exclude)
    for r in snippets:
        snip = to_snippet(r)
        plant_snippet(out, chunker, snip, train_pool, snip.group, rng, stats,
                      plants[snip.label])
    for f in files:
        woven_file(out, chunker, f, rng, stats)
    load_stats["by_group"] = dict(Counter(f"{split_of(r['src'])}:{r['label']}"
                                          for r in snippets + files))
    return load_stats
