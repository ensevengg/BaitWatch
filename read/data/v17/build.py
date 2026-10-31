"""Build data v1.7: scan-shaped windows with exact labels.

Every planted row is a real scanner window: the carrier is read and blob-masked
like ``read.scan`` does, the snippet is planted at a recorded character span,
and the file is cut by the scanner's own Chunker (448/64). A window is label 1
only when it holds the planted span (all of it, or 80%+ of a long one); windows
that cut the span partially are dropped; windows that miss it are harmless.

Rows per planted attack: the attack window, the same window from the clean
file (minimal pair), and one other window of the same file. Harmless snippets
get the same plants and the same markup weights, so position and markup carry
no label signal.

Splits (disjoint by snippet AND by carrier repository):
- train / val: train+val snippets planted into TRAIN_REPOS carriers, plus the
  old sources, carrier windows and agent files from train repos.
- test_planted: test snippets planted into TEST_REPOS carriers, plus TEST_REPOS
  carrier windows. Generated text, so it is reported apart from test.parquet.
- test: the frozen v1.6 test split (unchanged) — the hand-written gold set is
  added by read.data.v17.gold.

    python -m read.data.v17.build --out ~/.local/share/baitwatch/data_v17
"""

from __future__ import annotations

import argparse
import base64
import codecs
import json
import random
import re
import string
import time
from collections import Counter, defaultdict
from pathlib import Path

from read.chunking import Chunker
from read.data.leakage import check_rows, frozen_texts
from read.data.schema import Row, read_jsonl, read_parquet, text_sha256
from read.data.v17.agentfiles import PERMISSIVE, split_for_repo
from read.data.v17.carriers import (Carrier, CarrierPool, classify, index_agentfiles,
                                    index_repos, read_text)
from read.data.v17.embed import family, normalize_kind, plant, wrap
from read.data.v17.snippets import (assign_split, fill_placeholders, load_batches,
                                    random_host, stable_unit)
from read.data.v17.sources import TEST_REPOS, TRAIN_REPOS
from read.decoders import mask_blobs

HOME = Path.home() / ".local/share/baitwatch"
RAW = HOME / "v17_raw"

PLANTS_PER_SNIPPET = 6
SPAN_MIN_FRACTION = 0.8
CARRIER_WINDOWS_PER_REPO = 160
KIND_WEIGHT = {          # carrier-window sampling weight per kind (docs/config heavy)
    "README.md": 3, "docs": 2, "CONTRIBUTING.md": 3, "AGENTS.md": 4, "CLAUDE.md": 4,
    ".cursorrules": 4, ".github/copilot-instructions.md": 4, "SKILL.md": 4,
    "CHANGELOG.md": 2, "SECURITY.md": 4, "issue_template": 3, "package.json": 2,
    "pyproject.toml": 2, "Makefile": 2, "shell_script": 3, "workflow_yaml": 3,
    "compose_yaml": 2, "yaml": 1, "dockerfile": 3, "env_example": 4, "json": 1,
    "vscode_tasks": 3, "mcp_json": 3, "claude_settings": 3,
    "python_comment": 1, "js_comment": 1, "go_comment": 1, "other": 1,
}
# Hosts whose name labels the row by itself (old seed rows use them).
LOADED_HOST_RE = re.compile(
    r"\b[\w.-]*(?:evil|attacker|malicious|exfil|badguy|hacker)[\w-]*\.[a-z]{2,}(?:\.[a-z]{2,})?\b",
    re.I)

V17_SOURCES = ("v17_planted", "v17_bare", "v17_carrier", "v17_agentfile", "v17_noise")


class Out:
    """Rows plus metadata columns (the trainer reads only text/label/source/split)."""

    def __init__(self):
        self.rows: list[dict] = []
        self.seen: set[str] = set()

    def add(self, text: str, label: int, source: str, split: str, keep: bool = False,
            **meta) -> bool:
        """``keep`` bypasses dedupe and stripping (the frozen v1.6 test split)."""
        if not keep:
            text = text.strip("\n")
        if not text.strip():
            return False
        h = text_sha256(text)
        if h in self.seen and not keep:
            return False
        self.seen.add(h)
        self.rows.append({"text": text, "label": int(label), "source": source,
                          "split": split, **{k: str(v) for k, v in meta.items()}})
        return True


def _sanitize_hosts(text: str, rng: random.Random) -> str:
    return LOADED_HOST_RE.sub(lambda _m: random_host(rng), text)


def plant_snippet(out: Out, chunker: Chunker, snip, pool: CarrierPool, split: str,
                  rng: random.Random, stats: Counter, plants: int = PLANTS_PER_SNIPPET) -> None:
    for k in range(plants):
        kind = normalize_kind(rng.choice(snip.file_kinds))
        carrier = pool.pick(kind, rng)
        clean = read_text(carrier.path)
        if clean is None:
            stats["carrier_unreadable"] += 1
            continue
        clean = mask_blobs(clean)
        filled = fill_placeholders(snip.text, rng)
        block = wrap(filled, kind, snip.form, rng)
        text, a, b = plant(clean, block, family(kind), rng)
        chunks, _ = chunker.chunk(text, carrier.rel, line_offset=None, max_chunks=10_000)
        meta = dict(sid=snip.sid, intent=snip.intent, voice=snip.voice, lang=snip.lang,
                    kind=kind, carrier=f"{carrier.repo}:{carrier.rel}", plant=k)
        span = b - a
        hit, others = None, []
        for c in chunks:
            ov = max(0, min(b, c.end_char) - max(a, c.start_char))
            if ov >= span or (span > 0 and ov / span >= SPAN_MIN_FRACTION):
                if hit is None:
                    hit = c
            elif ov == 0:
                others.append(c)
        if hit is None:
            stats["span_not_windowed"] += 1
            continue
        if out.add(hit.text, snip.label, "v17_planted", split, role="planted", **meta):
            stats[f"planted_{snip.label}"] += 1
        if snip.label == 1:
            # Minimal pair: the clean file's window over the same spot.
            clean_chunks, _ = chunker.chunk(clean, carrier.rel, line_offset=None, max_chunks=10_000)
            twin = next((c for c in clean_chunks if c.start_char <= a < c.end_char), None)
            if twin is None and clean_chunks:
                twin = clean_chunks[-1]
            if twin is not None and out.add(twin.text, 0, "v17_planted", split,
                                            role="twin", **meta):
                stats["twin_0"] += 1
            if others and rng.random() < 0.5:
                if out.add(rng.choice(others).text, 0, "v17_planted", split,
                           role="context", **meta):
                    stats["context_0"] += 1
    # The bare snippet: what a decoded view (HTML comment, base64...) yields.
    filled = fill_placeholders(snip.text, rng)
    if out.add(filled, snip.label, "v17_bare", split, role="bare", sid=snip.sid,
               intent=snip.intent, voice=snip.voice, lang=snip.lang,
               kind=",".join(snip.file_kinds)):
        stats[f"bare_{snip.label}"] += 1


def carrier_windows(out: Out, chunker: Chunker, carriers: list[Carrier], split_of,
                    source: str, rng: random.Random, stats: Counter,
                    per_repo: int = CARRIER_WINDOWS_PER_REPO) -> None:
    by_repo: dict[str, list[Carrier]] = defaultdict(list)
    for c in carriers:
        by_repo[c.repo].append(c)
    for repo, files in sorted(by_repo.items()):
        weights = [KIND_WEIGHT.get(c.kind, 1) for c in files]
        picked = 0
        tries = 0
        while picked < per_repo and tries < per_repo * 4:
            tries += 1
            c = rng.choices(files, weights=weights)[0]
            text = read_text(c.path)
            if text is None:
                continue
            chunks, _ = chunker.chunk(mask_blobs(text), c.rel, line_offset=None, max_chunks=48)
            if not chunks:
                continue
            ch = rng.choice(chunks)
            if out.add(ch.text, 0, source, split_of(c), role="carrier", kind=c.kind,
                       carrier=f"{c.repo}:{c.rel}"):
                picked += 1
                stats[f"{source}_{split_of(c)}"] += 1


def noise_rows(rng: random.Random, n: int) -> list[str]:
    """Harmless encoded/gibberish text the old models scored as attacks."""
    words = ("build", "cache", "release", "notes", "config", "server", "client", "token",
             "update", "install", "the", "and", "with", "for", "this", "project", "data")
    out = []
    for i in range(n):
        sent = " ".join(rng.choice(words) for _ in range(rng.randint(6, 30)))
        kind = i % 6
        if kind == 0:
            out.append(sent[::-1])
        elif kind == 1:
            out.append(codecs.encode(sent, "rot13"))
        elif kind == 2:
            out.append(base64.b32encode(sent.encode()).decode())
        elif kind == 3:
            out.append(" ".join("".join(rng.choice(string.hexdigits.lower()) for _ in range(8))
                                for _ in range(rng.randint(4, 16))))
        elif kind == 4:
            out.append("".join(rng.choice(string.ascii_letters + string.digits + "_$")
                               for _ in range(rng.randint(40, 300))))
        else:
            out.append(";".join(f"var {rng.choice(string.ascii_lowercase)}{j}="
                                f"function(){{return {rng.randint(0, 99)}}}" for j in range(rng.randint(5, 40))))
    return out


def old_sources(out: Out, old_dir: Path, rng: random.Random, stats: Counter,
                chunk_tokens, max_tokens: int, llmail_cap: int = 2_500,
                opencode_cap: int = 2_000) -> None:
    """The v1.6 sources, trimmed: no truncated rows, no label-1 fragments."""
    for split in ("train", "val", "test"):
        rows = read_parquet(old_dir / f"{split}.parquet")
        if split == "train":
            # Snippet/patch rows come back in from their own files below.
            rows = [r for r in rows if r.source != "synthetic"]
        by_src: dict[tuple[str, int], list[Row]] = defaultdict(list)
        for r in rows:
            by_src[(r.source, r.label)].append(r)
        for (src, label), group in sorted(by_src.items()):
            rng.shuffle(group)
            cap = {"llmail": llmail_cap, "opencodeinstruct": opencode_cap}.get(src)
            if cap is not None and split == "train":
                group = group[:cap]
            for r in group:
                # test stays byte-identical to v1.6 so old numbers stay comparable
                if split != "test" and chunk_tokens(r.text) > max_tokens:
                    stats[f"old_dropped_long_{src}_{label}"] += 1
                    continue
                text = (_sanitize_hosts(r.text, rng)
                        if label == 1 and split != "test" else r.text)
                if out.add(text, label, src, split, keep=(split == "test"), role="old"):
                    stats[f"old_{split}_{src}_{label}"] += 1
    patch = old_dir / "patch_v16.jsonl"
    if patch.exists():
        for r in read_jsonl(patch):
            text = _sanitize_hosts(r.text, rng) if r.label == 1 else r.text
            if out.add(text, r.label, "synthetic", "train", role="patch_v16"):
                stats[f"patch_v16_{r.label}"] += 1
    snippets = HOME / "data" / "short_snippets.jsonl"
    if snippets.exists():
        for r in read_jsonl(snippets):
            if r.label != 0:          # label-1 fragments ("you to send an") are noise
                stats["short_attack_dropped"] += 1
                continue
            if out.add(r.text, 0, "synthetic", "train", role="short_snippet"):
                stats["short_snippet_0"] += 1


def build(out_dir: Path, tokenizer_path: Path, old_dir: Path, seed: int = 42,
          muse_dir: Path = RAW / "muse", carriers_dir: Path = RAW / "carriers",
          agent_dir: Path = RAW / "agentfiles", agent_exclude: Path | None = None,
          extra_frozen: list[Path] | None = None,
          window: tuple[int, int] = (448, 64)) -> dict:
    from transformers import AutoTokenizer

    started = time.time()
    rng = random.Random(seed)
    tok = AutoTokenizer.from_pretrained(str(tokenizer_path))
    chunker = Chunker(tok, window_tokens=window[0], overlap_tokens=window[1],
                      max_file_tokens=60_000, max_chunks=10_000, tail_windows=2)

    def chunk_tokens(text: str) -> int:
        return len(tok(text, add_special_tokens=False)["input_ids"])

    stats: Counter = Counter()
    out = Out()

    snippets, load_stats = load_batches(muse_dir)
    assign_split(snippets)
    train_pool = CarrierPool(index_repos(carriers_dir / "train"))
    test_pool = CarrierPool(index_repos(carriers_dir / "test"))

    lock_path = agent_dir / "agentfiles_lock.json"
    agent_carriers: list[Carrier] = []
    if lock_path.exists():
        lock = json.loads(lock_path.read_text())
        excluded = set()
        if agent_exclude and agent_exclude.exists():
            excluded = set(json.loads(agent_exclude.read_text()))
        agent_carriers = [c for c in index_agentfiles(agent_dir / "files", lock)
                          if f"{c.repo}:{c.rel}" not in excluded
                          and lock["repos"].get(c.repo, {}).get("license") in PERMISSIVE]
    def agent_split(c: Carrier) -> str:
        return split_for_repo(c.repo, TRAIN_REPOS, TEST_REPOS)

    agent_train = [c for c in agent_carriers if agent_split(c) in ("train", "val")]
    agent_test = [c for c in agent_carriers if agent_split(c) == "test_planted"]
    # Agent files are carriers too: planted agent-kind snippets land in real ones.
    train_pool = CarrierPool(train_pool.all + agent_train)
    test_pool = CarrierPool(test_pool.all + agent_test)

    # Plant harmless snippets more often when they are fewer, so planted
    # windows (and their markup) split evenly between the labels.
    n_by_label = Counter(s.label for s in snippets)
    plants = {1: PLANTS_PER_SNIPPET,
              0: max(PLANTS_PER_SNIPPET, min(2 * PLANTS_PER_SNIPPET, round(
                  PLANTS_PER_SNIPPET * n_by_label[1] / max(1, n_by_label[0]))))}
    stats["plants_label_0"], stats["plants_label_1"] = plants[0], plants[1]
    for snip in snippets:
        if snip.group == "test":
            plant_snippet(out, chunker, snip, test_pool, "test_planted", rng, stats,
                          plants[snip.label])
        else:
            plant_snippet(out, chunker, snip, train_pool, snip.group, rng, stats,
                          plants[snip.label])

    def repo_split(c: Carrier) -> str:
        return "val" if stable_unit("v17-carrier:" + c.repo + ":" + c.rel) < 0.1 else "train"

    agent_set = set(agent_carriers)
    carrier_windows(out, chunker, [c for c in train_pool.all if c not in agent_set],
                    repo_split, "v17_carrier", rng, stats)
    carrier_windows(out, chunker, [c for c in test_pool.all if c not in agent_set],
                    lambda _c: "test_planted", "v17_carrier", rng, stats, per_repo=80)
    carrier_windows(out, chunker, agent_carriers, agent_split, "v17_agentfile", rng,
                    stats, per_repo=6)

    for i, text in enumerate(noise_rows(rng, 900)):
        split = "val" if i % 10 == 0 else "train"
        if out.add(text, 0, "v17_noise", split, role="noise"):
            stats[f"noise_{split}"] += 1

    old_sources(out, old_dir, rng, stats, chunk_tokens, window[0])

    # Leakage: nothing frozen (suite fixtures, InjecAgent, attack repos) may
    # appear in train/val, and generated test rows must not echo train.
    frozen = frozen_texts([Path(p) for p in (extra_frozen or [])])
    leak_report = {}
    for split in ("train", "val", "test_planted"):
        rows = [Row(r["text"], r["label"], "synthetic", "train") for r in out.rows
                if r["split"] == split]
        rep = check_rows(rows, frozen)
        leak_report[split] = {"rows": rep["rows"], "clean": rep["clean"],
                              "exact": {k: len(v) for k, v in rep["exact_leaks"].items()},
                              "fuzzy": {k: len(v) for k, v in rep["fuzzy_leaks"].items()}}
        if not rep["clean"]:
            bad = {e["split_row"] for v in rep["exact_leaks"].values() for e in v} | \
                  {e["split_row"] for v in rep["fuzzy_leaks"].values() for e in v}
            idx = [i for i, r in enumerate(out.rows) if r["split"] == split]
            drop = {idx[j] for j in bad}
            out.rows = [r for i, r in enumerate(out.rows) if i not in drop]
            leak_report[split]["dropped"] = len(drop)

    # The frozen test split bypasses dedupe; any training row equal to a test
    # row is dropped from train/val instead.
    test_hashes = {text_sha256(r["text"]) for r in out.rows if r["split"] == "test"}
    before = len(out.rows)
    out.rows = [r for r in out.rows
                if r["split"] == "test" or text_sha256(r["text"]) not in test_hashes]
    stats["dropped_equal_to_test"] = before - len(out.rows)

    out_dir.mkdir(parents=True, exist_ok=True)
    import pyarrow as pa
    import pyarrow.parquet as pq

    meta_cols = sorted({k for r in out.rows for k in r} - {"text", "label", "source", "split"})
    counts = {}
    for split in ("train", "val", "test", "test_planted"):
        rows = [r for r in out.rows if r["split"] == split]
        if split == "test_planted":
            rows = [{**r, "split": "test"} for r in rows]
        if not rows:
            continue
        table = {c: [r.get(c, "") for r in rows] for c in ("text", "label", "source", "split", *meta_cols)}
        pq.write_table(pa.table(table), out_dir / f"{split}.parquet")
        counts[split] = {"rows": len(rows), "label_1": sum(r["label"] for r in rows),
                         "by_source": dict(Counter(f'{r["source"]}:{r["label"]}' for r in rows))}

    manifest = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "seed": seed,
        "tokenizer": str(tokenizer_path),
        "window": list(window),
        "snippet_load": load_stats,
        "snippets_by_group": dict(Counter(f"{s.group}:{s.label}" for s in snippets)),
        "carriers": {"train": train_pool.counts(), "test": test_pool.counts()},
        "agentfiles": {"train": len(agent_train), "test": len(agent_test)},
        "stats": dict(sorted(stats.items())),
        "leakage": leak_report,
        "counts": counts,
        "elapsed_s": round(time.time() - started, 1),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.data.v17.build")
    parser.add_argument("--out", default=str(HOME / "data_v17"))
    parser.add_argument("--tokenizer", default="/mnt/d/hf_models/Llama-Prompt-Guard-2-22M")
    parser.add_argument("--old-data", default=str(HOME / "data_v16"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--window", type=int, nargs=2, default=(448, 64),
                        metavar=("TOKENS", "OVERLAP"), help="must match the scanner's window")
    parser.add_argument("--agent-exclude", default=str(RAW / "agentfiles_exclude.json"))
    parser.add_argument("--extra-frozen", nargs="*",
                        default=[str(RAW / "frozen" / "aditya_attack_slice.json")])
    args = parser.parse_args(argv)
    manifest = build(Path(args.out), Path(args.tokenizer), Path(args.old_data), args.seed,
                     agent_exclude=Path(args.agent_exclude),
                     extra_frozen=[Path(p) for p in args.extra_frozen],
                     window=tuple(args.window))
    print(json.dumps({k: manifest[k] for k in ("snippet_load", "snippets_by_group",
                                               "counts", "leakage")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
