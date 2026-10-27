"""Short-snippet patch: teach the model the *short text* regime.

Measured failure (stress suite, v1.5d): arbitrary short benign lines —
"no extension at all", "generated file, do not edit", "hello world" — score
0.65–0.99. The seed set has no short-sentence voice: its shortest rows are
still full emails/configs.

Fix: extract genuinely diverse short snippets from the FROZEN v1 train split
(benign lines and fragments -> label 0, attack fragments -> label 1). No
corpus text is used — the snippets come from training data, so the leakage
guarantee is untouched. Ingest train-only via prepare --merge-mode.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

from read.data.schema import (SPLIT_TRAIN, read_parquet, text_sha256,
                              write_jsonl)


def _short_lines(text: str, lo: int = 3, hi: int = 90) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if lo <= len(line) <= hi and not line.startswith(("#!", "```")):
            out.append(line)
    return out


def _short_span(rng: random.Random, text: str, max_words: int = 9) -> str | None:
    words = text.split()
    if len(words) < 3:
        return None
    n = min(rng.randint(3, max_words), len(words))
    i = rng.randint(0, len(words) - n)
    return " ".join(words[i: i + n])


_ATTACK_MARKERS = ("http", ".env", "ignore", "key", "token", "password",
                   "secret", "credential", ".sh", "curl", "wget", "exfil",
                   "upload", "send", "instruction", "agent", "sms", "otp",
                   "btc", "wallet", "urgent", "verify", "click", "login")


def build_snippets(data_dir: Path, seed: int = 42,
                   n_benign: int = 1600, n_attack: int = 450) -> list[dict]:
    rng = random.Random(seed)
    rows = read_parquet(Path(data_dir) / "train.parquet")

    benign_rows = [r for r in rows if r.label == 0]
    attack_rows = [r for r in rows if r.label == 1]
    rng.shuffle(benign_rows)
    rng.shuffle(attack_rows)

    out: list[dict] = []
    seen: set[str] = set()

    # Benign: whole short lines, then short spans from longer rows.
    per_row = max(1, n_benign // max(1, len(benign_rows)))
    for r in benign_rows:
        if len(out) >= n_benign:
            break
        candidates = _short_lines(r.text)
        if candidates:
            picks = rng.sample(candidates, min(per_row, len(candidates)))
        else:
            span = _short_span(rng, r.text)
            picks = [span] if span else []
        for p in picks:
            p = p.strip()
            h = text_sha256(p)
            if p and h not in seen:
                seen.add(h)
                out.append({"text": p, "label": 0, "source": "synthetic",
                            "split": SPLIT_TRAIN})

    # Attack: short spans from attack rows that still carry attack content —
    # a fragment of an attack email can be plain code, and mislabeling that
    # as an attack would poison the short-text boundary.
    for r in attack_rows:
        if sum(1 for x in out if x["label"] == 1) >= n_attack:
            break
        span = _short_span(rng, r.text, max_words=rng.randint(5, 10))
        if span and len(span) >= 12 and any(m in span.lower() for m in _ATTACK_MARKERS):
            h = text_sha256(span)
            if h not in seen:
                seen.add(h)
                out.append({"text": span, "label": 1, "source": "synthetic",
                            "split": SPLIT_TRAIN})
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.data.short_snippets")
    parser.add_argument("--data-dir", required=True,
                        help="dir with the FROZEN v1 train.parquet")
    parser.add_argument("--out", required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    rows = build_snippets(Path(args.data_dir), seed=args.seed)
    write_jsonl_rows(rows, Path(args.out))
    from collections import Counter
    print(json.dumps({"rows": len(rows),
                      "labels": dict(Counter(r["label"] for r in rows))}))
    return 0


def write_jsonl_rows(rows: list[dict], path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
