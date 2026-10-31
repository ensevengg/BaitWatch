"""Screen fetched agent files before they become harmless (label 0) rows.

A public AGENTS.md can carry a real injection, and one mislabelled attack
teaches the model the opposite of what we want. Every file is scored with a
detector (max window score) and checked against patterns that real planted
text uses; the riskiest are printed for a human to read, and anything judged
hostile goes into ``agentfiles_exclude.json`` (read by build.py).

    python -m read.data.v17.screen --model <ckpt> [--top 60]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from read.chunking import Chunker
from read.data.v17.carriers import index_agentfiles, read_text
from read.decoders import mask_blobs

RAW = Path.home() / ".local/share/baitwatch/v17_raw"

SUSPICIOUS = {
    "pipe_to_shell": re.compile(r"(curl|wget|iwr|irm)[^\n|]{0,200}\|\s*(ba|z)?sh\b|\|\s*iex\b", re.I),
    "dont_tell": re.compile(r"(do not|don't|never)\s+(tell|mention|inform|reveal|show)[^.\n]{0,40}(user|human|anyone)", re.I),
    "override": re.compile(r"ignore (all |any )?(previous|prior|above|earlier) (instructions|rules)", re.I),
    "secrets_out": re.compile(r"(\.env|id_rsa|id_ed25519|credentials|api[_ -]?key|token)[^\n]{0,80}(curl|post|send|upload|http)", re.I),
    "hidden_unicode": re.compile("[​-‏‪-‮⁠-⁤\U000e0000-\U000e007f]"),
    "long_base64": re.compile(r"[A-Za-z0-9+/]{120,}={0,2}"),
    "auto_approve": re.compile(r"(auto[- ]?approve|dangerously|--yolo|skip (all )?(permission|confirmation))", re.I),
}


def screen(model: Path, top: int) -> list[dict]:
    from read.detector import Detector

    lock = json.loads((RAW / "agentfiles/agentfiles_lock.json").read_text())
    carriers = index_agentfiles(RAW / "agentfiles/files", lock)
    det = Detector(model, batch_size=32)
    chunker = Chunker(det.tokenizer, max_chunks=48)
    rows = []
    for c in carriers:
        text = read_text(c.path)
        if text is None:
            continue
        chunks, _ = chunker.chunk(mask_blobs(text), c.rel, line_offset=None)
        scores = det.scores([ch.text for ch in chunks]) if chunks else []
        hits = sorted(k for k, rx in SUSPICIOUS.items() if rx.search(text))
        rows.append({"key": f"{c.repo}:{c.rel}", "local": c.path.name,
                     "score": round(float(max(scores, default=0.0)), 4), "patterns": hits})
    rows.sort(key=lambda r: (-len(r["patterns"]), -r["score"]))
    (RAW / "agentfiles_screen.json").write_text(json.dumps(rows, indent=1))
    return rows[:top]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.data.v17.screen")
    parser.add_argument("--model", default=str(Path.home() / ".local/share/baitwatch/models/v15f_22m"))
    parser.add_argument("--top", type=int, default=60)
    args = parser.parse_args(argv)
    for r in screen(Path(args.model), args.top):
        print(f'{r["score"]:.3f} {",".join(r["patterns"]) or "-":40} {r["key"]}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
