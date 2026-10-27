"""Benign corpus: the false-positive measuring stick (roadmap D2: 10, D4: 30).

Nothing is vendored in the repo — public repo rule. This module holds the
pinned starter list and a clone helper that records every repo's resolved
commit in ``corpus_lock.json`` next to the clones, so an FPR number always
names the exact commits it was measured on. Grow the list with Aditya on D4,
including the scary-benign categories from the test matrix: security docs
about prompt injection, base64 data-URIs, minified JS, Hindi/Persian text
with legit zero-width joiners, .env.example files.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class CorpusRepo:
    url: str
    why: str            # which benign category this repo stress-tests


# Starter list (D2). Every entry small enough to clone in seconds.
CORPUS_STARTER: tuple[CorpusRepo, ...] = (
    CorpusRepo("https://github.com/microsoft/llmail-inject-challenge",
               "security docs about prompt injection — the scary-benign flagship"),
    CorpusRepo("https://github.com/OWASP/CheatSheetSeries",
               "security cheat sheets incl. LLM/prompt-injection guidance"),
    CorpusRepo("https://github.com/laravel/laravel",
               ".env.example with realistic-looking fake keys"),
    CorpusRepo("https://github.com/jquery/jquery",
               "minified JS in build artifacts"),
    CorpusRepo("https://github.com/expressjs/express",
               "README + examples with agent-readable setup text"),
    CorpusRepo("https://github.com/psf/requests",
               "docs with HTTP examples and tokens-in-docs"),
    CorpusRepo("https://github.com/pallets/flask",
               "docstrings and tutorial text"),
    CorpusRepo("https://github.com/sindresorhus/awesome",
               "huge curated README, links everywhere"),
    CorpusRepo("https://github.com/github/gitignore",
               "config-file voice, many small files"),
    CorpusRepo("https://github.com/httpie/cli",
               "CLI docs with command examples"),
)


def clone_corpus(target_dir: Path, repos: tuple[CorpusRepo, ...] = CORPUS_STARTER) -> dict:
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    lock_path = target_dir / "corpus_lock.json"
    lock: dict = {}
    if lock_path.exists():
        lock = json.loads(lock_path.read_text(encoding="utf-8"))

    for repo in repos:
        name = repo.url.rstrip("/").rsplit("/", 1)[-1]
        dest = target_dir / name
        if dest.exists():
            print(f"  = {name} already cloned")
        else:
            print(f"  → cloning {repo.url}")
            subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", repo.url, str(dest)],
                check=True)
        head = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True).stdout.strip()
        lock[name] = {"url": repo.url, "commit": head, "why": repo.why}
    lock_path.write_text(json.dumps(lock, indent=2), encoding="utf-8")
    print(f"lock written: {lock_path}")
    return lock


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.data.benign_corpus")
    parser.add_argument("target_dir", help="where to clone (not inside the BaitWatch repo)")
    args = parser.parse_args(argv)
    clone_corpus(Path(args.target_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
