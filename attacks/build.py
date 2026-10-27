"""Write (or verify) the generated attack trees.

Single source of truth: ``attacks/synth/generate.py``.  This module only
serialises it, so ``MANIFEST.json`` and the files it describes can never be
assembled by two different code paths.

    python -m attacks.build            # write repos/ and examples/
    python -m attacks.build --check    # fail if the tree on disk drifted
    python -m attacks.build --prune    # delete files no longer generated
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from attacks.manifests import MANIFEST_NAME, validate_manifest
from attacks.synth.generate import build_examples, build_repos

__all__ = ["build_tree", "check_tree", "main", "write_tree"]

PACKAGE_DIR = Path(__file__).resolve().parent
REPOS_DIR = PACKAGE_DIR / "repos"
EXAMPLES_DIR = PACKAGE_DIR / "examples"


def _json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def build_tree() -> dict[Path, str]:
    """Every managed path mapped to the exact bytes it should contain."""
    files: dict[Path, str] = {}
    for repo in build_repos().values():
        manifest = repo.manifest()
        validate_manifest(manifest)
        root = REPOS_DIR / repo.name
        for rel, text in repo.files.items():
            files[root / rel] = text
        files[root / MANIFEST_NAME] = _json(manifest)

    examples = build_examples()
    example_entries = [
        entry.as_manifest_entry() for example in examples for entry in example.entries
    ]
    examples_manifest = {
        "schema_version": 1,
        "repo": "examples",
        "title": "Hand-written attack examples",
        "threat": "two examples for each of the five attack threat types",
        "entries": example_entries,
    }
    validate_manifest(examples_manifest)
    for example in examples:
        files[EXAMPLES_DIR / example.path] = example.content
    files[EXAMPLES_DIR / "manifest.json"] = _json(examples_manifest)
    return files


def _managed_files() -> set[Path]:
    found: set[Path] = set()
    for root in (REPOS_DIR, EXAMPLES_DIR):
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                found.add(path)
    return found


def check_tree() -> list[str]:
    """Return human-readable drift entries; empty means the tree is current."""
    expected = build_tree()
    drift: list[str] = []
    for path, text in sorted(expected.items()):
        if not path.exists():
            drift.append(f"missing: {path.relative_to(PACKAGE_DIR)}")
            continue
        try:
            actual = path.read_text(encoding="utf-8")
        except OSError as exc:
            drift.append(f"unreadable: {path.relative_to(PACKAGE_DIR)} ({exc})")
            continue
        if actual != text:
            drift.append(f"changed: {path.relative_to(PACKAGE_DIR)}")
    for path in sorted(_managed_files() - set(expected)):
        drift.append(f"stale: {path.relative_to(PACKAGE_DIR)}")
    return drift


def write_tree(*, prune: bool = False) -> list[Path]:
    expected = build_tree()
    written: list[Path] = []
    for path, text in sorted(expected.items()):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        written.append(path)
    if prune:
        for path in sorted(_managed_files() - set(expected)):
            path.unlink()
        for root in (REPOS_DIR, EXAMPLES_DIR):
            if root.exists():
                for directory in sorted(root.rglob("*"), reverse=True):
                    if directory.is_dir() and not any(directory.iterdir()):
                        shutil.rmtree(directory)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m attacks.build")
    parser.add_argument(
        "--check", action="store_true", help="verify generated files instead of writing"
    )
    parser.add_argument(
        "--prune", action="store_true", help="delete files that are no longer generated"
    )
    args = parser.parse_args(argv)

    if args.check:
        drift = check_tree()
        if drift:
            for item in drift:
                print(f"drift: {item}", file=sys.stderr)
            print(
                f"{len(drift)} generated file(s) out of date; run `python -m attacks.build`",
                file=sys.stderr,
            )
            return 1
        print("attack tree is up to date")
        return 0

    written = write_tree(prune=args.prune)
    repos = build_repos()
    entries = sum(len(repo.entries) for repo in repos.values())
    print(f"wrote {len(written)} files: {len(repos)} repos, {entries} repo entries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
