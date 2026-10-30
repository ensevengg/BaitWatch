"""Repo-wide publication check: no personal workstation paths.

The payload-target lint (``attacks/lint.py``) only looks at attack artifacts.
This check is deliberately separate and covers the whole repository: a public
submission must not disclose a contributor's home directory, Windows profile,
WSL drive mount, or local checkout name.  Use the documented placeholders
instead:

    <checkout>   the repository checkout
    <data-dir>   a directory holding the training corpus
    <model-dir>  a directory holding model weights

Run ``python -m attacks.publication``; exit 1 means a path must be scrubbed.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = ["Violation", "main", "publication_violations", "text_files"]

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parent

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    "build",
    "dist",
    "artifacts",
    "node_modules",
}
_TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".example",
    ".ini",
    ".json",
    ".md",
    ".patch",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "windows-user-home",
        re.compile(r"[A-Za-z]:\\Users\\[A-Za-z0-9._<> -]+", re.IGNORECASE),
    ),
    ("posix-home", re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+/")),
    ("wsl-drive-mount", re.compile(r"/mnt/[a-z]/", re.IGNORECASE)),
    (
        "local-checkout",
        re.compile(r"[A-Za-z]:\\(?:Hackathon|BaitWatch|bw-d3)\b", re.IGNORECASE),
    ),
)

# Generic shared-data mounts are configuration candidates, not a person's
# workstation path: they carry no username and are tried only after the
# home-directory location. Every other /mnt/<drive>/ path stays a violation.
_GENERIC_WSL_PREFIXES = ("/mnt/d/hf_models", "/mnt/d/hf_datasets")


def _only_generic_mounts(line: str, pattern: re.Pattern[str]) -> bool:
    matches = list(pattern.finditer(line))
    return bool(matches) and all(
        line[match.start() :].lower().startswith(_GENERIC_WSL_PREFIXES) for match in matches
    )


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.kind}: {self.detail}"


def text_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in _SKIP_DIRS)
        for name in sorted(filenames):
            # A linked worktree stores ``.git`` as a file containing a local
            # gitdir pointer.  It has no suffix, so it would otherwise be read
            # as published content and fail the check on a clean tree.
            if name in _SKIP_DIRS:
                continue
            path = Path(dirpath) / name
            if path.suffix.lower() in _TEXT_SUFFIXES:
                found.append(path)
    return found


def publication_violations(root: Path | None = None) -> list[Violation]:
    root = (root or REPO_ROOT).resolve()
    violations: list[Violation] = []
    for path in text_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        try:
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()
        for lineno, line in enumerate(text.splitlines(), start=1):
            for kind, pattern in _PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                if kind == "wsl-drive-mount" and _only_generic_mounts(line, pattern):
                    continue
                violations.append(
                    Violation(rel, lineno, kind, f"personal path {match.group()!r}")
                )
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m attacks.publication")
    parser.add_argument("--root", type=Path, default=None, help="repository root")
    args = parser.parse_args(argv)
    violations = publication_violations(args.root)
    for violation in violations:
        print(str(violation), file=sys.stderr)
    if violations:
        print(f"{len(violations)} personal path(s) must be scrubbed", file=sys.stderr)
        return 1
    print("publication check clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
