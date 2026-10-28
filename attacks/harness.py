"""Per-repo detection harness: the answer key meets an actual scanner.

For every generated repo the harness:

1. stages a copy **without** ``MANIFEST.json`` (the scanner must never see the
   answer key);
2. runs a scanner over the staged copy;
3. compares the flagged files with the manifest: every ``READ``/``both`` entry
   must be found, and no file outside the manifest may be flagged;
4. checks that the decoder layer recovers every payload from its file.

Two scanners ship here:

``keyword``
    Deterministic, CPU-only, no model download. It decodes every hidden view
    with the real decoder registry and matches a small set of attack markers.
    This is the CI scanner and the demo's fast path.

``read``
    The real ``read.scan`` with ``ReadConfig.quick()``. It needs torch and a
    Prompt Guard checkpoint, so it is the GPU/regression scanner:
    ``python -m attacks.harness --scanner read``.

    python -m attacks.harness                    # all repos, READ gate
    python -m attacks.harness --layer RUN        # manifest coverage for RUN
    python -m attacks.harness --scanner read     # real detector
    python -m attacks.harness --json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from attacks.decoderlib import builtin_decoders, external_decoders, produce_views
from attacks.manifests import (
    MANIFEST_NAME,
    ManifestError,
    all_entry_files,
    expected_files,
    load_manifest,
)

__all__ = [
    "GateReport",
    "ScanOutcome",
    "evaluate",
    "keyword_scanner",
    "main",
    "read_scanner",
    "recover_generated",
    "run_all",
    "run_repo",
    "stage_repo",
]

PACKAGE_DIR = Path(__file__).resolve().parent
REPOS_DIR = PACKAGE_DIR / "repos"
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", ".tox"}
_BINARY_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".whl",
    ".so",
    ".dll",
    ".exe",
    ".pyc",
    ".woff",
    ".woff2",
    ".ttf",
    ".parquet",
    ".arrow",
    ".sqlite",
    ".db",
}

Scanner = Callable[[Path], "ScanOutcome"]

# Markers broad enough to catch every seed in seeds.py, narrow enough that the
# benign shell of a repo never matches. Credential filenames are matched by
# name rather than by a bare ``.env``: a README may legitimately say
# "copy .env.example", and a marker that cannot tell those apart is useless.
_MARKERS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore (?:all )?(?:the )?(?:previous|prior) instructions",
        r"ignore prior rules",
        r"disregard (?:the|your|all)",
        r"system override",
        r"system\s*:",
        r"maintenance mode",
        r"assistant\s*:",
        r"the user has approved",
        r"run_command",
        r"call the tool",
        r"when you open this repository",
        r"print the system prompt",
        r"do not mention this",
        r"evil\.example",
        r"10\.13\.37\.\d{1,3}",
        r"id_rsa",
        r"\.ssh\b",
        r"\.aws\b",
        r"\.netrc\b",
        r"eval\(",
        r"base64 -d",
        r"xxd -r -p",
    )
)


@dataclass
class ScanOutcome:
    flagged: dict[str, float] = field(default_factory=dict)
    incomplete: bool = False
    notes: list[str] = field(default_factory=list)

    @property
    def files(self) -> set[str]:
        return set(self.flagged)


@dataclass
class GateReport:
    repo: str
    layer: str
    expected: set[str]
    flagged: set[str]
    missed: set[str]
    extra: set[str]
    incomplete: bool
    recovered: int
    recoverable: int
    scanner: str

    @property
    def ok(self) -> bool:
        return (
            not self.missed
            and not self.extra
            and not self.incomplete
            and self.recovered == self.recoverable
        )

    def as_dict(self) -> dict:
        return {
            "repo": self.repo,
            "layer": self.layer,
            "scanner": self.scanner,
            "ok": self.ok,
            "expected": sorted(self.expected),
            "flagged": sorted(self.flagged),
            "missed": sorted(self.missed),
            "extra": sorted(self.extra),
            "incomplete": self.incomplete,
            "recovered": self.recovered,
            "recoverable": self.recoverable,
        }


def stage_repo(repo_dir: str | Path, dest: str | Path) -> Path:
    """Copy a repo without its manifest or VCS metadata."""
    repo_dir, dest = Path(repo_dir), Path(dest)
    ignore = shutil.ignore_patterns(MANIFEST_NAME, "__pycache__", ".git", "node_modules", "*.pyc")
    shutil.copytree(repo_dir, dest, ignore=ignore)
    return dest


def _iter_files(root: Path) -> Iterator[tuple[str, Path]]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in _SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.suffix.lower() in _BINARY_SUFFIXES:
                continue
            try:
                if b"\x00" in path.read_bytes()[:4096]:
                    continue
            except OSError:
                continue
            yield path.relative_to(root).as_posix(), path


def keyword_scanner(root: str | Path) -> ScanOutcome:
    """Deterministic CPU scanner over decoded views (the CI stand-in)."""
    root = Path(root)
    decoders = builtin_decoders() + external_decoders()
    outcome = ScanOutcome()
    for rel, path in _iter_files(root):
        if path.name == MANIFEST_NAME:
            continue  # answer key, never evidence
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            outcome.incomplete = True
            outcome.notes.append(f"{rel}: unreadable ({exc})")
            continue
        views = produce_views(text, decoders)
        for view in views:
            if any(marker.search(view.text) for marker in _MARKERS):
                outcome.flagged[rel] = 1.0
                break
    return outcome


def read_scanner(root: str | Path) -> ScanOutcome:
    """The real READ scanner; imports torch lazily so CI never needs it."""
    try:
        from read.config import ReadConfig
        from read.scan import scan
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            f"the READ scanner is missing a dependency ({exc}); install "
            "torch and transformers, or use --scanner keyword on CPU"
        ) from exc
    cfg = ReadConfig.quick()
    cfg.judge.enabled = False  # deterministic, no network in harness
    try:
        result = scan(Path(root), cfg=cfg)
    except FileNotFoundError as exc:  # pragma: no cover - needs the checkpoint
        raise RuntimeError(
            f"READ checkpoint unavailable ({exc}). Set BAITWATCH_MODEL_PATH "
            "or copy the pinned checkpoint from the training machine; use "
            "--scanner keyword for the CPU gate"
        ) from exc
    outcome = ScanOutcome(
        flagged={finding.file: finding.score for finding in result.flagged},
        incomplete=result.read_verdict == "incomplete",
        notes=list(result.stats.incomplete_reasons),
    )
    return outcome


def evaluate(outcome: ScanOutcome, manifest: dict, layer: str, scanner: str) -> GateReport:
    expected = expected_files(manifest, layer)
    flagged = outcome.files
    allowed = all_entry_files(manifest)
    return GateReport(
        repo=manifest.get("repo", "<unknown>"),
        layer=layer,
        expected=expected,
        flagged=flagged,
        missed=expected - flagged,
        extra=flagged - allowed,
        incomplete=outcome.incomplete,
        recovered=0,
        recoverable=0,
        scanner=scanner,
    )


def recover_generated(repo_name: str) -> tuple[int, int]:
    """How many generated payloads the decoder layer recovers from the file."""
    from attacks.synth.generate import build_examples, build_repos

    if repo_name == "examples":
        specs = [
            (example.content, entry) for example in build_examples() for entry in example.entries
        ]
    else:
        repo = build_repos().get(repo_name)
        if repo is None:
            return 0, 0
        specs = [(repo.files[entry.file], entry) for entry in repo.entries]
    decoders = builtin_decoders() + external_decoders()
    recovered = 0
    for text, entry in specs:
        views = produce_views(text, decoders)
        if any(entry.payload in view.text for view in views):
            recovered += 1
    return recovered, len(specs)


def run_repo(
    repo_dir: str | Path, scanner: Scanner, layer: str = "READ", scanner_name: str = "keyword"
) -> GateReport:
    repo_dir = Path(repo_dir)
    manifest = load_manifest(repo_dir / MANIFEST_NAME)
    with tempfile.TemporaryDirectory(prefix="baitwatch-stage-") as tmp:
        staged = stage_repo(repo_dir, Path(tmp) / repo_dir.name)
        outcome = scanner(staged)
    report = evaluate(outcome, manifest, layer, scanner_name)
    report.recovered, report.recoverable = recover_generated(report.repo)
    return report


def run_all(
    scanner: Scanner | None = None,
    layer: str = "READ",
    scanner_name: str = "keyword",
    repos: set[str] | None = None,
) -> list[GateReport]:
    scanner = scanner or keyword_scanner
    reports: list[GateReport] = []
    for repo_dir in sorted(path for path in REPOS_DIR.iterdir() if path.is_dir()):
        if repos and repo_dir.name not in repos:
            continue
        reports.append(run_repo(repo_dir, scanner, layer, scanner_name))
    return reports


def _table(reports: list[GateReport]) -> str:
    header = (
        f"{'repo':30} {'layer':5} {'ok':3} {'want':5} {'got':5} "
        f"{'miss':5} {'extra':5} {'rec':5} scanner"
    )
    lines = [header, "-" * len(header)]
    for report in reports:
        lines.append(
            f"{report.repo:30} {report.layer:5} {'yes' if report.ok else 'NO':3} "
            f"{len(report.expected):5} {len(report.flagged):5} "
            f"{len(report.missed):5} {len(report.extra):5} "
            f"{report.recovered}/{report.recoverable:<3} {report.scanner}"
        )
        for missed in sorted(report.missed):
            lines.append(f"    missed: {missed}")
        for extra in sorted(report.extra):
            lines.append(f"    extra:  {extra}")
        if report.incomplete:
            lines.append("    incomplete evidence")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m attacks.harness")
    parser.add_argument("--scanner", choices=("keyword", "read"), default="keyword")
    parser.add_argument("--layer", choices=("READ", "RUN"), default="READ")
    parser.add_argument(
        "--repo", action="append", default=[], help="only these repo names (repeatable)"
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    scanner = read_scanner if args.scanner == "read" else keyword_scanner
    try:
        reports = run_all(scanner, args.layer, args.scanner, set(args.repo) or None)
    except (ManifestError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload = {
            "ok": all(report.ok for report in reports),
            "reports": [report.as_dict() for report in reports],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(_table(reports))
    return 0 if all(report.ok for report in reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())
