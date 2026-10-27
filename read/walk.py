"""Repository walker: safe, deterministic file selection.

Rules enforced here (each has a test in tests/read/test_walker.py):

- Symlinks pointing outside the repo are never followed; links to files inside
  the repo are scanned once, under their repo-relative name.
- ``.git``, ``node_modules`` and the other cache/build dirs in WalkerConfig are
  skipped entirely.
- Binary files are skipped by extension and by a NUL-byte sniff; UTF-16/32
  text (BOM or BOM-less) is text, not binary.
- Files larger than ``max_file_bytes`` are read as a prefix and marked
  ``truncated`` — the text still gets scanned, nothing silently disappears.
- Unreadable files become per-file errors; the caller decides (default: a
  fail-closed system finding).
- Deterministic order with agent-instruction files first *repo-wide* (then
  READMEs/manifests, then the rest, shallow before deep), so the file cap
  always cuts the least agent-relevant files.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from read.config import WalkerConfig

# Tier 0: files coding agents load as instructions or configuration.
AGENT_FILE_NAMES = frozenset({
    "agents.md", "agent.md", "claude.md", "claude.local.md", "gemini.md",
    "codex.md", "conventions.md", ".cursorrules", ".clinerules",
    ".windsurfrules", ".roorules", ".goosehints", "copilot-instructions.md",
    ".mcp.json", "mcp.json",
})
AGENT_DIR_PREFIXES = (
    ".claude/", ".cursor/", ".windsurf/", ".clinerules/", ".roo/",
    ".continue/", ".github/instructions/", ".github/prompts/",
    ".github/chatmodes/", ".vscode/",
)
# Tier 1: what an agent reads next — READMEs, contributing guides, manifests
# and install/CI scripts it is likely to run.
TIER1_NAMES = frozenset({
    "readme", "readme.md", "readme.rst", "readme.txt", "contributing.md",
    "install.md", "setup.md", "package.json", "pyproject.toml", "setup.py",
    "setup.cfg", "makefile", "dockerfile", "docker-compose.yml",
    "requirements.txt", "cargo.toml", "go.mod", "install.sh", "setup.sh",
})
TIER1_DIR_PREFIXES = (".github/workflows/", ".devcontainer/")

_UTF32_BOMS = (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")
_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")


@dataclass
class ScannedFile:
    path: Path             # absolute path actually read (symlinks resolved)
    rel_path: str          # repo-relative name reported in findings
    truncated: bool = False
    read_bytes: int = 0
    encoding: str = "utf-8"   # sniffed: utf-8 | utf-16 | utf-16-le | utf-16-be | utf-32


@dataclass
class WalkResult:
    files: list[ScannedFile] = field(default_factory=list)
    skipped_dirs: list[str] = field(default_factory=list)
    skipped_binary: list[str] = field(default_factory=list)
    skipped_outside_symlinks: list[str] = field(default_factory=list)
    unreadable: list[tuple[str, str]] = field(default_factory=list)  # (rel_path, reason)
    truncated_scan: bool = False     # file cap hit: not everything was inspected
    files_over_cap: int = 0          # how many scannable files the cap cut

    @property
    def n_scanned(self) -> int:
        return len(self.files)


def sniff_encoding(head: bytes) -> str | None:
    """Text encoding from the first bytes, or None for binary.

    A BOM wins over the NUL sniff — UTF-16 text is full of NULs, and skipping
    it as binary let a UTF-16 AGENTS.md through unscanned. BOM-less UTF-16 is
    recognised by NULs on alternating byte positions (ASCII-range text).
    """
    if head.startswith(_UTF32_BOMS):
        return "utf-32"
    if head.startswith(_UTF16_BOMS):
        return "utf-16"
    if b"\x00" not in head:
        return "utf-8"
    sample = head[:4096]
    sample = sample[: len(sample) // 2 * 2]
    if len(sample) >= 16:
        even, odd = sample[0::2], sample[1::2]
        nul_even = even.count(0) / len(even)
        nul_odd = odd.count(0) / len(odd)
        if nul_odd > 0.6 and nul_even < 0.1:
            return "utf-16-le"
        if nul_even > 0.6 and nul_odd < 0.1:
            return "utf-16-be"
    return None


def _is_within(repo_root: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(repo_root.resolve())
        return True
    except ValueError:
        return False


def priority_tier(rel_path: str) -> int:
    rel = rel_path.replace(os.sep, "/").lower()
    name = rel.rsplit("/", 1)[-1]
    if name in AGENT_FILE_NAMES or rel.startswith(AGENT_DIR_PREFIXES) \
            or any(f"/{p}" in f"/{rel}" for p in AGENT_DIR_PREFIXES):
        return 0
    if name in TIER1_NAMES or name.startswith("readme") \
            or rel.startswith(TIER1_DIR_PREFIXES):
        return 1
    return 2


def _sort_key(rel_path: str) -> tuple[int, int, str]:
    rel = rel_path.replace(os.sep, "/")
    return (priority_tier(rel), rel.count("/"), rel.lower())


@dataclass
class _Candidate:
    full: Path
    rel: str
    read_path: Path
    size: int


def walk(repo_root: Path, cfg: WalkerConfig | None = None) -> WalkResult:
    cfg = cfg or WalkerConfig()
    repo_root = Path(repo_root).resolve()
    result = WalkResult()
    seen_targets: set[str] = set()
    candidates: list[_Candidate] = []

    def on_walk_error(exc: OSError) -> None:
        # An unreadable directory is silently PRUNED by os.walk by default —
        # its files would never be scanned and nothing would say so. Record it
        # so the fail-closed layer flags it (scan.py turns `unreadable` into
        # system findings when on_file_error="flag").
        result.unreadable.append((str(exc.filename or repo_root), str(exc)))

    # Pass 1: enumerate (metadata only, no reads) so the cap can be applied in
    # priority order across the whole repo, not per directory.
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False,
                                                onerror=on_walk_error):
        root = Path(dirpath)

        kept: list[str] = []
        for d in sorted(dirnames):
            full = root / d
            if d in cfg.excluded_dirs:
                result.skipped_dirs.append(str(full.relative_to(repo_root)))
                continue
            if full.is_symlink():
                # A symlinked directory inside the repo is only safe if its real
                # target stays inside; os.walk(followlinks=False) won't descend
                # either way, so record and move on.
                if not _is_within(repo_root, full):
                    result.skipped_outside_symlinks.append(str(full.relative_to(repo_root)))
                    continue
            kept.append(d)
        dirnames[:] = kept

        for name in filenames:
            full = root / name
            rel = str(full.relative_to(repo_root))
            try:
                lst = full.lstat()
            except OSError as exc:
                result.unreadable.append((rel, f"lstat failed: {exc}"))
                continue

            read_path, size = full, lst.st_size
            if stat.S_ISLNK(lst.st_mode):
                target = full.resolve()
                if not _is_within(repo_root, target):
                    result.skipped_outside_symlinks.append(rel)
                    continue
                try:
                    tst = target.stat()
                except OSError as exc:
                    result.unreadable.append((rel, f"broken symlink: {exc}"))
                    continue
                if not stat.S_ISREG(tst.st_mode):
                    result.skipped_binary.append(rel)
                    continue
                read_path, size = target, tst.st_size
            elif not stat.S_ISREG(lst.st_mode):
                continue

            if Path(name).suffix.lower() in cfg.binary_extensions:
                result.skipped_binary.append(rel)
                continue
            candidates.append(_Candidate(full, rel, read_path, size))

    # Pass 2: priority order, dedupe link/target pairs, sniff, cap.
    candidates.sort(key=lambda c: _sort_key(c.rel))
    for cand in candidates:
        # A link and its target are the same content — scan once, under
        # whichever name comes first in the deterministic order.
        resolved = str(cand.read_path.resolve())
        if resolved in seen_targets:
            continue
        if len(result.files) >= cfg.max_files:
            result.truncated_scan = True
            result.files_over_cap += 1
            continue
        try:
            with open(cand.read_path, "rb") as f:
                head = f.read(min(cand.size, cfg.binary_sniff_bytes))
        except OSError as exc:
            result.unreadable.append((cand.rel, str(exc)))
            continue
        encoding = sniff_encoding(head)
        if encoding is None:
            result.skipped_binary.append(cand.rel)
            continue
        seen_targets.add(resolved)
        result.files.append(ScannedFile(
            path=cand.read_path,
            rel_path=cand.rel,
            truncated=cand.size > cfg.max_file_bytes,
            read_bytes=min(cand.size, cfg.max_file_bytes),
            encoding=encoding,
        ))

    return result
