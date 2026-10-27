"""Repository walker: safe, deterministic file selection.

Rules enforced here (each has a test in tests/read/test_walker.py):

- Symlinks pointing outside the repo are never followed; links to files inside
  the repo are scanned once, under their repo-relative name.
- ``.git``, ``node_modules`` and the other cache/build dirs in WalkerConfig are
  skipped entirely.
- Binary files are skipped by extension and by a NUL-byte sniff.
- Files larger than ``max_file_bytes`` are read as a prefix and marked
  ``truncated`` — the text still gets scanned, nothing silently disappears.
- Unreadable files become per-file errors; the caller decides (default: a
  fail-closed system finding).
- Deterministic order with agent-config files first, so the inline hook path
  surfaces the highest-risk findings even when a scan is cut short.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from read.config import WalkerConfig

# Scanned before everything else: the files an agent actually ingests first.
PRIORITY_FILES = frozenset({
    "agents.md", "claude.md", "gemini.md", "codex.md", "cursorrules",
    ".cursorrules", ".clinerules", ".windsurfrules", "readme.md", "readme",
    ".claude/settings.json", ".claude/settings.local.json",
    ".cursor/rules", ".github/copilot-instructions.md",
})


@dataclass
class ScannedFile:
    path: Path             # absolute path actually read (symlinks resolved)
    rel_path: str          # repo-relative name reported in findings
    truncated: bool = False
    read_bytes: int = 0


@dataclass
class WalkResult:
    files: list[ScannedFile] = field(default_factory=list)
    skipped_dirs: list[str] = field(default_factory=list)
    skipped_binary: list[str] = field(default_factory=list)
    skipped_outside_symlinks: list[str] = field(default_factory=list)
    unreadable: list[tuple[str, str]] = field(default_factory=list)  # (rel_path, reason)
    truncated_scan: bool = False     # file cap hit: not everything was inspected

    @property
    def n_scanned(self) -> int:
        return len(self.files)


def _is_within(repo_root: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(repo_root.resolve())
        return True
    except ValueError:
        return False


def _sort_key(root: Path, name: str) -> tuple[int, str]:
    rel_str = str((root / name).relative_to(root)).lower()
    return (0 if rel_str in PRIORITY_FILES else 1, rel_str)


def walk(repo_root: Path, cfg: WalkerConfig | None = None) -> WalkResult:
    cfg = cfg or WalkerConfig()
    repo_root = Path(repo_root).resolve()
    result = WalkResult()
    seen_targets: set[str] = set()

    def on_walk_error(exc: OSError) -> None:
        # An unreadable directory is silently PRUNED by os.walk by default —
        # its files would never be scanned and nothing would say so. Record it
        # so the fail-closed layer flags it (scan.py turns `unreadable` into
        # system findings when on_file_error="flag").
        result.unreadable.append((str(exc.filename or repo_root), str(exc)))

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

        for name in sorted(filenames, key=lambda n: _sort_key(root, n)):
            full = root / name
            rel = str(full.relative_to(repo_root))
            try:
                lst = full.lstat()
            except OSError as exc:
                result.unreadable.append((rel, f"lstat failed: {exc}"))
                continue

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
                # A link and its target are the same content — scan once,
                # under whichever name comes first in the deterministic order.
                resolved = str(target)
                if resolved in seen_targets:
                    continue
                seen_targets.add(resolved)
            elif not stat.S_ISREG(lst.st_mode):
                continue

            if Path(name).suffix.lower() in cfg.binary_extensions:
                result.skipped_binary.append(rel)
                continue

            if len(result.files) >= cfg.max_files:
                result.truncated_scan = True
                return result

            size = lst.st_size if not full.is_symlink() else tst.st_size
            truncated = size > cfg.max_file_bytes
            read_bytes = min(size, cfg.max_file_bytes)
            try:
                with open(full if not full.is_symlink() else target, "rb") as f:
                    head = f.read(min(read_bytes, cfg.binary_sniff_bytes))
                if b"\x00" in head:
                    result.skipped_binary.append(rel)
                    continue
                result.files.append(ScannedFile(
                    path=full if not full.is_symlink() else target,
                    rel_path=rel,
                    truncated=truncated,
                    read_bytes=read_bytes,
                ))
            except OSError as exc:
                result.unreadable.append((rel, str(exc)))

    return result
