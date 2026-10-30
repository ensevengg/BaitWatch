"""Repository walker: safe, deterministic file selection.

Rules enforced here (each has a test in tests/read/test_walker.py):

- Symlinks pointing outside the repo are never followed; links to files inside
  the repo are scanned once, under their repo-relative name.
- Directory symlinks whose resolved target stays inside the repo *are*
  followed, under the link path (the path an agent reads) — even when the
  target lies inside an excluded dir such as ``dist/``. Link and real paths
  to the same file are deduped, and symlink loops are not descended. Each
  resolved directory is listed only when reached through a strictly better
  dir tier than before (at most three times), so many links to one dir do
  not make the walk exponential.
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

import heapq
import itertools
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
    ".mcp.json", "mcp.json", "skill.md",
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


def _dir_tier(rel_dir: str) -> int:
    """Tier of a logical directory path, as in :func:`priority_tier`.

    0 for agent dirs, 1 for tier-1 dirs, else 2. The trailing slash makes
    the dir itself (``.cursor``) match its prefix (``.cursor/``). Tier never
    gets worse on descent: appending a name keeps any prefix/segment match.
    """
    if not rel_dir:
        return 2
    rel = rel_dir.replace(os.sep, "/").lower()
    rel_slash = rel if rel.endswith("/") else rel + "/"
    if rel_slash.startswith(AGENT_DIR_PREFIXES) \
            or any(f"/{p}" in f"/{rel_slash}" for p in AGENT_DIR_PREFIXES):
        return 0
    if rel_slash.startswith(TIER1_DIR_PREFIXES):
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

    # Pass 1: enumerate (metadata only, no reads) so the cap can be applied in
    # priority order across the whole repo, not per directory. Traversal is
    # manual (not os.walk) so directory symlinks can be followed safely:
    # a link is descended only when its resolved target stays inside the
    # repo, and it is reported under the link path. A resolved dir is listed
    # only through a logical path whose dir tier is strictly better than any
    # visit before it; tier never gets worse on descent, so each real dir is
    # listed at most three times and the walk stays linear even when many
    # links point at one dir. The heap on (tier, depth, path) visits the
    # best logical name first. An unreadable directory is recorded, not
    # silently pruned, so the fail-closed layer flags it (scan.py turns
    # `unreadable` into system findings when on_file_error="flag").
    visited_best: dict[str, int] = {}
    counter = itertools.count()
    heap: list[tuple[int, int, str, int, Path, str]] = []
    heapq.heappush(heap, (_dir_tier(""), 0, "", next(counter), repo_root, ""))
    while heap:
        tier, _depth, _path, _n, logical_dir, rel_dir = heapq.heappop(heap)
        try:
            resolved_key = str(logical_dir.resolve())
        except (OSError, RuntimeError) as exc:
            result.unreadable.append((rel_dir or str(repo_root), str(exc)))
            continue
        best = visited_best.get(resolved_key)
        if best is not None and best <= tier:
            continue
        visited_best[resolved_key] = tier
        try:
            with os.scandir(logical_dir) as it:
                names = sorted(e.name for e in it)
        except OSError as exc:
            result.unreadable.append((rel_dir or str(repo_root), str(exc)))
            continue
        for name in names:
            full = logical_dir / name
            # Logical paths are POSIX on every platform: findings, manifests
            # and the priority tiers all speak "/", and str(Path) would give
            # "\" on Windows.
            rel = f"{rel_dir}/{name}" if rel_dir else name
            try:
                lst = full.lstat()
            except OSError as exc:
                result.unreadable.append((rel, f"lstat failed: {exc}"))
                continue

            if stat.S_ISLNK(lst.st_mode):
                try:
                    target = full.resolve()
                except (OSError, RuntimeError) as exc:   # symlink loop (ELOOP)
                    result.unreadable.append((rel, f"broken symlink: {exc}"))
                    continue
                if not _is_within(repo_root, target):
                    result.skipped_outside_symlinks.append(rel)
                    continue
                try:
                    tst = target.stat()
                except OSError as exc:
                    result.unreadable.append((rel, f"broken symlink: {exc}"))
                    continue
                if stat.S_ISDIR(tst.st_mode):
                    if name in cfg.excluded_dirs:
                        result.skipped_dirs.append(rel)
                        continue
                    # Never descend a link back into the directory being
                    # listed or one of its real ancestors: that would
                    # re-list the same tree under the alias, however good
                    # the alias's tier is.
                    try:
                        listing_resolved = logical_dir.resolve()
                    except (OSError, RuntimeError) as exc:
                        result.unreadable.append(
                            (rel, f"broken symlink: {exc}"))
                        continue
                    try:
                        listing_resolved.relative_to(target)
                        continue
                    except ValueError:
                        pass
                    new_tier = _dir_tier(rel)
                    if visited_best.get(str(target), 99) <= new_tier:
                        continue
                    heapq.heappush(heap, (new_tier, rel.count("/"), rel,
                                          next(counter), full, rel))
                    continue
                if not stat.S_ISREG(tst.st_mode):
                    result.skipped_binary.append(rel)
                    continue
                read_path, size = target, tst.st_size
            elif stat.S_ISDIR(lst.st_mode):
                if name in cfg.excluded_dirs:
                    result.skipped_dirs.append(rel)
                    continue
                new_tier = _dir_tier(rel)
                try:
                    key = str(full.resolve())
                except (OSError, RuntimeError):
                    key = str(full)
                if visited_best.get(key, 99) <= new_tier:
                    continue
                heapq.heappush(heap, (new_tier, rel.count("/"), rel,
                                      next(counter), full, rel))
                continue
            elif stat.S_ISREG(lst.st_mode):
                read_path, size = full, lst.st_size
            else:
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
