"""Verdict cache and explicit approvals for the hook.

The READ model is the slow part of a scan, and an agent makes many tool calls
in the same repository.  A cache key is ``repo path + git HEAD + model tag +
fingerprint of the scanned tree + scanner configuration``.  The fingerprint
covers tracked and untracked files, so editing an instruction file or adding a
new one invalidates a cached ALLOW immediately.  Entries expire after
``BAITWATCH_HOOK_TTL`` seconds (default 600).

The cache is advisory: a cache read failure means "scan again", never
"allow".  Writes are atomic, so two hooks racing cannot truncate the file.
When the tree cannot be fingerprinted within the bounded budget, ``key``
returns ``None`` and the caller rescans rather than trusting an old verdict.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = [
    "ApprovalStore",
    "CachedScan",
    "ScanCache",
    "default_cache_path",
    "repo_fingerprint",
    "repo_head",
    "scanner_signature",
]

DEFAULT_TTL = 600.0
DEFAULT_APPROVAL_TTL = 900.0
MAX_FINGERPRINT_FILES = 4_000
MAX_FINGERPRINT_BYTES = 8 * 1024 * 1024
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
}


def default_cache_path() -> Path:
    override = os.environ.get("BAITWATCH_HOOK_CACHE")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "baitwatch" / "hook-cache.json"


def default_approval_path() -> Path:
    override = os.environ.get("BAITWATCH_HOOK_APPROVALS")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "baitwatch" / "approvals.json"


def _walk_files(root: Path) -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in _SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                rel = path.as_posix()
            files.append((rel, path))
            if len(files) > MAX_FINGERPRINT_FILES:
                raise ValueError("too many files")
    return files


def repo_fingerprint(repo: str | Path, *, exclude: list[str | Path] | None = None) -> str | None:
    """Bounded content fingerprint of the whole scanned tree.

    Returns ``None`` when the tree is too large or unreadable, which the caller
    must treat as "cannot confirm unchanged": rescan, never reuse ALLOW.
    """
    root = Path(repo)
    if not root.is_dir():
        return None
    excluded = {Path(item).resolve() for item in (exclude or [])}
    try:
        files = _walk_files(root)
    except (OSError, ValueError):
        return None
    digest = hashlib.sha256()
    total = 0
    for rel, path in files:
        try:
            if path.resolve() in excluded:
                continue
            stat = path.lstat()
            if path.is_symlink():
                digest.update(f"{rel}\0link\0{os.readlink(path)}\0".encode())
                continue
            if not path.is_file():
                continue
            size = stat.st_size
            total += size
            if total > MAX_FINGERPRINT_BYTES:
                return None
            digest.update(f"{rel}\0{size}\0{stat.st_mtime_ns}\0".encode())
            with open(path, "rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
        except OSError:
            return None
    return digest.hexdigest()


def scanner_signature() -> str:
    """Configuration that changes what a scan means, hashed into the key."""
    digest = hashlib.sha256()
    for key in (
        "BAITWATCH_HOOK_SCANNER",
        "BAITWATCH_HOOK_JUDGE",
        "BAITWATCH_MODEL_PATH",
        "BAITWATCH_ON_ERROR",
    ):
        digest.update(f"{key}={os.environ.get(key, '')}\0".encode())
    root = Path(__file__).resolve().parents[1]
    for rel in ("read/model_config.json", "attacks/decoders.py", "read/decoders.py"):
        path = root / rel
        try:
            stat = path.stat()
            digest.update(f"{rel}:{stat.st_size}:{stat.st_mtime_ns}\0".encode())
        except OSError:
            digest.update(f"{rel}:missing\0".encode())
    return digest.hexdigest()[:16]


def repo_head(repo: str | Path) -> str:
    """Best-effort git HEAD without spawning a process.

    The hook runs on every tool call; a subprocess per call is measurable.
    Reading ``.git/HEAD`` and the ref it points at is enough to notice a
    commit. A worktree ``.git`` file or a broken ref falls back to "unknown".
    """
    root = Path(repo)
    git = root / ".git"
    if git.is_file():  # worktree / submodule pointer
        try:
            line = git.read_text(encoding="utf-8").strip()
        except OSError:
            return "unknown"
        if line.startswith("gitdir:"):
            git = (root / line.split(":", 1)[1].strip()).resolve()
    head = git / "HEAD"
    try:
        value = head.read_text(encoding="utf-8").strip()
    except OSError:
        return "unknown"
    if value.startswith("ref:"):
        ref = git / value.split(":", 1)[1].strip()
        try:
            return ref.read_text(encoding="utf-8").strip() or "unknown"
        except OSError:
            return "unknown"
    return value or "unknown"


@dataclass
class CachedScan:
    verdict: str
    score: float
    reason: str
    files: list[str]
    model: str
    created: float

    def as_dict(self) -> dict:
        return asdict(self)


class ScanCache:
    def __init__(self, path: str | Path | None = None, ttl: float | None = None) -> None:
        self.path = Path(path) if path is not None else default_cache_path()
        self.ttl = (
            ttl if ttl is not None else float(os.environ.get("BAITWATCH_HOOK_TTL", DEFAULT_TTL))
        )

    def key(self, repo: str | Path, model_tag: str = "read-quick") -> str | None:
        root = Path(repo).resolve()
        fingerprint = repo_fingerprint(root, exclude=[self.path])
        if fingerprint is None:
            return None
        return f"{root}|{repo_head(root)}|{model_tag}|{fingerprint}|{scanner_signature()}"

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def get(self, key: str) -> CachedScan | None:
        entry = self._load().get(key)
        if not isinstance(entry, dict):
            return None
        try:
            created = float(entry["created"])
            verdict = str(entry["verdict"])
            score = float(entry.get("score", 0.0))
            reason = str(entry.get("reason", ""))
            files = [str(item) for item in entry.get("files", [])]
            model = str(entry.get("model", ""))
        except (KeyError, TypeError, ValueError):
            return None
        if verdict not in ("allow", "ask", "block"):
            return None
        if self.ttl >= 0 and time.time() - created > self.ttl:
            return None
        return CachedScan(verdict, score, reason, files, model, created)

    def set(self, key: str, scan: CachedScan) -> None:
        data = self._load()
        data[key] = scan.as_dict()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + f".{os.getpid()}.tmp")
        try:
            tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp.unlink()

    def clear(self) -> int:
        data = self._load()
        with contextlib.suppress(OSError):
            self.path.unlink()
        return len(data)


class ApprovalStore:
    """Explicit user approval for one exact tree, used by Gate A's ASK path.

    Approval is bound to the tree fingerprint: if any scanned file changes,
    the approval stops matching and Gate A asks (blocks) again.
    """

    def __init__(self, path: str | Path | None = None, ttl: float | None = None) -> None:
        self.path = Path(path) if path is not None else default_approval_path()
        self.ttl = (
            ttl
            if ttl is not None
            else float(os.environ.get("BAITWATCH_APPROVAL_TTL", DEFAULT_APPROVAL_TTL))
        )

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        now = time.time()
        data = {
            key: value
            for key, value in data.items()
            if isinstance(value, dict) and float(value.get("expires", 0)) > now
        }
        tmp = self.path.with_suffix(self.path.suffix + f".{os.getpid()}.tmp")
        try:
            tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp.unlink()

    def _key(self, root: Path, fingerprint: str) -> str:
        return f"{root}|{fingerprint}"

    def approve(self, repo: str | Path, minutes: float | None = None) -> str:
        root = Path(repo).resolve()
        fingerprint = repo_fingerprint(root, exclude=[self.path])
        if fingerprint is None:
            raise ValueError(f"cannot fingerprint {root}; refusing to approve an unknown tree")
        seconds = (minutes * 60.0) if minutes is not None else self.ttl
        now = time.time()
        data = self._load()
        data[self._key(root, fingerprint)] = {
            "repo": str(root),
            "fingerprint": fingerprint,
            "created": now,
            "expires": now + seconds,
        }
        self._write(data)
        return fingerprint

    def is_approved(self, repo: str | Path) -> bool:
        root = Path(repo).resolve()
        fingerprint = repo_fingerprint(root, exclude=[self.path])
        if fingerprint is None:
            return False
        entry = self._load().get(self._key(root, fingerprint))
        if not isinstance(entry, dict):
            return False
        try:
            return float(entry.get("expires", 0)) > time.time()
        except (TypeError, ValueError):
            return False

    def revoke(self, repo: str | Path) -> int:
        root = Path(repo).resolve()
        data = self._load()
        before = len(data)
        data = {key: value for key, value in data.items() if not key.startswith(f"{root}|")}
        self._write(data)
        return before - len(data)
