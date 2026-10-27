"""Verdict cache for the hook.

The READ model is the slow part of a scan, and an agent makes many tool calls
in the same repository. The cache key is ``repo path + git HEAD + model tag``
so a new commit or a different checkpoint invalidates it. Entries expire after
``BAITWATCH_HOOK_TTL`` seconds (default 600).

The cache is advisory: a cache read failure means "scan again", never
"allow". Writes are atomic, so two hooks racing cannot truncate the file.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

__all__ = ["CachedScan", "ScanCache", "default_cache_path", "repo_head"]

DEFAULT_TTL = 600.0


def default_cache_path() -> Path:
    override = os.environ.get("BAITWATCH_HOOK_CACHE")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "baitwatch" / "hook-cache.json"


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

    def key(self, repo: str | Path, model_tag: str = "read-quick") -> str:
        root = Path(repo).resolve()
        return f"{root}|{repo_head(root)}|{model_tag}"

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
