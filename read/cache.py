"""Persistent detector-score cache: repeat scans skip inference.

The hook scans the same repositories over and over; chunk texts barely change
between scans, so their scores are looked up instead of recomputed. Keys are
``blake2b(model identity + chunk text)`` — model identity covers the weights
file (path, size, mtime), device and dtype, so a re-pinned or retrained
checkpoint never reads stale scores.

The cache can only ever *save work*: any SQLite error (corrupt file, locked,
disk full) disables it for the rest of the process and the scan proceeds with
plain inference. Nothing about a verdict depends on it.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from pathlib import Path

DEFAULT_CACHE_PATH = Path(os.environ.get(
    "BAITWATCH_SCORE_CACHE",
    str(Path.home() / ".cache" / "baitwatch" / "scores.sqlite")))

_BATCH = 500


def model_identity(model_path: str, device: str, dtype: str) -> str:
    """Identity of the scoring function: weights file stat + device + dtype."""
    p = Path(model_path)
    weights = p / "model.safetensors" if p.is_dir() else p
    try:
        st = weights.stat()
        stamp = f"{st.st_size}:{st.st_mtime_ns}"
    except OSError:
        stamp = "nostat"
    return f"{p.resolve()}|{stamp}|{device}|{dtype}"


class ScoreCache:
    def __init__(self, path: Path, model_id: str):
        self.path = Path(path)
        self.model_id = model_id.encode("utf-8")
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None
        self.hits = 0
        self.misses = 0
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            db = sqlite3.connect(str(self.path), timeout=2.0, check_same_thread=False)
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS scores (k BLOB PRIMARY KEY, s REAL) WITHOUT ROWID")
            self._db = db
        except (sqlite3.Error, OSError):
            self._db = None

    @property
    def enabled(self) -> bool:
        return self._db is not None

    def _key(self, text: str) -> bytes:
        h = hashlib.blake2b(self.model_id, digest_size=16)
        h.update(b"\0")
        h.update(text.encode("utf-8", errors="surrogatepass"))
        return h.digest()

    def _disable(self) -> None:
        try:
            if self._db is not None:
                self._db.close()
        except sqlite3.Error:
            pass
        self._db = None

    def get_many(self, texts: list[str]) -> dict[str, float]:
        """Cached scores for whichever texts are present."""
        if self._db is None or not texts:
            return {}
        keys = {self._key(t): t for t in texts}
        found: dict[str, float] = {}
        klist = list(keys)
        try:
            with self._lock:
                for i in range(0, len(klist), _BATCH):
                    part = klist[i: i + _BATCH]
                    marks = ",".join("?" * len(part))
                    for k, s in self._db.execute(
                            f"SELECT k, s FROM scores WHERE k IN ({marks})", part):
                        found[keys[k]] = float(s)
        except sqlite3.Error:
            self._disable()
            return {}
        self.hits += len(found)
        self.misses += len(texts) - len(found)
        return found

    def put_many(self, scores: dict[str, float]) -> None:
        if self._db is None or not scores:
            return
        rows = [(self._key(t), float(s)) for t, s in scores.items()]
        try:
            with self._lock, self._db:
                self._db.executemany("INSERT OR REPLACE INTO scores (k, s) VALUES (?, ?)", rows)
        except sqlite3.Error:
            self._disable()
