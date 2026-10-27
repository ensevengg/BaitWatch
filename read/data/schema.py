"""Dataset row schema: {text, label, source, split}.

Every training/eval row carries its source so metrics can be reported per
source (the roadmap warns that only prodnull is repo-file voice — llmail is
email voice), and test splits must never contain muse_spark rows (rule from
the D2/D3 test matrix).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

SPLIT_TRAIN = "train"
SPLIT_VAL = "val"
SPLIT_TEST = "test"
SPLITS = (SPLIT_TRAIN, SPLIT_VAL, SPLIT_TEST)

VALID_SOURCES = frozenset({
    "prodnull", "llmail", "opencodeinstruct", "muse_spark",
    "attack_obfuscation",     # Aditya's +5k obfuscated rows (D3)
    "synthetic",              # fixtures and tests
})

MAX_ROW_CHARS = 6_000   # 512 tokens ~ 2k chars; 6k is a generous ceiling

_WS_RE = re.compile(r"\s+")


@dataclass
class Row:
    text: str
    label: int
    source: str
    split: str

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("text must be a non-empty string")
        if self.label not in (0, 1):
            raise ValueError(f"label must be 0 or 1, got {self.label!r}")
        if self.source not in VALID_SOURCES:
            raise ValueError(f"unknown source {self.source!r} (known: {sorted(VALID_SOURCES)})")
        if self.split not in SPLITS:
            raise ValueError(f"split must be one of {SPLITS}, got {self.split!r}")
        if self.source == "muse_spark" and self.split == SPLIT_TEST:
            raise ValueError("muse_spark rows must never land in the test split")
        if len(self.text) > MAX_ROW_CHARS:
            self.text = self.text[:MAX_ROW_CHARS]

    def to_dict(self) -> dict:
        return {"text": self.text, "label": self.label, "source": self.source,
                "split": self.split}


def normalize_for_dedupe(text: str) -> str:
    """Normalization used by both dedupe and the leakage check.

    Lowercase, collapse whitespace, drop punctuation — enough to catch
    re-worded copies without flattening code entirely.
    """
    return _WS_RE.sub(" ", re.sub(r"[^\w\s]", " ", text.casefold())).strip()


def text_sha256(text: str) -> str:
    return hashlib.sha256(normalize_for_dedupe(text).encode("utf-8")).hexdigest()


def write_parquet(rows: list[Row], path: Path) -> None:
    import pyarrow as pa
    import pyarrow.parquet as pq

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    table = pa.table({
        "text": [r.text for r in rows],
        "label": [r.label for r in rows],
        "source": [r.source for r in rows],
        "split": [r.split for r in rows],
    })
    pq.write_table(table, path)


def read_parquet(path: Path) -> list[Row]:
    import pyarrow.parquet as pq

    table = pq.read_table(path)
    return [Row(text=t, label=l, source=s, split=sp)
            for t, l, s, sp in zip(
                table.column("text").to_pylist(),
                table.column("label").to_pylist(),
                table.column("source").to_pylist(),
                table.column("split").to_pylist())]


def write_jsonl(rows: list[Row], path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r.to_dict(), ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[Row]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            try:
                rows.append(Row(
                    text=data["text"], label=int(data["label"]),
                    source=data.get("source", "synthetic"),
                    split=data.get("split", SPLIT_TRAIN)))
            except (KeyError, ValueError) as exc:
                raise ValueError(f"{path}:{i + 1}: bad row: {exc}") from exc
    return rows
