"""Prove the attack payloads never reached the READ training corpus.

Manan's ``read.data.leakage`` already checks InjecAgent and the frozen eval
suite. This module answers the ATTACK side's half of the roadmap gate: none of
the payloads in ``attacks/repos`` or ``attacks/examples`` may appear in the
training parquet, exactly, embedded in a longer row, or as a near copy.

The manifest stores only hashes, so the payload text is regenerated from
``attacks/synth/generate.py`` — the same source that produced the files. The
check then:

1. hashes every payload (SHA-256 of the raw text, of the normalized text, and
   of each word 3-gram);
2. streams the corpus rows from parquet / JSONL / text files;
3. reports exact, embedded and fuzzy matches (Jaccard >= 0.8).

No corpus is committed to this repository. When no split is found the check
prints "skipped" and exits 0, so CPU-only CI stays green; the gate runs for
real on the machine that holds the training data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from attacks.manifests import ManifestError, iter_manifests
from attacks.synth.generate import build_examples, build_repos

__all__ = [
    "DEFAULT_DATA_DIR",
    "FrozenPayload",
    "LeakReport",
    "check_corpus",
    "discover_corpus",
    "frozen_payloads",
    "main",
]

DEFAULT_DATA_DIR = Path.home() / ".local/share/baitwatch/data"
PACKAGE_DIR = Path(__file__).resolve().parent
FUZZY_THRESHOLD = 0.8
_SHINGLE = 3


def _normalize(text: str) -> str:
    return " ".join(text.casefold().split())


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _shingles(text: str) -> set[str]:
    words = _normalize(text).split()
    if len(words) < _SHINGLE:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i : i + _SHINGLE]) for i in range(len(words) - _SHINGLE + 1)}


@dataclass(frozen=True)
class FrozenPayload:
    name: str
    text: str
    sha256: str
    normalized_sha256: str
    normalized: str
    shingles: frozenset[str]

    @classmethod
    def build(cls, name: str, text: str) -> FrozenPayload:
        normalized = _normalize(text)
        return cls(
            name=name,
            text=text,
            sha256=_sha(text),
            normalized_sha256=_sha(normalized),
            normalized=normalized,
            shingles=frozenset(_shingles(text)),
        )


def frozen_payloads() -> list[FrozenPayload]:
    """Every payload in the generated repos and the hand-written examples."""
    payloads: list[FrozenPayload] = []
    for repo in build_repos().values():
        for entry in repo.entries:
            payloads.append(
                FrozenPayload.build(f"{repo.name}/{entry.file}:{entry.line}", entry.payload)
            )
    for example in build_examples():
        for entry in example.entries:
            payloads.append(
                FrozenPayload.build(f"examples/{example.path}:{entry.line}", entry.payload)
            )
    return payloads


def _manifest_hashes() -> dict[str, str]:
    """name -> decoded_sha256, for cross-checking the generated payloads."""
    hashes: dict[str, str] = {}
    for _path, manifest in iter_manifests(PACKAGE_DIR):
        for entry in manifest.get("entries", []):
            key = f"{manifest.get('repo')}/{entry['file']}:{entry['line']}"
            if entry.get("decoded_sha256"):
                hashes[key] = entry["decoded_sha256"]
    return hashes


@dataclass
class Leak:
    payload: str
    source: str
    row: int
    kind: str
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "payload": self.payload,
            "source": self.source,
            "row": self.row,
            "kind": self.kind,
            "detail": self.detail,
        }


@dataclass
class LeakReport:
    rows: int = 0
    corpus: list[str] = field(default_factory=list)
    leaks: list[Leak] = field(default_factory=list)
    skipped: bool = False

    @property
    def clean(self) -> bool:
        return not self.leaks

    def as_dict(self) -> dict:
        return {
            "clean": self.clean,
            "skipped": self.skipped,
            "rows": self.rows,
            "corpus": self.corpus,
            "leaks": [leak.as_dict() for leak in self.leaks],
        }


def _parquet_rows(path: Path) -> Iterator[str]:
    try:
        import pyarrow.parquet as pq
    except ModuleNotFoundError:
        return
    table = pq.read_table(path)
    columns = [name for name in table.column_names if name == "text"]
    if not columns:
        columns = [
            name
            for name in table.column_names
            if str(table.schema.field(name).type) in ("string", "large_string")
        ]
    for batch in table.select(columns).to_batches():
        data = batch.to_pydict()
        for index in range(batch.num_rows):
            pieces = [str(data[name][index]) for name in columns if data[name][index] is not None]
            if pieces:
                yield "\n".join(pieces)


def _json_rows(path: Path) -> Iterator[str]:
    text = path.read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("["):
        for item in json.loads(stripped):
            if isinstance(item, str):
                yield item
            elif isinstance(item, dict):
                yield from (
                    str(item[key])
                    for key in ("text", "content", "prompt", "instruction")
                    if isinstance(item.get(key), str)
                )
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            yield line
            continue
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            yield from (
                str(item[key])
                for key in ("text", "content", "prompt", "instruction")
                if isinstance(item.get(key), str)
            )


def _text_rows(path: Path) -> Iterator[str]:
    try:
        yield path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return


def iter_rows(path: Path) -> Iterator[str]:
    suffix = path.suffix.lower()
    if suffix == ".parquet":
        yield from _parquet_rows(path)
    elif suffix in (".json", ".jsonl", ".ndjson"):
        yield from _json_rows(path)
    elif suffix in (".txt", ".md"):
        yield from _text_rows(path)
    else:
        raise ValueError(f"unsupported corpus format: {path}")


def discover_corpus(
    data_dir: Path | None = None,
    splits: Iterable[str] = ("train", "val", "test"),
    extra: Iterable[Path] = (),
) -> list[Path]:
    found: list[Path] = [Path(path) for path in extra if Path(path).exists()]
    if data_dir is not None and Path(data_dir).is_dir():
        for split in splits:
            for suffix in (".parquet", ".jsonl", ".json", ".txt"):
                candidate = Path(data_dir) / f"{split}{suffix}"
                if candidate.exists():
                    found.append(candidate)
        found.extend(sorted(Path(data_dir).glob("*.parquet")))
    # Keep order, drop duplicates.
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in found:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


def check_corpus(payloads: list[FrozenPayload], corpus: list[Path]) -> LeakReport:
    report = LeakReport(corpus=[str(path) for path in corpus])
    if not corpus:
        report.skipped = True
        return report

    exact: dict[str, str] = {}
    normalized: dict[str, str] = {}
    inverted: dict[str, set[str]] = {}
    for payload in payloads:
        exact[payload.sha256] = payload.name
        normalized[payload.normalized_sha256] = payload.name
        for shingle in payload.shingles:
            inverted.setdefault(shingle, set()).add(payload.name)
    by_name = {payload.name: payload for payload in payloads}

    for path in corpus:
        for index, row in enumerate(iter_rows(path), start=1):
            report.rows += 1
            row_sha = _sha(row)
            row_norm = _normalize(row)
            row_norm_sha = _sha(row_norm)

            if row_sha in exact:
                report.leaks.append(Leak(exact[row_sha], str(path), index, "exact"))
                continue
            if row_norm_sha in normalized:
                report.leaks.append(
                    Leak(normalized[row_norm_sha], str(path), index, "exact-normalized")
                )
                continue

            counts: dict[str, int] = {}
            for shingle in _shingles(row):
                for name in inverted.get(shingle, ()):
                    counts[name] = counts.get(name, 0) + 1
            hit = False
            for name, shared in counts.items():
                payload = by_name[name]
                score = shared / max(1, len(payload.shingles))
                if len(payload.normalized) >= 24 and payload.normalized in row_norm:
                    report.leaks.append(Leak(name, str(path), index, "embedded"))
                    hit = True
                elif score >= FUZZY_THRESHOLD:
                    report.leaks.append(
                        Leak(name, str(path), index, "fuzzy", f"shingle overlap {score:.2f}")
                    )
                    hit = True
            if hit:
                continue
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m attacks.leakage")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="directory holding train/val/test.{parquet,jsonl,txt}",
    )
    parser.add_argument("--splits", nargs="*", default=["train", "val", "test"])
    parser.add_argument(
        "--text", nargs="*", type=Path, default=[], help="extra corpus files to check"
    )
    parser.add_argument("--json", action="store_true", help="JSON report on stdout")
    args = parser.parse_args(argv)

    payloads = frozen_payloads()
    manifest_hashes = _manifest_hashes()
    mismatched = [
        payload.name
        for payload in payloads
        if manifest_hashes.get(payload.name) and manifest_hashes[payload.name] != payload.sha256
    ]
    if mismatched:
        print(
            "error: manifest decoded_sha256 does not match generated payloads: "
            + ", ".join(sorted(mismatched)),
            file=sys.stderr,
        )
        return 2

    corpus = discover_corpus(args.data_dir, args.splits, args.text)
    try:
        report = check_corpus(payloads, corpus)
    except (OSError, ValueError, ManifestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    elif report.skipped:
        print(f"leakage check skipped: no corpus found under {args.data_dir}")
    elif report.clean:
        print(f"PASS: {len(payloads)} attack payloads absent from {report.rows} corpus rows")
    else:
        for leak in report.leaks:
            print(
                f"LEAK {leak.payload} -> {leak.source}:{leak.row} ({leak.kind} {leak.detail})",
                file=sys.stderr,
            )
        print(f"FAIL: {len(report.leaks)} leak(s) across {report.rows} rows", file=sys.stderr)

    if report.skipped:
        return 0
    return 0 if report.clean else 3


if __name__ == "__main__":
    raise SystemExit(main())
