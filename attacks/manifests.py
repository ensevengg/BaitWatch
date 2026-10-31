"""Manifest loading, validation and span hashing.

A ``MANIFEST.json`` is the ground truth of an attack repository: which file,
which line, which technique, which encoding, which layer is expected to catch
it, and where the payload points.  It is deliberately **labels only** — it
stores SHA-256 hashes of the bytes and of the decoded payload, never the
payload text.  That keeps the manifest safe to read, keeps it from tripping
the READ detector, and still lets the leakage check compare payloads with the
training corpus without storing them.

The harness stages a copy of a repo **without** ``MANIFEST.json`` before
scanning, so the scanner can never use the answer key as evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from pathlib import Path

__all__ = [
    "MANIFEST_NAME",
    "SCHEMA_PATH",
    "ManifestError",
    "all_entry_files",
    "entry_span",
    "expected_files",
    "hash_text",
    "iter_manifests",
    "load_manifest",
    "normalize_text",
    "span_text",
    "validate_manifest",
    "verify_hashes",
]

MANIFEST_NAME = "MANIFEST.json"
SCHEMA_PATH = Path(__file__).resolve().with_name("MANIFEST.schema.json")
LAYERS = ("READ", "RUN", "both")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(ValueError):
    """A manifest is malformed or disagrees with the files on disk."""


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_text(text: str) -> str:
    """Case-folded, whitespace-collapsed form used for leakage comparison."""
    return " ".join(text.casefold().split())


def load_manifest(path: str | Path) -> dict:
    path = Path(path)
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"{path}: cannot read manifest: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{path}: manifest must be a JSON object")
    return data


def validate_manifest(data: dict, *, schema_path: Path | None = None) -> None:
    """Validate against the JSON Schema, then apply checks the schema cannot.

    ``jsonschema`` is a dev dependency; when it is missing the manual checks
    below still cover every invariant the harness relies on.
    """
    errors: list[str] = []

    for key in ("schema_version", "repo", "title", "threat", "entries"):
        if key not in data:
            errors.append(f"missing required key {key!r}")
    if data.get("schema_version") != 1:
        errors.append(f"schema_version must be 1, got {data.get('schema_version')!r}")
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        errors.append("entries must be a non-empty array")
        entries = []

    for index, entry in enumerate(entries):
        where = f"entries[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{where}: must be an object")
            continue
        for key in (
            "file",
            "line",
            "technique",
            "encoding",
            "expected_layer",
            "target",
            "payload_sha256",
            "decoded_sha256",
        ):
            if key not in entry:
                errors.append(f"{where}: missing {key!r}")
        if not isinstance(entry.get("line"), int) or entry.get("line", 0) < 1:
            errors.append(f"{where}: line must be a positive integer")
        end = entry.get("end_line", entry.get("line"))
        if not isinstance(end, int) or end < entry.get("line", 1):
            errors.append(f"{where}: end_line must be >= line")
        if entry.get("expected_layer") not in LAYERS:
            errors.append(f"{where}: expected_layer must be one of {LAYERS}")
        digest = entry.get("payload_sha256")
        if not isinstance(digest, str) or not _SHA_RE.match(digest):
            errors.append(f"{where}: payload_sha256 must be 64 lowercase hex chars")
        decoded = entry.get("decoded_sha256")
        if not isinstance(decoded, str) or not _SHA_RE.match(decoded):
            errors.append(f"{where}: decoded_sha256 must be 64 lowercase hex chars")

    try:
        import jsonschema
    except ModuleNotFoundError:  # CPU-only test envs
        jsonschema = None
    if jsonschema is not None:
        schema = json.loads((schema_path or SCHEMA_PATH).read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        for error in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
            location = ".".join(str(part) for part in error.path) or "<root>"
            errors.append(f"schema {location}: {error.message}")

    if errors:
        raise ManifestError(f"{data.get('repo', '<unknown>')}: " + "; ".join(errors))


def span_text(text: str, start_line: int, end_line: int) -> str:
    """Exact file text from 1-based ``start_line`` through ``end_line``."""
    if start_line < 1 or end_line < start_line:
        raise ManifestError(f"invalid span {start_line}..{end_line}")
    lines = text.split("\n")
    if end_line > len(lines):
        raise ManifestError(f"span {start_line}..{end_line} past end of file ({len(lines)} lines)")
    return "\n".join(lines[start_line - 1 : end_line])


def entry_span(repo_dir: str | Path, entry: dict) -> str:
    path = Path(repo_dir) / entry["file"]
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"{path}: cannot read entry file: {exc}") from exc
    return span_text(text, entry["line"], entry.get("end_line", entry["line"]))


def verify_hashes(repo_dir: str | Path, manifest: dict) -> list[str]:
    """Every entry's span hash must match the file on disk."""
    problems: list[str] = []
    for entry in manifest.get("entries", []):
        try:
            span = entry_span(repo_dir, entry)
        except ManifestError as exc:
            problems.append(str(exc))
            continue
        actual = hash_text(span)
        expected = entry.get("payload_sha256")
        if actual != expected:
            problems.append(
                f"{manifest.get('repo')}:{entry.get('file')}:{entry.get('line')} "
                f"payload_sha256 mismatch (expected {expected}, got {actual})"
            )
    return problems


def iter_manifests(root: str | Path) -> Iterator[tuple[Path, dict]]:
    """Yield every repo manifest plus the examples manifest, sorted."""
    root = Path(root)
    paths = sorted(root.glob("repos/*/MANIFEST.json"))
    examples = root / "examples" / "manifest.json"
    if examples.exists():
        paths.append(examples)
    for path in paths:
        yield path, load_manifest(path)


def expected_files(manifest: dict, layer: str) -> set[str]:
    """Files a gate must flag: expected_layer == layer or ``both``."""
    if layer not in ("READ", "RUN"):
        raise ValueError(f"layer must be READ or RUN, got {layer!r}")
    return {
        entry["file"]
        for entry in manifest.get("entries", [])
        if entry.get("expected_layer") in (layer, "both")
    }


def all_entry_files(manifest: dict) -> set[str]:
    return {entry["file"] for entry in manifest.get("entries", [])}
