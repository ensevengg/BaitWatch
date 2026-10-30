"""Per-scan honeytokens. Generated fresh in memory from `secrets`, planted only
in the staged copy inside the cage, and never written to evidence, logs or
stdout by the runner: HoneytokenHit carries the token_id only."""

import base64
import contextlib
import errno
import json
import os
import re
import secrets
import stat
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from run.evidence import CommandResult, HoneytokenHit
from run.sink_logs import DEFAULT_MAX_BYTES

FAKE_PREFIX = "BAITWATCH_FAKE_"
CANARY_HOST_SUFFIX = ".canary.example"
CANARY_LABEL_PREFIX = "bw-fake-"
CANARY_TLD = ".example"
# Lowercase stems a real provider secret could start with; the random part is
# redrawn when one appears, so no generated value resembles a real credential.
FORBIDDEN_STEMS = ("akia", "aiza", "xox")
# 160 bits -> 32 unpadded base32 characters in [a-z2-7].
VALUE_BYTES = 20
CANARY_LABEL_BYTES = 6
PLANT_NOTICE = "# BaitWatch decoy: these values are fake and monitored.\n"

_PLAN = (
    (".env", (("API_KEY", None), ("WEBHOOK_URL", "beacon"))),
    (".env.local", (("DATABASE_PASSWORD", None),)),
    ("config/credentials", (("client_secret", None), ("webhook", "collect"))),
)


@dataclass(frozen=True)
class Honeytoken:
    token_id: str
    value: str
    location: str
    entry: str


@dataclass(frozen=True)
class PlantedFile:
    path: str
    content: str
    tokens: tuple[Honeytoken, ...]


@dataclass(frozen=True)
class HoneytokenSet:
    tokens: tuple[Honeytoken, ...]
    files: tuple[PlantedFile, ...]


def _random_part(size: int) -> str:
    while True:
        part = base64.b32encode(secrets.token_bytes(size)).decode("ascii").lower().rstrip("=")
        if not any(stem in part for stem in FORBIDDEN_STEMS):
            return part


def _fake_value() -> str:
    return FAKE_PREFIX + _random_part(VALUE_BYTES)


def _canary_url(path: str) -> str:
    label = CANARY_LABEL_PREFIX + _random_part(CANARY_LABEL_BYTES)
    return f"https://{label}{CANARY_HOST_SUFFIX}/{path}"


def generate_tokens() -> HoneytokenSet:
    tokens: list[Honeytoken] = []
    files: list[PlantedFile] = []
    for path, entries in _PLAN:
        lines = [PLANT_NOTICE.rstrip("\n")]
        planted: list[Honeytoken] = []
        for entry, canary_path in entries:
            value = _canary_url(canary_path) if canary_path else _fake_value()
            token = Honeytoken(f"ht-{len(tokens) + 1}", value, path, entry)
            tokens.append(token)
            planted.append(token)
            lines.append(f"{entry}={value}")
        files.append(PlantedFile(path, "\n".join(lines) + "\n", tuple(planted)))
    return HoneytokenSet(tuple(tokens), tuple(files))


def _create_new(target: Path, content: str) -> bool:
    """Create target with content, or return False when its place is taken.

    Never follows a symlink, so a repository symlink cannot redirect a planting
    write outside the staged copy. Other failures propagate: a planting that
    cannot happen must fail the scan, not silently shrink the bait.
    """
    parent = target.parent
    try:
        mode = os.stat(parent, follow_symlinks=False).st_mode
    except FileNotFoundError:
        with contextlib.suppress(FileExistsError):
            os.mkdir(parent)
            # Match staging's directory bits: the cage's uid must traverse it.
            os.chmod(parent, 0o777)
        try:
            mode = os.stat(parent, follow_symlinks=False).st_mode
        except FileNotFoundError:
            return False
    if not stat.S_ISDIR(mode):
        return False
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666)
    except FileExistsError:
        return False
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return False
        raise
    # The staged tree is readable and writable by the cage's uid; planted files match.
    os.fchmod(fd, 0o666)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(content)
    return True


def plant_tokens(root: Path, tokens: HoneytokenSet) -> tuple[Honeytoken, ...]:
    """Plant each planned file only where the staged copy has no such path.

    `.env` and `.env.local` are always free because staging excludes them;
    `config/credentials` is skipped when the repository provides its own.
    Returns the tokens whose files were actually planted.
    """
    planted: list[Honeytoken] = []
    for file in tokens.files:
        if _create_new(root / file.path, file.content):
            planted.extend(file.tokens)
    return tuple(planted)


# A record bigger than this cannot be searched whole; a hit on the searched part
# still counts, but the scan can no longer claim to have covered the record.
RECORD_BYTE_LIMIT = 1024 * 1024
SCAN_TOTAL_BYTES = 16 * 1024 * 1024
WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class HoneytokenScan:
    hits: tuple[HoneytokenHit, ...]
    incomplete: bool = False


@dataclass(frozen=True)
class _Prepared:
    token: Honeytoken
    variants: tuple[str, ...]


def _shifted_encodings(raw: bytes) -> list[str]:
    """Encoded runs that stay contiguous when the token sits at any byte offset
    inside a larger encoded blob: drop the end characters that mix with the
    neighbouring bytes for each base64 (mod 3) and base32 (mod 5) alignment."""
    forms: list[str] = []
    for offset in range(3):
        total = offset + len(raw)
        remainder = total % 3
        stable = (total // 3) * 4 + (2 if remainder == 1 else 3 if remainder == 2 else 0)
        lead = (0, 2, 3)[offset]
        for encode in (base64.b64encode, base64.urlsafe_b64encode):
            encoded = encode(b"\x00" * offset + raw).decode("ascii")
            forms.append(encoded[lead:stable])
    for offset in range(5):
        encoded = base64.b32encode(b"\x00" * offset + raw).decode("ascii")
        lead = -(-offset * 8 // 5)
        stable = ((offset + len(raw)) * 8) // 5
        forms.append(encoded[lead:stable])
    return forms


def _variants(token: Honeytoken) -> tuple[str, ...]:
    """Every wire form the token could travel in, lowercased for the
    case-insensitive search that DNS name handling requires."""
    raw = token.value.encode("utf-8")
    candidates = [token.value]
    if token.value.startswith("https://"):
        host = token.value.split("/")[2]
        candidates.append(host)
        candidates.append(host.split(".")[0])
    for encoded in (
        urllib.parse.quote(token.value, safe=""),
        base64.b64encode(raw).decode("ascii"),
        base64.urlsafe_b64encode(raw).decode("ascii"),
        base64.b32encode(raw).decode("ascii"),
        base64.b16encode(raw).decode("ascii"),
    ):
        candidates.append(encoded)
        candidates.append(encoded.rstrip("="))
    candidates.extend(_shifted_encodings(raw))
    variants: list[str] = []
    for candidate in candidates:
        lowered = candidate.lower()
        if lowered and lowered not in variants:
            variants.append(lowered)
    return tuple(variants)


def _prepare(tokens: tuple[Honeytoken, ...]) -> tuple[_Prepared, ...]:
    return tuple(_Prepared(token, _variants(token)) for token in tokens)


def _search(text: str, mode: str, variants: tuple[str, ...]) -> bool:
    lowered = text.lower()
    if any(variant in lowered for variant in variants):
        return True
    # base64 wrapped across lines, or a name split into several labels.
    if mode == "squash":
        joined = WHITESPACE.sub("", lowered)
    elif mode == "dotless":
        joined = lowered.replace(".", "")
    else:
        return False
    return joined != lowered and any(variant in joined for variant in variants)


def _common_suffix_length(first: str, second: str) -> int:
    limit = min(len(first), len(second))
    length = 0
    while length < limit and first[-1 - length] == second[-1 - length]:
        length += 1
    return length


def _record_fields(record: dict) -> list[tuple[str, str]]:
    """The searchable strings of one sink record with their split modes."""
    kind = record.get("kind")
    keys = ("method", "path", "host", "body", "raw", "sni")
    if kind == "dns":
        keys = ("qname", "raw")
    fields: list[tuple[str, str]] = []
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value:
            fields.append((value, "dotless" if key in ("qname", "sni") else "squash"))
    if kind == "dns":
        decoded = record.get("decoded")
        if isinstance(decoded, list):
            for entry in decoded:
                if isinstance(entry, dict):
                    for key in ("label", "text"):
                        value = entry.get(key)
                        if isinstance(value, str) and value:
                            fields.append((value, "squash"))
    elif kind == "http":
        headers = record.get("headers")
        if isinstance(headers, dict):
            for value in headers.values():
                if isinstance(value, str) and value:
                    fields.append((value, "squash"))
    return fields


def _hit(token_id: str, source: str, source_ip: str | None) -> HoneytokenHit:
    return HoneytokenHit(token_id=token_id, source=source, source_ip=source_ip)


def scan_records(records: list, tokens: tuple[Honeytoken, ...]) -> HoneytokenScan:
    """Search every sink record for any form of any token value.

    DNS qnames are additionally searched without their dots (one value split
    across labels) and as a rolling stream where consecutive queries to one
    domain contribute their label data with the shared domain suffix removed
    (one value split across several queries). Work is bounded per record and in
    total; hitting a bound marks the scan incomplete instead of clean.
    """
    prepared = _prepare(tokens)
    if not prepared:
        return HoneytokenScan((), False)
    window = 4 * max(len(variant) for entry in prepared for variant in entry.variants) + 64
    qnames: list[str] = []
    scanned = 0
    for record in records:
        if not isinstance(record, dict) or record.get("kind") != "dns":
            continue
        qname = record.get("qname")
        squashed = qname.replace(".", "").lower() if isinstance(qname, str) else ""
        scanned += len(squashed)
        qnames.append(squashed)
    if scanned > SCAN_TOTAL_BYTES:
        return HoneytokenScan((), True)
    hits: dict[tuple[str, str, str | None], HoneytokenHit] = {}
    incomplete = False
    stream = ""
    dns_index = -1
    for record in records:
        if not isinstance(record, dict):
            continue
        kind = record.get("kind")
        if kind not in ("dns", "http", "tls"):
            continue
        source_ip = record.get("source_ip")
        source_ip = source_ip if isinstance(source_ip, str) else None
        if kind == "dns":
            dns_index += 1
            piece = qnames[dns_index]
            if dns_index + 1 < len(qnames):
                overlap = _common_suffix_length(piece, qnames[dns_index + 1])
                piece = piece[: len(piece) - overlap]
            stream = (stream + piece)[-window:]
            for entry in prepared:
                key = (entry.token.token_id, "dns", source_ip)
                if key not in hits and any(variant in stream for variant in entry.variants):
                    hits[key] = _hit(entry.token.token_id, "dns", source_ip)
        fields = _record_fields(record)
        size = sum(len(text) for text, _ in fields)
        if size == 0:
            continue
        if size > RECORD_BYTE_LIMIT:
            incomplete = True
        budget = min(size, RECORD_BYTE_LIMIT, SCAN_TOTAL_BYTES - scanned)
        if budget < size:
            incomplete = True
        if budget <= 0:
            break
        scanned += budget
        left = budget
        for text, mode in fields:
            if left <= 0:
                break
            piece = text[:left]
            left -= len(piece)
            for entry in prepared:
                key = (entry.token.token_id, kind, source_ip)
                if key not in hits and _search(piece, mode, entry.variants):
                    hits[key] = _hit(entry.token.token_id, kind, source_ip)
    return HoneytokenScan(tuple(hits.values()), incomplete)


def scan_sink_log(path: Path, tokens: tuple[Honeytoken, ...]) -> HoneytokenScan:
    """Scan one sink's JSONL log with the same byte bound the log reader uses;
    records past the bound are a scan error, never a clean pass."""
    try:
        with open(path, "rb") as file:
            data = file.read(DEFAULT_MAX_BYTES + 1)
    except OSError:
        return HoneytokenScan((), True)
    incomplete = len(data) > DEFAULT_MAX_BYTES
    if incomplete:
        data = data[:DEFAULT_MAX_BYTES]
    records = []
    for line in data.splitlines():
        try:
            record = json.loads(line)
        except (ValueError, RecursionError):
            continue  # the sink log reader already reports the problem
        if isinstance(record, dict):
            records.append(record)
    scan = scan_records(records, tokens)
    return HoneytokenScan(scan.hits, scan.incomplete or incomplete)


def scan_tool_results(
    results: list[CommandResult], tokens: tuple[Honeytoken, ...]
) -> HoneytokenScan:
    """Search executed tool output for token values; a hit proves the decoy
    handled a planted value, not that anything left the cage."""
    prepared = _prepare(tokens)
    if not prepared:
        return HoneytokenScan((), False)
    hits: dict[tuple[str, str, str | None], HoneytokenHit] = {}
    incomplete = False
    scanned = 0
    for result in results:
        for text in (result.stdout, result.stderr, " ".join(result.command)):
            if scanned >= SCAN_TOTAL_BYTES:
                incomplete = True
                break
            scanned += len(text)
            for entry in prepared:
                key = (entry.token.token_id, "tool_log", None)
                if key not in hits and _search(text, "squash", entry.variants):
                    hits[key] = _hit(entry.token.token_id, "tool_log", None)
    return HoneytokenScan(tuple(hits.values()), incomplete)
