"""Reads a sink's JSONL log into typed hits. Anything malformed or unexpected
becomes a problem instead of being dropped, so an incomplete log can never
silently turn into an ALLOW."""

import json
from dataclasses import dataclass, field
from pathlib import Path

from run.evidence import NetworkHit

# The sinks stop logging at 4 MiB plus one truncation record; a bigger file
# means the log is not what the sinks produced.
DEFAULT_MAX_BYTES = 4 * 1024 * 1024 + 1024
BODY_PREVIEW_CHARS = 100
DETAIL_LIMIT = 400


class SinkLogLineError(ValueError):
    pass


@dataclass(frozen=True)
class SinkLog:
    ready: bool = False
    stopped: bool = False
    truncated: bool = False
    dns_hits: list[NetworkHit] = field(default_factory=list)
    http_hits: list[NetworkHit] = field(default_factory=list)
    tls_hits: list[NetworkHit] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def _text(record, key, *, default=None):
    value = record.get(key, default)
    if not isinstance(value, str):
        raise SinkLogLineError(f"{key} is missing or not a string")
    return value


def _dns_hit(record) -> NetworkHit:
    qname = _text(record, "qname")
    qtype = record.get("qtype", "unknown")
    if not isinstance(qtype, (int, str)):
        raise SinkLogLineError("qtype is not an int or name")
    detail = f"qtype={qtype}"
    decoded = []
    for entry in record.get("decoded", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("text"), str):
            raise SinkLogLineError("decoded entry is not {encoding, label, text}")
        label = entry.get("label", "")
        encoding = entry.get("encoding", "?")
        decoded.append(f"{encoding}({label})={entry['text']}")
    if decoded:
        detail += " decoded: " + "; ".join(decoded)
    return NetworkHit(
        source_ip=_text(record, "source_ip"),
        destination=qname,
        detail=detail[:DETAIL_LIMIT],
    )


def _http_hit(record) -> NetworkHit:
    path = _text(record, "path")
    method = _text(record, "method")
    host = record.get("host", "")
    if not isinstance(host, str):
        raise SinkLogLineError("host is not a string")
    body = record.get("body", "")
    if not isinstance(body, str):
        raise SinkLogLineError("body is not a string")
    truncated = record.get("body_truncated", False)
    if not isinstance(truncated, bool):
        raise SinkLogLineError("body_truncated is not a boolean")
    raw = record.get("raw")
    if raw is not None and not isinstance(raw, str):
        raise SinkLogLineError("raw is not a string")
    parts = [method]
    if body:
        parts.append(f"body={body[:BODY_PREVIEW_CHARS]}")
    if truncated:
        parts.append("body_truncated")
    if raw:
        parts.append(f"raw={raw[:BODY_PREVIEW_CHARS]}")
    return NetworkHit(
        source_ip=_text(record, "source_ip"),
        destination=f"{host}{path}" if host or path else "<unparsed>",
        detail=" ".join(parts)[:DETAIL_LIMIT],
    )


def _tls_hit(record) -> NetworkHit:
    sni = record.get("sni")
    if sni is not None and not isinstance(sni, str):
        raise SinkLogLineError("sni is not a string or null")
    return NetworkHit(
        source_ip=_text(record, "source_ip"),
        destination=sni if sni is not None else "<no sni>",
        detail="" if sni is not None else "ClientHello without SNI",
    )


def read_sink_log(path: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> SinkLog:
    ready = False
    stopped = False
    truncated = False
    dns_hits: list[NetworkHit] = []
    http_hits: list[NetworkHit] = []
    tls_hits: list[NetworkHit] = []
    problems: list[str] = []
    try:
        with open(path, "rb") as file:
            data = file.read(max_bytes + 1)
    except OSError as exc:
        return SinkLog(problems=[f"cannot read sink log: {exc}"])
    if len(data) > max_bytes:
        problems.append(
            f"sink log exceeds {max_bytes} bytes; only the first {max_bytes} were parsed"
        )
        data = data[:max_bytes]
    elif data and not data.endswith(b"\n"):
        problems.append("sink log ends with a partial line")
    for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        if stopped:
            problems.append(f"line {number}: record after the stopped marker")
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            problems.append(f"line {number}: not JSON ({exc.msg})")
            continue
        if not isinstance(record, dict):
            problems.append(f"line {number}: not a JSON object")
            continue
        kind = record.get("kind")
        if kind == "ready":
            if record.get("sink") in {"dns", "http"}:
                ready = True
            else:
                problems.append(
                    f"line {number}: ready record names no known sink ({record.get('sink')!r})"
                )
        elif kind == "stopped":
            if record.get("sink") in {"dns", "http"}:
                stopped = True
            else:
                problems.append(
                    f"line {number}: stopped record names no known sink ({record.get('sink')!r})"
                )
        elif kind == "log_truncated":
            truncated = True
        elif kind == "refused":
            problems.append(
                f"line {number}: sink refused a connection; that contact was not captured"
            )
        elif kind == "dns":
            _append(dns_hits, problems, number, _dns_hit, record)
        elif kind == "http":
            _append(http_hits, problems, number, _http_hit, record)
        elif kind == "tls":
            _append(tls_hits, problems, number, _tls_hit, record)
        else:
            problems.append(f"line {number}: unknown kind {kind!r}")
    return SinkLog(
        ready=ready,
        stopped=stopped,
        truncated=truncated,
        dns_hits=dns_hits,
        http_hits=http_hits,
        tls_hits=tls_hits,
        problems=problems,
    )


def _append(hits, problems, number, mapper, record):
    try:
        hits.append(mapper(record))
    except SinkLogLineError as exc:
        problems.append(f"line {number}: {exc}")
