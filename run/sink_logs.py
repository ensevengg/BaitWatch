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


def _check_ts(record):
    if "ts" in record:
        ts = record["ts"]
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            raise SinkLogLineError("ts is not a number")


def _check_sink(record, kind):
    _check_ts(record)
    sink = record.get("sink")
    if not isinstance(sink, str) or sink not in {"dns", "http"}:
        raise SinkLogLineError(f"{kind} record names no known sink ({sink!r})")


def _dns_hit(record) -> NetworkHit:
    _check_ts(record)
    qname = _text(record, "qname")
    qtype = record.get("qtype", "unknown")
    if isinstance(qtype, bool) or not isinstance(qtype, (int, str)):
        raise SinkLogLineError("qtype is not an int or name")
    detail = f"qtype={qtype}"
    raw_decoded = record.get("decoded", [])
    if not isinstance(raw_decoded, list):
        raise SinkLogLineError("decoded is not a list")
    decoded = []
    for entry in raw_decoded:
        if not isinstance(entry, dict) or not isinstance(entry.get("text"), str):
            raise SinkLogLineError("decoded entry is not {encoding, label, text}")
        label = entry.get("label", "")
        encoding = entry.get("encoding", "?")
        if not isinstance(label, str) or not isinstance(encoding, str):
            raise SinkLogLineError("decoded entry is not {encoding, label, text}")
        decoded.append(f"{encoding}({label})={entry['text']}")
    if decoded:
        detail += " decoded: " + "; ".join(decoded)
    raw = record.get("raw")
    if raw is not None and not isinstance(raw, str):
        raise SinkLogLineError("raw is not a string")
    if raw:
        detail += f" raw={raw[:BODY_PREVIEW_CHARS]}"
    capture_incomplete = record.get("capture_incomplete", False)
    if not isinstance(capture_incomplete, bool):
        raise SinkLogLineError("capture_incomplete is not a boolean")
    if capture_incomplete:
        detail += " capture_incomplete"
    return NetworkHit(
        source_ip=_text(record, "source_ip"),
        destination=qname,
        detail=detail[:DETAIL_LIMIT],
    )


def _http_hit(record) -> NetworkHit:
    _check_ts(record)
    path = _text(record, "path")
    method = _text(record, "method")
    headers = record.get("headers", {})
    if not isinstance(headers, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in headers.items()
    ):
        raise SinkLogLineError("headers is not a string map")
    host = record.get("host", "")
    if not isinstance(host, str):
        raise SinkLogLineError("host is not a string")
    body = record.get("body", "")
    if not isinstance(body, str):
        raise SinkLogLineError("body is not a string")
    truncated = record.get("body_truncated", False)
    if not isinstance(truncated, bool):
        raise SinkLogLineError("body_truncated is not a boolean")
    headers_truncated = record.get("headers_truncated")
    if not isinstance(headers_truncated, bool):
        raise SinkLogLineError("headers_truncated is not a boolean")
    raw = record.get("raw")
    if raw is not None and not isinstance(raw, str):
        raise SinkLogLineError("raw is not a string")
    parts = [method]
    if host and any(not ch.isascii() or not (ch.isalnum() or ch in "-.:") for ch in host):
        parts.append("invalid_host")
    if path and not path.startswith("/"):
        parts.append("invalid_path")
    if body:
        parts.append(f"body={body[:BODY_PREVIEW_CHARS]}")
    if truncated:
        parts.append("body_truncated")
    if headers_truncated:
        parts.append("headers_truncated")
    if raw:
        parts.append(f"raw={raw[:BODY_PREVIEW_CHARS]}")
    return NetworkHit(
        source_ip=_text(record, "source_ip"),
        destination=f"{host}{path}" if host or path else "<unparsed>",
        detail=" ".join(parts)[:DETAIL_LIMIT],
    )


def _tls_count(record, key):
    value = record.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SinkLogLineError(f"{key} is not a non-negative int")
    return value


def _tls_hit(record) -> NetworkHit:
    _check_ts(record)
    sni = record.get("sni")
    if sni is not None and not isinstance(sni, str):
        raise SinkLogLineError("sni is not a string or null")
    capture_incomplete = record.get("capture_incomplete", False)
    if not isinstance(capture_incomplete, bool):
        raise SinkLogLineError("capture_incomplete is not a boolean")
    hello_only = record.get("hello_only")
    if hello_only is not None and not isinstance(hello_only, bool):
        raise SinkLogLineError("hello_only is not a boolean")
    notes = []
    if sni is None:
        notes.append("ClientHello without SNI")
    if capture_incomplete:
        notes.append("capture_incomplete")
    if hello_only is not None:
        record_length = record.get("hello_record_length")
        if record_length is not None and (
            isinstance(record_length, bool)
            or not isinstance(record_length, int)
            or record_length <= 0
        ):
            raise SinkLogLineError("hello_record_length is not a positive int or null")
        total = _tls_count(record, "total_bytes")
        extra = _tls_count(record, "extra_bytes")
        prefix = record.get("extra_prefix", "")
        if (
            not isinstance(prefix, str)
            or len(prefix) > 32
            or len(prefix) % 2
            or any(ch not in "0123456789abcdef" for ch in prefix)
        ):
            raise SinkLogLineError("extra_prefix is not a bounded hex string")
        if hello_only and (capture_incomplete or record_length is None or total != record_length):
            raise SinkLogLineError("hello_only tls record is inconsistent")
        if extra != max(0, total - (record_length or 0)) or len(prefix) != 2 * min(extra, 16):
            raise SinkLogLineError("tls byte counts are inconsistent")
        notes.append(
            f"hello_only={'true' if hello_only else 'false'} "
            f"hello_record_length={record_length} total_bytes={total} extra_bytes={extra}"
            + (f" extra_prefix={prefix}" if prefix else "")
        )
    return NetworkHit(
        source_ip=_text(record, "source_ip"),
        destination=sni if sni is not None else "<no sni>",
        detail=" ".join(notes),
        hello_only=hello_only,
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
        except (ValueError, RecursionError) as exc:
            problems.append(f"line {number}: not JSON ({exc})")
            continue
        if not isinstance(record, dict):
            problems.append(f"line {number}: not a JSON object")
            continue
        kind = record.get("kind")
        try:
            if kind == "ready":
                _check_sink(record, "ready")
                ready = True
            elif kind == "stopped":
                _check_sink(record, "stopped")
                stopped = True
            elif kind == "log_truncated":
                _check_ts(record)
                truncated = True
            elif kind == "refused":
                _check_ts(record)
                _text(record, "source_ip")
                problems.append(
                    f"line {number}: sink refused a connection; that contact was not captured"
                )
            elif kind == "dns":
                hits_before = len(dns_hits)
                _append(dns_hits, problems, number, _dns_hit, record)
                if len(dns_hits) > hits_before and record.get("capture_incomplete") is True:
                    problems.append(
                        f"line {number}: dns capture is incomplete; "
                        "frames past the per-connection budget were not captured"
                    )
            elif kind == "http":
                hits_before = len(http_hits)
                _append(http_hits, problems, number, _http_hit, record)
                if len(http_hits) > hits_before and (
                    record.get("body_truncated") is True or record.get("headers_truncated") is True
                ):
                    # A truncated capture is incomplete evidence, like a cut DNS
                    # or TLS frame; the hit stays and so does this problem.
                    problems.append(
                        f"line {number}: http capture is incomplete; "
                        "the request head or body was cut at a capture limit"
                    )
            elif kind == "tls":
                hits_before = len(tls_hits)
                _append(tls_hits, problems, number, _tls_hit, record)
                if len(tls_hits) > hits_before and record.get("capture_incomplete") is True:
                    problems.append(
                        f"line {number}: tls capture is incomplete; "
                        "the full ClientHello was not captured"
                    )
            else:
                problems.append(f"line {number}: unknown kind {kind!r}")
        except SinkLogLineError as exc:
            problems.append(f"line {number}: {exc}")
        except Exception as exc:  # one bad line must not lose the rest of the log
            problems.append(f"line {number}: cannot parse record ({type(exc).__name__})")
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
