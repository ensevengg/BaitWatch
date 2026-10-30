"""Standalone DNS sink (UDP and TCP): answers everything, logs every query and
any data hidden in labels. Stdlib only; bind-mounted into the sink container."""

import argparse
import base64
import binascii
import contextlib
import ipaddress
import json
import os
import signal
import socket
import sys
import threading
import time

LOG_CAP_BYTES = 4 * 1024 * 1024
PACKET_LIMIT = 4096
TCP_PACKET_LIMIT = 65535
RAW_LIMIT = 200
ANSWER_TTL = 30
DECODED_LIMIT = 8
MIN_DECODED_BYTES = 4
MIN_LABEL_CHARS = 8
PRINTABLE_RATIO = 0.9
TCP_TIMEOUT = 5.0
TCP_MAX_FRAMES = 16
POLL_SECONDS = 0.2
SHUTDOWN_SECONDS = 1.5

QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    35: "NAPTR",
    39: "DNAME",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    48: "DNSKEY",
    65: "HTTPS",
    255: "ANY",
}
B32_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
B64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
B64URL_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
HEX_ALPHABET = set("0123456789abcdefABCDEF")


class JsonlLog:
    """One JSON object per line, flushed immediately; stops logging at the cap.

    The UDP and TCP paths write concurrently, so every cap check, append and
    flush happens under one lock. A failed write kills the process: a clean
    log prefix must never outlive contacts whose records were lost.
    """

    def __init__(self, file):
        self._file = file
        self._lock = threading.Lock()
        self._written = 0
        self.truncated = False
        self._closed = False

    def _write_locked(self, record):
        if self.truncated or self._closed:
            return
        line = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
        try:
            if self._written + len(line) > LOG_CAP_BYTES:
                # The truncation marker must be the last record even if it does not fit.
                self._file.write(
                    json.dumps(
                        {"kind": "log_truncated", "ts": time.time()},
                        ensure_ascii=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                self._file.flush()
                self.truncated = True
                return
            self._file.write(line)
            self._file.flush()
            self._written += len(line)
        except OSError as exc:
            with contextlib.suppress(OSError):
                print(f"dns_sink: cannot write log: {exc}", file=sys.stderr)
            os._exit(1)

    def write(self, record):
        with self._lock:
            self._write_locked(record)

    def close(self):
        """Acknowledge a graceful stop; no record can follow this one."""
        with self._lock:
            self._write_locked({"kind": "stopped", "ts": time.time(), "sink": "dns"})
            self._closed = True


def printable_ratio(data):
    if not data:
        return 0.0
    # U+FFFD stands in for undecodable bytes; counting it printable would bless binary garbage.
    text = data.decode("utf-8", errors="replace")
    printable = sum(1 for ch in text if ch.isprintable() and ch != "\ufffd")
    return printable / len(text)


def decode_label(label):
    """Best-effort decodings of one DNS label; only mostly-printable results survive."""
    entries = []
    seen = set()
    body = label.rstrip("=")
    if len(body) < MIN_LABEL_CHARS:
        return entries
    candidates = []
    if len(body) % 2 == 0 and all(ch in HEX_ALPHABET for ch in body):
        candidates.append(("hex", bytes.fromhex(body)))
    # Base32 must ignore label case: DNS names are case-insensitive and
    # resolvers may randomize it (0x20). Base64 alphabets stay case-sensitive.
    upper = body.upper()
    padded8 = upper + "=" * (-len(upper) % 8)
    padded4 = body + "=" * (-len(body) % 4)
    if all(ch in B32_ALPHABET for ch in upper):
        with contextlib.suppress(binascii.Error, ValueError):
            candidates.append(("base32", base64.b32decode(padded8)))
    if all(ch in B64URL_ALPHABET for ch in body):
        with contextlib.suppress(binascii.Error, ValueError):
            candidates.append(("base64url", base64.urlsafe_b64decode(padded4)))
    if all(ch in B64_ALPHABET for ch in body):
        with contextlib.suppress(binascii.Error, ValueError):
            candidates.append(("base64", base64.b64decode(padded4, validate=True)))
    for encoding, data in candidates:
        if len(data) < MIN_DECODED_BYTES or data in seen:
            continue
        if printable_ratio(data) < PRINTABLE_RATIO:
            continue
        seen.add(data)
        entries.append(
            {
                "label": label[:100],
                "encoding": encoding,
                "text": data.decode("utf-8", errors="replace")[:200],
            }
        )
        if len(entries) >= DECODED_LIMIT:
            break
    return entries


def parse_query(packet, start=12):
    """Return (question_wire_bytes, qname_labels, qtype) or None for malformed input."""
    if len(packet) < 12:
        return None
    if int.from_bytes(packet[2:4], "big") & 0x8000:
        return None  # a response, not a query
    if int.from_bytes(packet[4:6], "big") < 1:
        return None
    offset = start
    labels = []
    while True:
        if offset >= len(packet):
            return None
        length = packet[offset]
        if length & 0xC0:
            # Compression pointers never appear in a question this sink must answer.
            return None
        offset += 1
        if length == 0:
            break
        if offset + length > len(packet) or offset + length - start > 254:
            return None
        labels.append(packet[offset : offset + length])
        offset += length
    if offset + 4 > len(packet):
        return None
    # The echoed question carries its QTYPE and QCLASS; resolvers reject replies without them.
    qtype = int.from_bytes(packet[offset : offset + 2], "big")
    return packet[start : offset + 4], labels, qtype


def build_response(query_id, question, qtype, answer):
    header = query_id + (0x8180).to_bytes(2, "big")
    answer_count = 1 if qtype == 1 else 0
    header += (1).to_bytes(2, "big") + answer_count.to_bytes(2, "big")
    header += (0).to_bytes(2, "big") + (0).to_bytes(2, "big")
    response = header + question
    if answer_count:
        # 0xC00C points at the question name at offset 12.
        response += b"\xc0\x0c" + (1).to_bytes(2, "big") + (1).to_bytes(2, "big")
        response += ANSWER_TTL.to_bytes(4, "big") + (4).to_bytes(2, "big") + answer
    return response


def label_text(label):
    return "".join(
        chr(byte)
        if chr(byte).isascii() and (chr(byte).isalnum() or byte == 45)
        else f"\\{byte:03d}"
        for byte in label
    )


def log_question(log, source_ip, parsed, *, capture_incomplete=False):
    question, labels, qtype = parsed
    decoded = []
    for label in labels:
        decoded.extend(decode_label(label.decode("ascii", errors="backslashreplace")))
        if len(decoded) >= DECODED_LIMIT:
            break
    record = {
        "kind": "dns",
        "ts": time.time(),
        "source_ip": source_ip,
        "qname": ".".join(label_text(label) for label in labels),
        "qtype": QTYPE_NAMES.get(qtype, qtype),
        "decoded": decoded[:DECODED_LIMIT],
    }
    if capture_incomplete:
        record["capture_incomplete"] = True
    log.write(record)


def log_query(log, source_ip, packet, parsed, *, capture_incomplete=False):
    count = int.from_bytes(packet[4:6], "big")
    offset = 12
    questions = []
    for _ in range(min(count, 128)):
        question = parse_query(packet, offset)
        if question is None:
            break
        questions.append(question)
        offset += len(question[0])
    incomplete = (
        capture_incomplete
        or count != 1
        or len(questions) != count
        or offset != len(packet)
        or any(packet[6:12])
    )
    for question in questions:
        log_question(log, source_ip, question, capture_incomplete=incomplete)
    if len(questions) != count:
        log_unparsed(log, source_ip, packet[offset:], capture_incomplete=True)


def handle_query(log, sock, answer, packet, source, *, capture_incomplete=False):
    logged = False
    try:
        parsed = parse_query(packet)
        if parsed is None:
            log_unparsed(log, source[0], packet, capture_incomplete=capture_incomplete)
            return
        log_query(log, source[0], packet, parsed, capture_incomplete=capture_incomplete)
        logged = True
        sock.sendto(build_response(packet[:2], parsed[0], parsed[2], answer), source)
    except Exception:
        # Attacker-controlled input must never stop the sink or vanish unlogged.
        if not logged:
            with contextlib.suppress(Exception):
                log_unparsed(log, source[0], packet, capture_incomplete=capture_incomplete)


def receive(sock):
    """(packet, source, truncated): truncated is the kernel's MSG_TRUNC, i.e.
    bytes the sink never received, not a peer that merely sent a short query."""
    packet, _ancillary, flags, source = sock.recvmsg(PACKET_LIMIT)
    return packet, source, bool(flags & socket.MSG_TRUNC)


def serve(log, sock, answer, stopping):
    while not stopping.is_set():
        try:
            packet, source, truncated = receive(sock)
        except TimeoutError:
            continue
        except OSError:
            os._exit(1)  # a dead socket must not look like a clean stop
        handle_query(log, sock, answer, packet, source, capture_incomplete=truncated)
    # Datagrams queued when the stop arrived are contacts too; drain them.
    sock.setblocking(False)
    while True:
        try:
            packet, source, truncated = receive(sock)
        except OSError:
            break
        handle_query(log, sock, answer, packet, source, capture_incomplete=truncated)


def read_exact(conn, count):
    data = bytearray()
    try:
        while len(data) < count:
            chunk = conn.recv(count - len(data))
            if not chunk:
                break
            data.extend(chunk)
    except OSError:
        pass  # the caller logs the partial bytes as an unparsed contact
    return bytes(data)


def raw_preview(data):
    text = data.decode("utf-8", errors="backslashreplace")
    return "".join(
        ch
        if ch.isprintable()
        else (f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}")
        for ch in text
    )[:RAW_LIMIT]


def log_unparsed(log, source_ip, data, *, capture_incomplete=False):
    record = {
        "kind": "dns",
        "ts": time.time(),
        "source_ip": source_ip,
        "qname": "<unparsed>",
        "qtype": "unknown",
        "decoded": [],
        "raw": raw_preview(data),
    }
    if capture_incomplete:
        record["capture_incomplete"] = True
    log.write(record)


def serve_tcp(log, listener, answer, stopping, active, active_lock):
    """DNS over TCP on the same port: 2-byte length framing, successive frames
    on one connection, sequentially so a stalled peer cannot pile up handlers."""
    while not stopping.is_set():
        try:
            conn, source = listener.accept()
        except TimeoutError:
            continue
        except OSError:
            if stopping.is_set():
                return  # the listener was closed to stop this loop
            os._exit(1)  # a dead listener must not look like a clean stop
        with active_lock:
            active.add(conn)
        try:
            conn.settimeout(TCP_TIMEOUT)
            frames = 0
            while True:
                if frames >= TCP_MAX_FRAMES:
                    # Only flag incomplete capture when another frame actually arrived.
                    extra = read_exact(conn, 2)
                    if extra:
                        log_unparsed(log, source[0], extra, capture_incomplete=True)
                    break
                prefix = b""
                packet = b""
                logged = False
                try:
                    prefix = read_exact(conn, 2)
                    if len(prefix) < 2:
                        if prefix or frames == 0:
                            log_unparsed(log, source[0], prefix)
                        break
                    length = int.from_bytes(prefix, "big")
                    if length > TCP_PACKET_LIMIT:
                        log_unparsed(log, source[0], prefix)
                        break
                    if length < 12:
                        packet = read_exact(conn, length) if length else b""
                        log_unparsed(log, source[0], packet or prefix)
                        frames += 1
                        continue
                    # TCP framing carries up to 64 KiB, unlike the UDP datagram bound.
                    packet = read_exact(conn, length)
                    if len(packet) < length:
                        log_unparsed(log, source[0], packet)
                        break
                    frames += 1
                    parsed = parse_query(packet)
                    if parsed is None:
                        log_unparsed(log, source[0], packet)
                        continue
                    log_query(log, source[0], packet, parsed)
                    logged = True
                    response = build_response(packet[:2], parsed[0], parsed[2], answer)
                    conn.sendall(len(response).to_bytes(2, "big") + response)
                except Exception:
                    if not logged:
                        # Attacker-controlled input must never stop the sink or vanish.
                        with contextlib.suppress(Exception):
                            log_unparsed(log, source[0], packet or prefix)
                    break
        finally:
            with active_lock:
                active.discard(conn)
            with contextlib.suppress(OSError):
                conn.close()


def stop_tcp(listener, thread, stopping, active, active_lock):
    """Stop accepting before snapshotting live connections, then abort them.

    False means a handler is still running and the log may be incomplete.
    """
    stopping.set()
    with contextlib.suppress(OSError):
        listener.close()
    if thread.ident is not None:  # ident is None until the thread is started
        thread.join(SHUTDOWN_SECONDS)
    with active_lock:
        pending = list(active)
    for conn in pending:
        with contextlib.suppress(OSError):
            conn.shutdown(socket.SHUT_RDWR)
    if thread.ident is not None:
        thread.join(SHUTDOWN_SECONDS)
    return not thread.is_alive()


def main():
    parser = argparse.ArgumentParser(description="DNS (UDP+TCP) sink for BaitWatch scans")
    parser.add_argument("--log", required=True)
    parser.add_argument("--answer", required=True, help="IPv4 address returned for A queries")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=53)
    args = parser.parse_args()
    try:
        address = ipaddress.IPv4Address(args.answer)
    except ValueError:
        parser.error(f"--answer must be an IPv4 address, got {args.answer!r}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((args.bind, args.port))
        tcp.bind((args.bind, args.port))
        tcp.listen(8)
    except OSError as exc:
        print(f"dns_sink: cannot bind {args.bind}:{args.port}: {exc}", file=sys.stderr)
        return 1
    stopping = threading.Event()
    active: set[socket.socket] = set()
    active_lock = threading.Lock()
    signal.signal(signal.SIGTERM, lambda signum, frame: stopping.set())
    try:
        with open(args.log, "a", encoding="utf-8", buffering=1) as log_file:
            log = JsonlLog(log_file)
            # Only after both transports are bound can the host rely on both.
            log.write({"kind": "ready", "ts": time.time(), "sink": "dns"})
            answer = socket.inet_aton(str(address))
            sock.settimeout(POLL_SECONDS)
            tcp.settimeout(POLL_SECONDS)
            tcp_thread = threading.Thread(
                target=serve_tcp,
                args=(log, tcp, answer, stopping, active, active_lock),
                daemon=True,
            )
            tcp_thread.start()
            serve(log, sock, answer, stopping)
            if not stop_tcp(tcp, tcp_thread, stopping, active, active_lock):
                print("dns_sink: a TCP handler did not stop", file=sys.stderr)
                os._exit(1)  # no stopped record; the host must see an incomplete sink
            log.close()
    except OSError as exc:
        print(f"dns_sink: cannot write log: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
