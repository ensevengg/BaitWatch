"""Standalone DNS sink (UDP and TCP): answers everything, logs every query and
any data hidden in labels. Stdlib only; bind-mounted into the sink container."""

import argparse
import base64
import binascii
import contextlib
import ipaddress
import json
import socket
import sys
import threading
import time

LOG_CAP_BYTES = 4 * 1024 * 1024
PACKET_LIMIT = 4096
ANSWER_TTL = 30
DECODED_LIMIT = 8
MIN_DECODED_BYTES = 4
MIN_LABEL_CHARS = 8
PRINTABLE_RATIO = 0.9
TCP_TIMEOUT = 5.0

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
    """One JSON object per line, flushed immediately; stops logging at the cap."""

    def __init__(self, file):
        self._file = file
        self._written = 0
        self.truncated = False

    def write(self, record):
        if self.truncated:
            return
        line = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
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
    padded8 = body + "=" * (-len(body) % 8)
    padded4 = body + "=" * (-len(body) % 4)
    if all(ch in B32_ALPHABET for ch in body):
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


def parse_query(packet):
    """Return (question_wire_bytes, qname_labels, qtype) or None for malformed input."""
    if len(packet) < 12:
        return None
    if int.from_bytes(packet[2:4], "big") & 0x8000:
        return None  # a response, not a query
    if int.from_bytes(packet[4:6], "big") < 1:
        return None
    offset = 12
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
        if offset + length > len(packet) or len(labels) >= 128:
            return None
        labels.append(packet[offset : offset + length])
        offset += length
    if offset + 4 > len(packet):
        return None
    return packet[12:offset], labels, int.from_bytes(packet[offset : offset + 2], "big")


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
    return label.decode("utf-8", errors="backslashreplace")


def log_query(log, source_ip, packet, parsed):
    question, labels, qtype = parsed
    decoded = []
    for label in labels:
        decoded.extend(decode_label(label_text(label)))
        if len(decoded) >= DECODED_LIMIT:
            break
    log.write(
        {
            "kind": "dns",
            "ts": time.time(),
            "source_ip": source_ip,
            "qname": ".".join(label_text(label) for label in labels)[:500],
            "qtype": QTYPE_NAMES.get(qtype, qtype),
            "decoded": decoded[:DECODED_LIMIT],
        }
    )


def serve(log, sock, answer):
    while True:
        try:
            packet, source = sock.recvfrom(PACKET_LIMIT)
        except OSError:
            return  # a dead socket ends the sink so the host sees it exit
        try:
            parsed = parse_query(packet)
            if parsed is None:
                continue
            log_query(log, source[0], packet, parsed)
            sock.sendto(build_response(packet[:2], parsed[0], parsed[2], answer), source)
        except Exception:
            # Attacker-controlled input must never stop the sink; this query is lost.
            continue


def read_exact(conn, count):
    data = bytearray()
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise OSError("connection closed mid-message")
        data.extend(chunk)
    return bytes(data)


def serve_tcp(log, listener, answer):
    """DNS over TCP on the same port: 2-byte length framing, one query per
    connection, sequentially so a stalled peer cannot pile up handlers."""
    while True:
        try:
            conn, source = listener.accept()
        except OSError:
            return  # a dead listener ends the sink so the host sees it exit
        try:
            conn.settimeout(TCP_TIMEOUT)
            length = int.from_bytes(read_exact(conn, 2), "big")
            if not 12 <= length <= PACKET_LIMIT:
                continue
            packet = read_exact(conn, length)
            parsed = parse_query(packet)
            if parsed is None:
                continue
            log_query(log, source[0], packet, parsed)
            response = build_response(packet[:2], parsed[0], parsed[2], answer)
            conn.sendall(len(response).to_bytes(2, "big") + response)
        except Exception:
            continue  # attacker-controlled input must never stop the sink
        finally:
            with contextlib.suppress(OSError):
                conn.close()


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
    try:
        with open(args.log, "a", encoding="utf-8", buffering=1) as log_file:
            log = JsonlLog(log_file)
            # Only after both transports are bound can the host rely on both.
            log.write({"kind": "ready", "ts": time.time(), "sink": "dns"})
            answer = socket.inet_aton(str(address))
            threading.Thread(target=serve_tcp, args=(log, tcp, answer), daemon=True).start()
            serve(log, sock, answer)
    except OSError as exc:
        print(f"dns_sink: cannot write log: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
