"""Standalone HTTP/TLS sink: logs every request and the TLS ClientHello SNI
without terminating TLS. Stdlib only; bind-mounted into the sink container."""

import argparse
import contextlib
import json
import socket
import sys
import threading
import time

LOG_CAP_BYTES = 4 * 1024 * 1024
CONNECTION_TIMEOUT = 5.0
MAX_CONNECTIONS = 16
HEAD_LIMIT = 32 * 1024
MAX_HEADERS = 100
HEADER_VALUE_LIMIT = 4096
METHOD_LIMIT = 32
PATH_LIMIT = 2048
BODY_LIMIT = 64 * 1024
TLS_READ_LIMIT = 16 * 1024
RAW_LIMIT = 200
RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 2\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"ok"
)


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


def first_handshake(buf):
    """Concatenated payloads of the leading handshake records."""
    payload = bytearray()
    offset = 0
    while offset + 5 <= len(buf) and len(payload) < TLS_READ_LIMIT:
        if buf[offset] != 0x16:  # handshake
            break
        length = int.from_bytes(buf[offset + 3 : offset + 5], "big")
        if offset + 5 + length > len(buf):
            break
        payload += buf[offset + 5 : offset + 5 + length]
        offset += 5 + length
    return bytes(payload)


def client_hello_done(buf):
    if buf and buf[0] != 0x16:
        return True  # not TLS at all; nothing more to read for
    hello = first_handshake(buf)
    return len(hello) >= 4 and 4 + int.from_bytes(hello[1:4], "big") <= len(hello)


def server_name_from(data):
    list_end = min(2 + int.from_bytes(data[:2], "big"), len(data))
    pos = 2
    while pos + 3 <= list_end:
        entry_length = int.from_bytes(data[pos + 1 : pos + 3], "big")
        if data[pos] == 0 and entry_length and pos + 3 + entry_length <= list_end:
            name = data[pos + 3 : pos + 3 + entry_length]
            return name.decode("ascii", errors="backslashreplace")[:255]
        pos += 3 + entry_length
    return None


def parse_sni(buf):
    """Best-effort SNI from concatenated handshake records; None for anything unclear."""
    hello = first_handshake(buf)
    if len(hello) < 4 or hello[0] != 0x01:  # ClientHello
        return None
    body = hello[4 : 4 + int.from_bytes(hello[1:4], "big")]
    if len(body) < 35:  # client version (2) + random (32) + session id length (1)
        return None
    pos = 34
    pos += 1 + body[pos]  # session id
    if pos + 2 > len(body):
        return None
    pos += 2 + int.from_bytes(body[pos : pos + 2], "big")  # cipher suites
    if pos + 1 > len(body):
        return None
    pos += 1 + body[pos]  # compression methods
    if pos + 2 > len(body):
        return None
    extensions_end = min(pos + 2 + int.from_bytes(body[pos : pos + 2], "big"), len(body))
    pos += 2
    while pos + 4 <= extensions_end:
        extension_type = int.from_bytes(body[pos : pos + 2], "big")
        extension_length = int.from_bytes(body[pos + 2 : pos + 4], "big")
        data = body[pos + 4 : pos + 4 + extension_length]
        if len(data) < extension_length:
            break
        if extension_type == 0:  # server_name
            return server_name_from(data)
        pos += 4 + extension_length
    return None


def read_head(conn):
    """(head, None) once a request head arrives, else (None, raw bytes seen)."""
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer and len(buffer) <= HEAD_LIMIT:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buffer.extend(chunk)
    if b"\r\n\r\n" not in buffer or len(buffer) > HEAD_LIMIT:
        return None, bytes(buffer)
    head = bytes(buffer).partition(b"\r\n\r\n")
    return head, None


def raw_preview(data: bytes) -> str:
    """Printable one-line preview: control characters survive as escapes."""
    text = data.decode("utf-8", errors="backslashreplace")
    return "".join(
        ch
        if ch.isprintable()
        else (f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}")
        for ch in text
    )[:RAW_LIMIT]


def handle_http(conn, addr, log):
    conn.settimeout(CONNECTION_TIMEOUT)
    head, raw = read_head(conn)
    if head is not None:
        lines = head[0].split(b"\r\n")
        parts = lines[0].split()
        if len(parts) >= 2 and len(parts[0]) <= METHOD_LIMIT and len(parts[1]) <= PATH_LIMIT:
            _log_request(conn, addr, log, lines, parts, head[2])
            return
        raw = head[0] + head[2]  # an unparseable request line is still evidence
    # Any TCP contact on the HTTP port is a hit, even with no parseable request.
    log.write(
        {
            "kind": "http",
            "ts": time.time(),
            "source_ip": addr[0],
            "method": "",
            "path": "",
            "host": "",
            "headers": {},
            "body": "",
            "body_truncated": False,
            "raw": raw_preview(raw or b""),
        }
    )


def _log_request(conn, addr, log, lines, parts, body_prefix):
    method = parts[0].decode("ascii", errors="backslashreplace")
    path = parts[1].decode("utf-8", errors="backslashreplace")
    headers = {}
    host = ""
    for line in lines[1 : MAX_HEADERS + 1]:
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        key = name.strip().decode("ascii", errors="backslashreplace").lower()
        if not key:
            continue
        text = value.strip()[:HEADER_VALUE_LIMIT].decode("utf-8", errors="replace")
        headers[key] = f"{headers[key]}, {text}" if key in headers else text
        if key == "host":
            host = headers[key]
    try:
        content_length = max(0, int(headers.get("content-length", "0"), 10))
    except ValueError:
        content_length = 0
    body = bytearray(body_prefix[:BODY_LIMIT])
    needed = min(content_length, BODY_LIMIT) - len(body)
    while needed > 0:
        try:
            chunk = conn.recv(min(needed, 16384))
        except OSError:
            break  # keep the evidence that arrived before the client stalled
        if not chunk:
            break
        body.extend(chunk)
        needed -= len(chunk)
    log.write(
        {
            "kind": "http",
            "ts": time.time(),
            "source_ip": addr[0],
            "method": method,
            "path": path,
            "host": host,
            "headers": headers,
            "body": body.decode("utf-8", errors="replace"),
            "body_truncated": content_length > BODY_LIMIT,
        }
    )
    conn.sendall(RESPONSE)


def handle_tls(conn, addr, log):
    conn.settimeout(CONNECTION_TIMEOUT)
    buffer = bytearray()
    while len(buffer) < TLS_READ_LIMIT:
        try:
            chunk = conn.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        buffer.extend(chunk)
        if client_hello_done(bytes(buffer)):
            break
    log.write(
        {
            "kind": "tls",
            "ts": time.time(),
            "source_ip": addr[0],
            "sni": parse_sni(bytes(buffer)),
        }
    )


class Sink:
    def __init__(self, log):
        self.log = log
        self._lock = threading.Lock()
        self._active = 0

    def _track(self):
        with self._lock:
            if self._active >= MAX_CONNECTIONS:
                return False
            self._active += 1
            return True

    def _release(self):
        with self._lock:
            self._active -= 1

    def accept_loop(self, listener, handler):
        while True:
            try:
                conn, addr = listener.accept()
            except OSError:
                return  # a dead listener ends the sink so the host sees it exit
            if not self._track():
                # A dropped contact must stay evidence; the host turns the
                # refusal into a log problem so the component cannot look complete.
                self.log.write({"kind": "refused", "ts": time.time(), "source_ip": addr[0]})
                with contextlib.suppress(OSError):
                    conn.close()
                continue
            threading.Thread(target=self._serve, args=(conn, addr, handler), daemon=True).start()

    def _serve(self, conn, addr, handler):
        try:
            handler(conn, addr, self.log)
        except Exception:
            pass  # attacker-controlled input must never kill the sink
        finally:
            self._release()
            with contextlib.suppress(OSError):
                conn.close()


def main():
    parser = argparse.ArgumentParser(description="HTTP/TLS sink for BaitWatch scans")
    parser.add_argument("--log", required=True)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--tls-port", type=int, default=443)
    args = parser.parse_args()
    listeners = []
    try:
        for port in (args.http_port, args.tls_port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((args.bind, port))
            sock.listen(MAX_CONNECTIONS)
            listeners.append(sock)
    except OSError as exc:
        for sock in listeners:
            sock.close()
        print(f"http_sink: cannot bind {args.bind}: {exc}", file=sys.stderr)
        return 1
    try:
        with open(args.log, "a", encoding="utf-8", buffering=1) as log_file:
            log = JsonlLog(log_file)
            # Only after both ports are bound can the host rely on both listeners.
            log.write({"kind": "ready", "ts": time.time(), "sink": "http"})
            sink = Sink(log)
            threads = []
            for sock, handler in ((listeners[0], handle_http), (listeners[1], handle_tls)):
                thread = threading.Thread(
                    target=sink.accept_loop, args=(sock, handler), daemon=True
                )
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()
    except OSError as exc:
        print(f"http_sink: cannot write log: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
