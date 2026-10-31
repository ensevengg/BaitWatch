"""Standalone HTTP/TLS sink: logs every request and the TLS ClientHello SNI
without terminating TLS. Stdlib only; bind-mounted into the sink container."""

import argparse
import contextlib
import json
import os
import signal
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
# Real ClientHellos pass 16 KiB (post-quantum key shares, ECH, padding); the
# bound is four maximal plaintext records, and anything past it is flagged
# capture_incomplete rather than silently read as a null SNI.
TLS_READ_LIMIT = 64 * 1024
TLS_DRAIN_SECONDS = 1.0
TLS_DRAIN_LIMIT = 16 * 1024
EXTRA_PREFIX_BYTES = 16
RAW_LIMIT = 200
POLL_SECONDS = 0.2
SHUTDOWN_SECONDS = 1.5
RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 2\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"ok"
)
CONTINUE = b"HTTP/1.1 100 Continue\r\n\r\n"


class JsonlLog:
    """One JSON object per line, flushed immediately; stops logging at the cap.

    HTTP, TLS and refusal paths write concurrently, so every cap check, append
    and flush happens under one lock. A failed write kills the process: a clean
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
                print(f"http_sink: cannot write log: {exc}", file=sys.stderr)
            os._exit(1)

    def write(self, record):
        with self._lock:
            self._write_locked(record)

    def close(self):
        """Acknowledge a graceful stop; no record can follow this one."""
        with self._lock:
            self._write_locked({"kind": "stopped", "ts": time.time(), "sink": "http"})
            self._closed = True


def first_handshake(buf, *, partial=False):
    """Concatenated payloads of the leading handshake records; partial keeps a
    trailing record cut short by the read limit or a stalled peer."""
    payload = bytearray()
    offset = 0
    while offset + 5 <= len(buf) and len(payload) < TLS_READ_LIMIT:
        if buf[offset] != 0x16:  # handshake
            break
        length = int.from_bytes(buf[offset + 3 : offset + 5], "big")
        if offset + 5 + length > len(buf):
            if partial:
                payload += buf[offset + 5 :]
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
            return "".join(
                chr(byte)
                if chr(byte).isascii() and (chr(byte).isalnum() or byte in (45, 46))
                else f"\\{byte:03d}"
                for byte in name
            )
        pos += 3 + entry_length
    return None


def parse_sni(buf):
    """Best-effort SNI from the handshake records, a cut-short trailing record
    included; None for anything unclear."""
    hello = first_handshake(buf, partial=True)
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
    """(head, None, False) once a request head arrives, else (None, raw, truncated).

    truncated marks a head cut at HEAD_LIMIT — bytes the sink never received —
    not a peer that merely stalled: a stall keeps everything that was sent.
    """
    buffer = bytearray()
    while True:
        head, separator, rest = bytes(buffer).partition(b"\r\n\r\n")
        if separator:
            if len(head) + len(separator) > HEAD_LIMIT:
                return None, bytes(buffer), True
            return (head, separator, rest), None, False
        if len(buffer) > HEAD_LIMIT:
            return None, bytes(buffer), True
        try:
            chunk = conn.recv(4096)
        except OSError:
            break  # a stalled or reset peer still leaves the bytes it sent
        if not chunk:
            break
        buffer.extend(chunk)
    return None, bytes(buffer), False


def raw_preview(data: bytes) -> str:
    """Printable one-line preview: control characters survive as escapes."""
    text = data[:RAW_LIMIT].decode("utf-8", errors="backslashreplace")
    return "".join(
        ch
        if ch.isprintable()
        else (f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}")
        for ch in text
    )


def handle_http(conn, addr, log):
    conn.settimeout(CONNECTION_TIMEOUT)
    head, raw, head_truncated = read_head(conn)
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
            "headers_truncated": head_truncated,
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
    headers_truncated = len(lines) - 1 > MAX_HEADERS
    for line in lines[1 : MAX_HEADERS + 1]:
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        key = name.strip().decode("ascii", errors="backslashreplace").lower()
        if not key:
            continue
        stripped = value.strip()
        if len(stripped) > HEADER_VALUE_LIMIT:
            headers_truncated = True
        text = stripped[:HEADER_VALUE_LIMIT].decode("utf-8", errors="replace")
        headers[key] = f"{headers[key]}, {text}" if key in headers else text
        if key == "host":
            host = headers[key]
    length_text = headers.get("content-length", "0")
    invalid_length = not length_text.isascii() or not length_text.isdigit()
    try:
        content_length = 0 if invalid_length else int(length_text, 10)
    except ValueError:
        content_length = 0
        invalid_length = True
    chunked = bool(headers.get("transfer-encoding"))
    body = bytearray(body_prefix[:BODY_LIMIT])
    # Chunked framing carries no length to satisfy, so its drain runs to the cap.
    needed = (BODY_LIMIT if chunked or invalid_length else min(content_length, BODY_LIMIT)) - len(
        body
    )
    if needed > 0 and "100-continue" in headers.get("expect", "").lower():
        # The client is holding its body until an interim response arrives.
        with contextlib.suppress(OSError):
            conn.sendall(CONTINUE)
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
            "headers_truncated": headers_truncated,
            "body": body.decode("utf-8", errors="replace"),
            # Chunked framing is never decoded, so its capture cannot claim to be
            # whole; a connection that ends early is as truncated as one past the cap.
            "body_truncated": chunked
            or invalid_length
            or content_length > BODY_LIMIT
            or len(body) < content_length,
            **({"raw": raw_preview(lines[0])} if len(parts) > 3 else {}),
        }
    )
    conn.sendall(RESPONSE)


def _first_record_length(data: bytes) -> int | None:
    if len(data) < 5 or data[0] != 0x16:
        return None
    length = 5 + int.from_bytes(data[3:5], "big")
    return length if length <= len(data) else None


def _single_hello_record_length(data: bytes) -> int | None:
    length = _first_record_length(data)
    if length is None or length < 9:
        return None
    payload = data[5:length]
    if payload[0] != 0x01 or 4 + int.from_bytes(payload[1:4], "big") != len(payload):
        return None
    return length


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
    single_length = _single_hello_record_length(bytes(buffer))
    if single_length is not None:
        deadline = time.monotonic() + TLS_DRAIN_SECONDS
        while len(buffer) < TLS_READ_LIMIT and len(buffer) - single_length < TLS_DRAIN_LIMIT:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            conn.settimeout(remaining)
            try:
                chunk = conn.recv(min(4096, TLS_DRAIN_LIMIT - (len(buffer) - single_length)))
            except OSError:
                break
            if not chunk:
                break
            buffer.extend(chunk)
    data = bytes(buffer)
    record_length = _first_record_length(data)
    extra = data[record_length:] if record_length is not None else data
    record = {
        "kind": "tls",
        "ts": time.time(),
        "source_ip": addr[0],
        "sni": parse_sni(data),
        "hello_only": single_length is not None and len(data) == single_length,
        "hello_record_length": record_length,
        "total_bytes": len(data),
        "extra_bytes": len(extra),
    }
    if extra:
        record["extra_prefix"] = extra[:EXTRA_PREFIX_BYTES].hex()
    # A TLS-looking prefix without a whole ClientHello was cut short by the read
    # limit, a stall or an early end; the SNI may still be recoverable, but the
    # capture cannot pose as complete.
    if data[:1] == b"\x16" and not client_hello_done(data):
        record["capture_incomplete"] = True
    log.write(record)


class Sink:
    def __init__(self, log):
        self.log = log
        self._lock = threading.Lock()
        self._active = 0
        self._connections: set[socket.socket] = set()
        self._threads: set[threading.Thread] = set()
        self._stopping = threading.Event()

    def _track_and_start(self, conn, thread):
        # Starting under the lock means stop() can never snapshot a tracked
        # worker that has not been started yet.
        with self._lock:
            if self._stopping.is_set() or self._active >= MAX_CONNECTIONS:
                return False
            self._active += 1
            self._connections.add(conn)
            self._threads.add(thread)
            try:
                thread.start()
            except BaseException:
                self._active -= 1
                self._connections.discard(conn)
                self._threads.discard(thread)
                raise
            return True

    def _release(self, conn):
        with self._lock:
            self._active -= 1
            self._connections.discard(conn)
            self._threads.discard(threading.current_thread())

    def accept_loop(self, listener, handler):
        while not self._stopping.is_set():
            try:
                conn, addr = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                os._exit(1)  # a dead listener must not look like a clean stop
            thread = threading.Thread(target=self._serve, args=(conn, addr, handler), daemon=True)
            if not self._track_and_start(conn, thread):
                # A dropped contact must stay evidence; the host turns the
                # refusal into a log problem so the component cannot look complete.
                self.log.write({"kind": "refused", "ts": time.time(), "source_ip": addr[0]})
                with contextlib.suppress(OSError):
                    conn.close()
                continue

    def _serve(self, conn, addr, handler):
        try:
            handler(conn, addr, self.log)
        except Exception:
            pass  # attacker-controlled input must never kill the sink
        finally:
            self._release(conn)
            with contextlib.suppress(OSError):
                conn.close()

    def stop(self):
        """Abort in-flight reads so their partial evidence is logged within the bound.

        False means a handler is still running and the log may be incomplete.
        """
        self._stopping.set()
        with self._lock:
            connections = list(self._connections)
            threads = list(self._threads)
        for conn in connections:
            with contextlib.suppress(OSError):
                conn.shutdown(socket.SHUT_RDWR)
        for thread in threads:
            if thread.ident is not None:  # ident is None until the thread is started
                thread.join(SHUTDOWN_SECONDS)
        with self._lock:
            remaining = list(self._threads)
        return not any(thread.is_alive() for thread in remaining)


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
            sock.settimeout(POLL_SECONDS)
            listeners.append(sock)
    except OSError as exc:
        for sock in listeners:
            sock.close()
        print(f"http_sink: cannot bind {args.bind}: {exc}", file=sys.stderr)
        return 1
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda signum, frame: stopping.set())
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
            while not stopping.is_set() and all(thread.is_alive() for thread in threads):
                stopping.wait(POLL_SECONDS)
            if not stopping.is_set():
                return 1  # a listener died on its own; the host must see a failure
            handlers_stopped = sink.stop()
            for thread in threads:
                thread.join(SHUTDOWN_SECONDS)
            if any(thread.is_alive() for thread in threads):
                print("http_sink: an accept loop did not stop", file=sys.stderr)
                os._exit(1)
            for sock in listeners:
                with contextlib.suppress(OSError):
                    sock.close()
            if not handlers_stopped:
                print("http_sink: a connection handler did not stop", file=sys.stderr)
                os._exit(1)  # no stopped record; the host must see an incomplete sink
            log.close()
    except OSError as exc:
        print(f"http_sink: cannot write log: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
