"""Required Linux Docker checks: these must not silently skip on a broken host."""

import ipaddress
import json
import socket
import subprocess
import threading
import time
from pathlib import Path

import docker
import pytest
from docker.errors import NotFound

from run.evidence import State
from run.sandbox import SCAN_LABEL, Sandbox, SandboxConfig, SandboxError, detonate
from run.verdict import CAGE_HOME

pytestmark = pytest.mark.docker
PYTHON_IMAGE = "python:3.12-alpine"


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


def assert_resources_removed(engine, sandbox, *service_ids):
    for identifier in (sandbox.container_id, *service_ids):
        if identifier:
            with pytest.raises(NotFound):
                engine.containers.get(identifier)
    if sandbox.network_id:
        with pytest.raises(NotFound):
            engine.networks.get(sandbox.network_id)
    assert not sandbox.staged_path.parent.exists()


def test_network_mount_limits_and_cleanup(repo: Path, tmp_path: Path, engine, monkeypatch):
    outside = tmp_path / "host-only"
    outside.write_text("DO-NOT-COPY-THIS-FIXTURE")
    (repo / "host-link").symlink_to(outside)
    monkeypatch.setenv("BW_HOST_SECRET", "NOT-A-REAL-SECRET-ENVIRONMENT-FIXTURE")
    sandbox = Sandbox(repo, SandboxConfig(image=PYTHON_IMAGE))
    code = r"""
import http.client, os, pathlib, socket, sys, time
assert os.getuid() == 65532
assert 'BW_HOST_SECRET' not in os.environ
assert not pathlib.Path('/var/run/docker.sock').exists()
assert pathlib.Path('/repo/README.md').read_text() == 'A benign fixture.\n'
assert pathlib.Path('/repo/host-link').is_symlink()
assert not pathlib.Path('/repo/host-link').exists()
try:
    pathlib.Path('/should-not-write').write_text('bad')
except OSError: pass
else: raise AssertionError('write unexpectedly allowed: /should-not-write')
# The staged copy is writable so cage file changes can be detected; the host repo is never mounted.
pathlib.Path('/repo/README.md').write_text('cage was here\n')
assert pathlib.Path('/repo/README.md').read_text() == 'cage was here\n'
pathlib.Path('/repo/cage-marker.txt').write_text('marker\n')
deadline = time.monotonic() + 4
while True:
    try:
        conn = http.client.HTTPConnection(sys.argv[1], 80, timeout=1)
        conn.request('GET', '/')
        response = conn.getresponse()
        assert response.status == 200
        response.read(); conn.close(); break
    except OSError:
        if time.monotonic() >= deadline: raise
        time.sleep(0.05)
for address in ('1.1.1.1','8.8.8.8'):
    try:
        connection = socket.create_connection((address,443),timeout=0.5)
    except OSError: pass
    else:
        connection.close(); raise AssertionError('public TCP egress reachable')
query = bytes.fromhex('123401000001000000000000') + b'\x04evil\x07example\x00\x00\x01\x00\x01'
for address in ('1.1.1.1','8.8.8.8'):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.settimeout(0.5)
    try:
        sock.sendto(query,(address,53)); sock.recvfrom(1024)
    except OSError: pass
    else: raise AssertionError('public DNS reachable')
    finally: sock.close()
try:
    socket.getaddrinfo('example.com', 80)
except OSError: pass
else: raise AssertionError('name resolution reached a public resolver')
print('ISOLATION_OK'); print('STDERR_OK', file=sys.stderr)
"""
    with sandbox:
        service = sandbox.start_service(
            "http", PYTHON_IMAGE, ["python", "-m", "http.server", "80", "--bind", "0.0.0.0"]
        )
        result = sandbox.run_command(["python", "-c", code, sandbox.http_ip])
        assert result.exit_code == 0, result.model_dump_json()
        assert result.stdout == "ISOLATION_OK\n"
        assert result.stderr == "STDERR_OK\n"
        assert not sandbox.evidence.errors
        cage = engine.containers.get(sandbox.container_id)
        config = cage.attrs["HostConfig"]
        assert config["ReadonlyRootfs"]
        assert config["Memory"] == config["MemorySwap"] == 256 * 1024 * 1024
        assert config["NanoCpus"] == 500_000_000
        assert config["PidsLimit"] == 64
        assert config["CapDrop"] == ["ALL"]
        assert "no-new-privileges:true" in config["SecurityOpt"]
        assert not config["Privileged"]
        assert not config["PortBindings"]
        assert cage.attrs["Config"]["User"] == "65532:65532"
        assert cage.attrs["Mounts"][0]["Source"] != str(repo)
        # Writable on purpose: writes land in the disposable copy and are traced.
        assert cage.attrs["Mounts"][0]["RW"]
        assert list(cage.attrs["NetworkSettings"]["Networks"]) == [sandbox.name]
        network = engine.networks.get(sandbox.network_id)
        assert network.attrs["Internal"]
        assert network.attrs["IPAM"]["Config"][0]["Subnet"] == sandbox.subnet
    assert (repo / "README.md").read_text() == "A benign fixture.\n"
    assert not (repo / "cage-marker.txt").exists()
    assert sandbox.evidence.status == "incomplete"
    assert sandbox.evidence.components.sandbox == State.COMPLETE
    assert sandbox.evidence.components.http_sink == State.NOT_RUN
    assert_resources_removed(engine, sandbox, service.id)


def host_ipv4_addresses() -> list[str]:
    output = subprocess.run(
        ["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, check=True
    ).stdout
    return [line.split()[3].split("/")[0] for line in output.splitlines()]


def host_wildcard_tcp_ports() -> set[int]:
    # A host firewall may drop a fresh test port while allowing real services such as sshd.
    output = subprocess.run(["ss", "-ltnH"], capture_output=True, text=True, check=True).stdout
    ports = set()
    for line in output.splitlines():
        address, _, port = line.split()[3].rpartition(":")
        if address in {"0.0.0.0", "*"}:
            ports.add(int(port))
    return ports


def test_cage_cannot_reach_host_services(repo: Path, engine):
    listener = socket.create_server(("0.0.0.0", 0))
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    accepted: list[tuple] = []
    stop = threading.Event()

    def accept() -> None:
        while not stop.is_set():
            try:
                connection, peer = listener.accept()
            except TimeoutError:
                continue
            accepted.append(peer)
            connection.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    code = r"""
import socket, sys
for target in sys.argv[1:]:
    address, port = target.rsplit(':', 1)
    try:
        socket.create_connection((address, int(port)), timeout=1).close()
    except OSError:
        continue
    print('REACHED', target)
"""
    try:
        with Sandbox(repo, SandboxConfig(image=PYTHON_IMAGE)) as sandbox:
            network = engine.networks.get(sandbox.network_id)
            gateway_subnet = ipaddress.IPv4Network(sandbox.subnet)
            targets = {str(gateway_subnet.network_address + 1), *host_ipv4_addresses()}
            gateway = network.attrs["IPAM"]["Config"][0].get("Gateway")
            if gateway:
                targets.add(gateway)
            ports = {port, *host_wildcard_tcp_ports()}
            pairs = sorted(f"{address}:{p}" for address in targets for p in ports)
            result = sandbox.run_command(["python", "-c", code, *pairs])
        assert result.exit_code == 0, result.model_dump_json()
        assert "REACHED" not in result.stdout
        assert not accepted
        assert not gateway
    finally:
        stop.set()
        thread.join()
        listener.close()


def test_command_exit_code_is_preserved(repo: Path, engine):
    sandbox = Sandbox(repo)
    with sandbox:
        result = sandbox.run_command(["sh", "-c", "echo failed >&2; exit 7"])
        assert result.exit_code == 7
        assert result.stderr == "failed\n"
    assert sandbox.evidence.status == "error"
    assert sandbox.evidence.errors[0].code == "COMMAND_FAILED"
    assert_resources_removed(engine, sandbox)


def test_command_timeout_kills_container_and_cleans_up(repo: Path, engine):
    sandbox = Sandbox(repo, SandboxConfig(timeout_seconds=1))
    started = time.monotonic()
    with sandbox:
        result = sandbox.run_command(["sleep", "30"])
        assert result.timed_out
    assert time.monotonic() - started < 12
    assert sandbox.evidence.status == "error"
    assert any(error.code == "COMMAND_TIMEOUT" for error in sandbox.evidence.errors)
    assert_resources_removed(engine, sandbox)


def test_output_flood_is_bounded_and_cleans_up(repo: Path, engine):
    sandbox = Sandbox(repo, SandboxConfig(image=PYTHON_IMAGE, max_output_bytes=1024))
    with sandbox:
        result = sandbox.run_command(["python", "-c", "print('x'*1000000)"])
        assert result.output_truncated
        assert len(result.stdout.encode()) + len(result.stderr.encode()) <= 1024
    assert any(error.code == "OUTPUT_TRUNCATED" for error in sandbox.evidence.errors)
    assert_resources_removed(engine, sandbox)


def test_missing_image_fails_closed_without_implicit_pull(repo: Path, engine):
    evidence = detonate(repo, config=SandboxConfig(image="baitwatch-does-not-exist:local-test"))
    assert evidence.status == "error"
    assert evidence.errors
    assert not engine.containers.list(
        all=True, filters={"label": f"{SCAN_LABEL}={evidence.scan_id}"}
    )
    assert not engine.networks.list(filters={"label": f"{SCAN_LABEL}={evidence.scan_id}"})


def test_subnet_collision_does_not_remove_someone_elses_network(repo: Path, engine, monkeypatch):
    owner = Sandbox(repo)
    with owner:
        occupied = owner.subnet
        unrelated = engine.networks.get(owner.network_id)
        monkeypatch.setattr("run.sandbox.DEFAULT_SUBNET", occupied)
        with Sandbox(repo) as sandbox:
            chosen = ipaddress.IPv4Network(sandbox.subnet)
            assert chosen.subnet_of(ipaddress.IPv4Network("10.13.0.0/16"))
            assert chosen != ipaddress.IPv4Network(occupied)
            result = sandbox.run_command(["true"])
            assert result.exit_code == 0
            assert not sandbox.evidence.errors
        assert engine.networks.get(unrelated.id).id == unrelated.id
        explicit = Sandbox(repo, SandboxConfig(subnet=occupied))
        with pytest.raises(SandboxError, match="overlaps"), explicit:
            pytest.fail("an explicitly configured overlap must fail closed")
        assert engine.networks.get(unrelated.id).id == unrelated.id
        assert explicit.evidence.status == "error"
        assert not explicit.staged_path.parent.exists()
    assert_resources_removed(engine, owner)


def test_two_sandboxes_run_side_by_side(repo: Path, tmp_path: Path, engine):
    second_repo = tmp_path / "second-repo"
    second_repo.mkdir()
    (second_repo / "README.md").write_text("A benign fixture.\n")
    first = Sandbox(repo)
    second = Sandbox(second_repo)
    with first, second:
        assert first.subnet != second.subnet
        one = first.run_command(["sh", "-c", "echo first ready"])
        two = second.run_command(["sh", "-c", "echo second ready"])
        assert one.exit_code == 0 and one.stdout == "first ready\n", one.model_dump_json()
        assert two.exit_code == 0 and two.stdout == "second ready\n", two.model_dump_json()
        assert not first.evidence.errors
        assert not second.evidence.errors
    assert_resources_removed(engine, first)
    assert_resources_removed(engine, second)


def test_detonate_success_is_still_incomplete(repo: Path, engine):
    evidence = detonate(repo, ["echo", "sandbox ready"])
    assert evidence.tool_log[0].stdout == "sandbox ready\n"
    assert evidence.status == "incomplete"
    assert not evidence.errors
    # Plain JSON consumers must see that remaining components have not run.
    data = json.loads(evidence.model_dump_json())
    assert data["components"]["decoy"] == "not_run"


def test_repository_file_growth_is_bounded_and_recorded(repo: Path, engine):
    from run.staging import StagingLimits

    config = SandboxConfig(image=PYTHON_IMAGE, staging=StagingLimits(max_file_bytes=4096))
    sandbox = Sandbox(repo, config)
    with sandbox:
        sandbox.trace_before()
        result = sandbox.run_command(
            ["sh", "-c", "dd if=/dev/zero of=/repo/flood bs=1024 count=32 2>/dev/null; true"]
        )
        assert result.exit_code == 0
        assert (sandbox.staged_path / "flood").stat().st_size <= 4096
        sandbox.trace_after()
    assert any(error.code == "REPO_WRITE_LIMIT" for error in sandbox.evidence.errors)
    assert sandbox.evidence.status == "error"
    assert_resources_removed(engine, sandbox)


def test_home_writes_are_traced_and_disposable(repo, engine):
    from run.evidence import State
    from run.llm import ScriptedBackend, ToolCall
    from run.scan import run_scan
    from run.verdict import ReadOutcome, fuse

    report = run_scan(
        repo,
        read_scanner=lambda path: ReadOutcome(status=State.COMPLETE, verdict="clean"),
        backend=ScriptedBackend(
            [
                [
                    ToolCall(
                        name="run_cmd",
                        arguments={
                            "command": 'test "$HOME" = /cage/home && mkdir -p "$HOME/.cache" && '
                            'echo cache > "$HOME/.cache/tool" && echo bad > "$HOME/.bashrc"'
                        },
                    )
                ]
            ]
        ),
    )
    assert report.verdict == "BLOCK", report.reason
    assert report.run.status == "complete", report.run.errors
    assert {f"{CAGE_HOME}/.bashrc", f"{CAGE_HOME}/.cache/tool"} <= {
        entry.path for entry in report.run.file_diffs
    }
    assert fuse(ReadOutcome(status=State.COMPLETE, verdict="clean"), report.run).verdict == "BLOCK"
    assert not (repo / ".bashrc").exists()
