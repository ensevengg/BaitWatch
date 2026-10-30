"""Day 6 chaos: sinks and processes under real detonate() must fail closed."""

import contextlib
import threading
import time

import pytest

from run.evidence import State
from run.llm import LLMReply, ToolCall
from run.sandbox import SandboxConfig

pytestmark = pytest.mark.docker
PYTHON_IMAGE = "python:3.12-alpine"
LOG_CAP_BYTES = 4 * 1024 * 1024

# Runs inside the cage only. The scan network has no gateway, so nothing
# off-subnet is routable and the sinks are found from the cage's own address:
# the DNS sink shares the cage's subnet at .53 and answers every A query with
# the HTTP sink's address.
BOOTSTRAP = """\
import fcntl
import socket
import struct


def dns_query(qname):
    query = bytes.fromhex("abcd01000001000000000000")
    for part in qname.split("."):
        query += bytes([len(part)]) + part.encode()
    return query + b"\\x00\\x00\\x01\\x00\\x01"


def sink_ips():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    raw = fcntl.ioctl(probe.fileno(), 0x8915, struct.pack("256s", b"eth0"))[20:24]
    probe.close()
    prefix = socket.inet_ntoa(raw).rsplit(".", 1)[0]
    dns_ip = prefix + ".53"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(dns_query("bootstrap.evil.example"), (dns_ip, 53))
        return dns_ip, socket.inet_ntoa(sock.recvfrom(4096)[0][-4:])
"""


class Scripted:
    """Minimal scripted backend, deliberately independent of run.llm."""

    def __init__(self, steps: list[tuple[str, dict]]) -> None:
        self.steps = list(steps)
        self.count = 0

    def chat(self, messages, tools):
        if not self.steps:
            return LLMReply(text="done")
        name, arguments = self.steps.pop(0)
        self.count += 1
        return LLMReply(
            tool_calls=[ToolCall(id=f"call-{self.count}", name=name, arguments=arguments)]
        )


def test_sink_killed_mid_scan_keeps_hits_and_stays_error(
    repo, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone
):
    code = (
        BOOTSTRAP
        + r"""
import http.client, time

dns_ip, http_ip = sink_ips()
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(2)
    sock.sendto(dns_query("after-kill.evil.example"), (dns_ip, 53))
deadline = time.monotonic() + 8
while time.monotonic() < deadline:
    try:
        conn = http.client.HTTPConnection(http_ip, 80, timeout=2)
        conn.request("GET", "/killed-mid-scan")
        response = conn.getresponse()
        response.read()
        conn.close()
        break
    except OSError:
        pass
time.sleep(0.5)
print("KILL_SCAN_DONE")
"""
    )

    def kill_after_first_hits() -> None:
        killed: set[str] = set()
        deadline = time.monotonic() + 45
        while len(killed) < 2 and time.monotonic() < deadline:
            for instance in recorded_sandbox.instances:
                for role, marker in (("dns", '"kind":"dns"'), ("http", '"kind":"http"')):
                    if role in killed:
                        continue
                    log = instance.sink_log_path(role)
                    if log is None:
                        continue
                    try:
                        hit = marker in log.read_text(errors="replace")
                    except OSError:
                        continue
                    if hit:
                        with contextlib.suppress(Exception):
                            instance.kill_sink(role)
                        killed.add(role)
            time.sleep(0.05)

    killer = threading.Thread(target=kill_after_first_hits, daemon=True)
    killer.start()
    before = tree_digest(repo)
    evidence = run_scan(
        repo,
        ["python", "-c", code],
        config=SandboxConfig(image=PYTHON_IMAGE, timeout_seconds=30),
    )
    killer.join(timeout=5)
    assert not killer.is_alive(), "the sink-kill hook never finished"
    assert evidence.status == "error"
    assert [error.code for error in evidence.errors] == ["SINK_FAILED", "SINK_FAILED"]
    assert evidence.errors[0].message.startswith("dns:")
    assert evidence.errors[1].message.startswith("http:")
    components = evidence.components
    assert components.dns_sink == State.ERROR
    assert components.http_sink == State.ERROR
    assert components.tls_sink == State.ERROR
    assert components.sandbox == State.COMPLETE
    assert components.trace == State.COMPLETE
    assert evidence.dns_hits, "hits logged before the kill were dropped"
    assert evidence.http_hits, "hits logged before the kill were dropped"
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)


# Four identical base64 labels that decode to printable ASCII: the sink logs
# each label's decoding, so one flood record weighs about 1 KiB and a few
# thousand of them pass the 4 MiB cap even when a loaded sink is slow.
FLOOD_LABEL = "bWF0Y2hpbmcgcHJldGVuY2VzIGFuZCBmdWxsIGdyYW50IG1vbmV5"
FLOOD_QNAME = ".".join([FLOOD_LABEL] * 4)


@pytest.mark.timeout(180)
def test_sink_log_flood_truncates_and_stays_bounded(
    repo, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone
):
    code = (
        BOOTSTRAP
        + r"""
import http.client, sys, time

dns_ip, http_ip = sink_ips()
qname = sys.argv[1]
# Records near 400 bytes, so 30000 of them pass the 4 MiB cap nearly three
# times over and the log still reaches the cap even if the sink drops a
# large share. Replies are drained between waves to pace the flood, so the
# sink is keeping up rather than discarding datagrams.
sent = 0
end = time.monotonic() + 35
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(0.5)
    while sent < 30000 and time.monotonic() < end:
        for _ in range(250):
            sock.sendto(dns_query(qname), (dns_ip, 53))
        sent += 250
        # Wait for this wave's replies, not for a timeout after every wave.
        for _ in range(250):
            try:
                sock.recvfrom(4096)
            except TimeoutError:
                break
fat = "x" * 4000
for _ in range(300):
    conn = http.client.HTTPConnection(http_ip, 80, timeout=5)
    conn.request(
        "GET",
        "/" + "p" * 2000,
        headers={"X-Fat-1": fat, "X-Fat-2": fat, "X-Fat-3": fat, "X-Fat-4": fat},
    )
    conn.getresponse().read()
    conn.close()
print("FLOOD_DONE")
"""
    )
    before = tree_digest(repo)
    evidence = run_scan(
        repo,
        ["python", "-c", code, FLOOD_QNAME],
        config=SandboxConfig(image=PYTHON_IMAGE, timeout_seconds=45),
    )
    assert evidence.status == "error"
    assert [error.code for error in evidence.errors] == ["SINK_LOG", "SINK_LOG"]
    assert all("size cap" in error.message for error in evidence.errors)
    components = evidence.components
    assert components.dns_sink == State.ERROR
    assert components.http_sink == State.ERROR
    assert components.tls_sink == State.ERROR
    assert components.sandbox == State.COMPLETE
    assert evidence.dns_hits and evidence.http_hits
    instance = recorded_sandbox.instances[-1]
    for role in ("dns", "http"):
        assert instance.sink_log_sizes[role] <= LOG_CAP_BYTES + 4096
    # Boundedness is asserted through log sizes and hit counts, which are the
    # evidence the host keeps; host memory itself is not measured here.
    assert len(evidence.dns_hits) <= 45_000
    assert len(evidence.http_hits) <= 2_000
    assert tree_digest(repo) == before
    assert_staging_gone(instance, evidence)
    assert_no_leftovers(evidence)


def test_foreground_sleep_hits_the_deadline(
    repo, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone
):
    # The scan deadline also bounds the trace helpers, so it must fit a Python
    # container boot; the sleep still overruns it from inside the cage.
    command = ["sleep", "infinity"]
    before = tree_digest(repo)
    evidence = run_scan(repo, command, config=SandboxConfig(timeout_seconds=10))
    result = evidence.tool_log[0]
    assert result.command == command
    assert result.timed_out, result.model_dump_json()
    assert result.exit_code == 137
    assert [error.code for error in evidence.errors] == ["COMMAND_TIMEOUT"]
    assert evidence.components.sandbox == State.ERROR
    assert evidence.status == "error"
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)


DETACHED_SPAWNS = {
    "background": "sleep 300 >/dev/null 2>&1 &",
    "nohup": "nohup sleep 300 >/dev/null 2>&1 &",
    "setsid": "setsid sleep 300 >/dev/null 2>&1 &",
}


@pytest.mark.parametrize("spawn", DETACHED_SPAWNS.values(), ids=DETACHED_SPAWNS.keys())
def test_detached_background_process_is_swept_and_killed(
    repo, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone, spawn
):
    # The shell exits before the call ends, so the sleep outlives its parent.
    # The in-call probe proves it was really alive under its own pid, and
    # EXEC_LINGERING_KILLED fires only for a sweep kill that then found the
    # cage clear, so nothing is left alive.
    command = (
        f"{spawn} pid=$!; sleep 0.3; "
        "grep -h '^State:' /proc/$pid/status 2>/dev/null || echo BACKGROUND_GONE"
    )
    before = tree_digest(repo)
    evidence = run_scan(
        repo,
        config=SandboxConfig(image=PYTHON_IMAGE, decoy_seconds=90),
        backend_factory=lambda: Scripted([("run_cmd", {"command": command})]),
    )
    result = evidence.tool_log[0]
    assert result.command == ["run_cmd", command]
    assert result.exit_code == 0, result.model_dump_json()
    assert "BACKGROUND_GONE" not in result.stdout, result.stdout
    assert "State:" in result.stdout, result.stdout
    assert [error.code for error in evidence.errors] == ["EXEC_LINGERING_KILLED", "DECOY_FAILED"]
    assert evidence.components.decoy == State.ERROR
    assert evidence.components.sandbox == State.ERROR
    assert evidence.status == "error"
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)


def test_fork_bomb_stays_caged_and_fails_closed(
    repo, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone
):
    before = tree_digest(repo)
    evidence = run_scan(
        repo,
        ["sh", "-c", "bomb() { bomb | bomb; }; bomb"],
        config=SandboxConfig(timeout_seconds=10),
    )
    instance = recorded_sandbox.instances[-1]
    assert instance.container_id is not None
    # The pid bound is read from the container config; the kernel enforcing it
    # is not observed here. The fail-closed error and the cleanup are.
    assert instance._cage.attrs["HostConfig"]["PidsLimit"] == 64
    assert instance._cage.attrs["State"]["Status"] in {"exited", "dead"}
    assert evidence.status == "error"
    assert evidence.errors
    assert evidence.errors[0].code in {"COMMAND_FAILED", "COMMAND_TIMEOUT"}
    assert tree_digest(repo) == before
    assert_staging_gone(instance, evidence)
    assert_no_leftovers(evidence)


def test_output_flood_on_both_streams_is_truncated(
    repo, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone
):
    code = r"""
import sys, time
end = time.monotonic() + 10
while time.monotonic() < end:
    sys.stdout.write("A" * 250 + "\n")
    sys.stderr.write("B" * 250 + "\n")
    sys.stdout.flush()
    sys.stderr.flush()
    time.sleep(0.01)
"""
    before = tree_digest(repo)
    evidence = run_scan(
        repo,
        ["python", "-c", code],
        config=SandboxConfig(image=PYTHON_IMAGE, max_output_bytes=4096, timeout_seconds=20),
    )
    result = evidence.tool_log[0]
    assert result.output_truncated, result.model_dump_json()
    assert result.stdout and result.stderr, "both streams must be captured before the cap"
    assert len(result.stdout.encode()) + len(result.stderr.encode()) <= 4096
    assert [error.code for error in evidence.errors] == ["OUTPUT_TRUNCATED"]
    assert evidence.components.sandbox == State.ERROR
    assert evidence.status == "error"
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)


RENAME_PY = r"""
import ctypes, os, pathlib, time

comm = pathlib.Path("/repo/comm.txt").read_bytes()[:15]
dns_ip, _ = sink_ips()
query = dns_query("renamed.evil.example")
child = os.fork()
if child == 0:
    ctypes.CDLL(None).prctl(15, comm, 0, 0, 0)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        for _ in range(3):
            sock.sendto(query, (dns_ip, 53))
            try:
                sock.recvfrom(1024)
                break
            except OSError:
                pass
    pathlib.Path("/repo/renamed.ready").write_text(str(os.getpid()))
    time.sleep(100)
while not os.path.exists("/repo/renamed.ready"):
    time.sleep(0.01)
pid = pathlib.Path("/repo/renamed.ready").read_text().strip()
try:
    status = pathlib.Path(f"/proc/{pid}/status").read_text()
except FileNotFoundError:
    print("CHILD_GONE")
else:
    states = [line.split()[1] for line in status.splitlines() if line.startswith("State:")]
    print("CHILD_STATE", states[-1] if states else "malformed")
"""


@pytest.mark.parametrize("comm", [")", "a b", "x\ny"], ids=["paren", "space", "newline"])
def test_sweep_kills_renamed_process_and_keeps_its_contact(
    repo, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone, comm
):
    (repo / "comm.txt").write_text(comm)
    (repo / "rename.py").write_text(BOOTSTRAP + RENAME_PY)
    before = tree_digest(repo)

    def backend_factory():
        return Scripted([("run_cmd", {"command": "python rename.py"})])

    evidence = run_scan(
        repo,
        config=SandboxConfig(image=PYTHON_IMAGE, decoy_seconds=90),
        backend_factory=backend_factory,
    )
    # The parent's probe proves the hostile-comm process was alive when its
    # call ended, so the post-call sweep had to deal with it. A sweep blind to
    # the name would skip it and the decoy would end COMPLETE instead.
    result = evidence.tool_log[0]
    assert result.command == ["run_cmd", "python rename.py"]
    assert result.exit_code == 0, result.model_dump_json()
    assert "CHILD_GONE" not in result.stdout, result.stdout
    assert "CHILD_STATE" in result.stdout, result.stdout
    assert [error.code for error in evidence.errors] == ["EXEC_LINGERING_KILLED", "DECOY_FAILED"]
    assert evidence.components.decoy == State.ERROR
    assert evidence.components.sandbox == State.ERROR
    instance = recorded_sandbox.instances[-1]
    hit = next(item for item in evidence.dns_hits if item.destination == "renamed.evil.example")
    assert hit.source_ip == instance.cage_ip
    assert ("renamed.ready", "added") in {(item.path, item.change) for item in evidence.file_diffs}
    assert evidence.status == "error"
    assert tree_digest(repo) == before
    assert_staging_gone(instance, evidence)
    assert_no_leftovers(evidence)


def test_hanging_tool_call_times_out_inside_the_cage(
    repo, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone
):
    before = tree_digest(repo)
    evidence = run_scan(
        repo,
        config=SandboxConfig(image=PYTHON_IMAGE, decoy_seconds=60, tool_timeout_seconds=2),
        backend_factory=lambda: Scripted([("run_cmd", {"command": "sleep 100"})]),
    )
    result = evidence.tool_log[0]
    assert result.command == ["run_cmd", "sleep 100"]
    assert result.timed_out
    assert result.exit_code == 137
    assert [error.code for error in evidence.errors] == ["EXEC_TIMEOUT", "DECOY_FAILED"]
    assert evidence.components.decoy == State.ERROR
    assert evidence.components.sandbox == State.ERROR
    assert evidence.status == "error"
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)


CAGE_MARKER = "cage-death.marker"


def test_cage_dying_mid_run_fails_the_decoy(
    repo, recorded_sandbox, run_scan, tree_digest, assert_no_leftovers, assert_staging_gone
):
    command = f"touch /repo/{CAGE_MARKER} && sleep 30"

    def kill_once_marker() -> None:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            for instance in recorded_sandbox.instances:
                staged = instance._temporary
                if staged is not None and (staged / "repo" / CAGE_MARKER).exists():
                    with contextlib.suppress(Exception):
                        instance.kill_cage()
                    return
            time.sleep(0.02)

    killer = threading.Thread(target=kill_once_marker, daemon=True)
    killer.start()
    before = tree_digest(repo)
    evidence = run_scan(
        repo,
        config=SandboxConfig(image=PYTHON_IMAGE, decoy_seconds=90, tool_timeout_seconds=15),
        backend_factory=lambda: Scripted([("run_cmd", {"command": command})]),
    )
    killer.join(timeout=5)
    assert not killer.is_alive(), "the marker never reached the staged copy"
    assert evidence.components.decoy == State.ERROR
    assert evidence.status == "error"
    assert evidence.tool_log[0].command == ["run_cmd", command]
    # The kill lands mid-call, so the run must fail on the dead cage.
    assert [error.code for error in evidence.errors] == ["CAGE_EXITED", "DECOY_FAILED"]
    assert tree_digest(repo) == before
    assert_staging_gone(recorded_sandbox.instances[-1], evidence)
    assert_no_leftovers(evidence)
