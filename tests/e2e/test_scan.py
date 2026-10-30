"""Day 4 gate: `baitwatch scan` end to end on the local attack and benign fixtures.

The scripted decoy follows each fixture's own setup instructions inside the
cage; the fixtures discover the sink addresses from the cage's fixed host
offsets, so the scripts need no dynamic IPs. The READ model checkpoint is
injected through the run_scan seam, which is the one part that may not exist
on every machine.
"""

import json
from pathlib import Path

import docker
import jsonschema
import pytest
from typer.testing import CliRunner

from run.evidence import State
from run.llm import ScriptedBackend
from run.sandbox import SCAN_LABEL, SandboxConfig
from run.scan import run_scan
from run.scan_cli import app
from run.schemas import verdict_schema
from run.verdict import ReadOutcome

pytestmark = pytest.mark.docker

E2E = Path(__file__).parent
FIXTURES = E2E / "fixtures"
SCRIPTS = E2E / "scripts"
CLEAN_READ = ReadOutcome(status=State.COMPLETE, verdict="clean")


@pytest.fixture
def engine():
    client = docker.from_env(timeout=5)
    try:
        client.ping()
        client.images.get("alpine:3.20")
        yield client
    finally:
        client.close()


def assert_no_leftovers(engine, report) -> None:
    label = f"{SCAN_LABEL}={report.run.scan_id}"
    assert not engine.containers.list(all=True, filters={"label": label})
    assert not engine.networks.list(filters={"label": label})


def scan_fixture(name: str, read: ReadOutcome = CLEAN_READ):
    return run_scan(
        FIXTURES / name,
        read_scanner=lambda path: read,
        backend=ScriptedBackend.from_json(SCRIPTS / f"{name}.json"),
        config=SandboxConfig(decoy_seconds=90),
    )


def test_http_exfil_fixture_blocks(engine):
    report = scan_fixture("http-exfil")
    run = report.run
    assert report.verdict == "BLOCK"
    assert report.reason
    assert any(hit.destination == "exfil.evil.example" for hit in run.dns_hits)
    http = next(hit for hit in run.http_hits if "stolen=example-value" in hit.detail)
    assert http.destination.endswith("/collect")
    assert not run.errors, [error.model_dump_json() for error in run.errors]
    assert run.status == "complete"
    assert run.components.complete()
    assert [entry.command[0] for entry in run.tool_log] == [
        "list_files",
        "read_file",
        "read_file",
        "run_cmd",
    ]
    # The decoy read the env template; the original repository is untouched.
    assert "FAKE_TOKEN" in run.tool_log[2].stdout
    assert not (FIXTURES / "http-exfil" / "build.txt").exists()
    jsonschema.validate(report.model_dump(mode="json"), verdict_schema())
    assert_no_leftovers(engine, report)


def test_dns_exfil_fixture_blocks(engine):
    report = scan_fixture("dns-exfil")
    run = report.run
    assert report.verdict == "BLOCK"
    assert any(hit.destination == "secret.evil.example" for hit in run.dns_hits)
    assert not run.http_hits
    assert not run.errors, [error.model_dump_json() for error in run.errors]
    assert run.status == "complete"
    assert run.components.complete()
    jsonschema.validate(report.model_dump(mode="json"), verdict_schema())
    assert_no_leftovers(engine, report)


def test_benign_fixture_allows(engine):
    report = scan_fixture("benign")
    run = report.run
    assert report.verdict == "ALLOW", (report.reason, [e.model_dump() for e in run.errors])
    assert report.read.status == State.COMPLETE
    assert not run.errors, [error.model_dump_json() for error in run.errors]
    assert run.status == "complete"
    assert run.components.complete()
    assert ("build.txt", "added") in {(diff.path, diff.change) for diff in run.file_diffs}
    assert {
        ("build/output.txt", "added"),
        ("node_modules/example/index.js", "added"),
        (".venv/pyvenv.cfg", "added"),
        ("src/ready.py", "added"),
        ("package-lock.json", "modified"),
    } <= {(diff.path, diff.change) for diff in run.file_diffs}
    jsonschema.validate(report.model_dump(mode="json"), verdict_schema())
    assert_no_leftovers(engine, report)


def test_cli_scan_end_to_end(monkeypatch, engine, tmp_path):
    # The real CLI path; only the READ model is injected (checkpoint may not exist).
    monkeypatch.setattr("run.scan.default_read_scanner", lambda path, **kwargs: CLEAN_READ)
    target = tmp_path / "verdict.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(FIXTURES / "benign"),
            "--llm",
            f"scripted:{SCRIPTS / 'benign.json'}",
            "--json",
            str(target),
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads(target.read_text())
    assert data["verdict"] == "ALLOW"
    jsonschema.validate(data, verdict_schema())
    label = f"{SCAN_LABEL}={data['run']['scan_id']}"
    assert not engine.containers.list(all=True, filters={"label": label})
    assert not engine.networks.list(filters={"label": label})


def test_agent_config_fixture_blocks_without_network_contact(engine):
    report = scan_fixture("agent-config")
    assert report.verdict == "BLOCK", report.reason
    assert "agent-control" in report.reason
    assert report.run.status == "complete", report.run.errors
    assert not report.run.dns_hits
    assert not report.run.http_hits
    assert not report.run.tls_hits
    assert not report.run.honeytoken_hits
    assert any(change.path == ".claude/settings.json" for change in report.run.file_diffs)
    assert not (FIXTURES / "agent-config" / ".claude").exists()
    jsonschema.validate(report.model_dump(mode="json"), verdict_schema())
    assert_no_leftovers(engine, report)
