import json

import jsonschema
from typer.testing import CliRunner

from run.evidence import (
    CommandResult,
    HoneytokenHit,
    NetworkHit,
    RunComponents,
    RunError,
    RunEvidence,
    State,
)
from run.scan_cli import app
from run.schemas import verdict_schema
from run.verdict import ReadOutcome

runner = CliRunner()
CLEAN = ReadOutcome(status=State.COMPLETE, verdict="clean")


def complete_run() -> RunEvidence:
    return RunEvidence(
        status="complete",
        tool_log=[CommandResult(command=["run_cmd", "true"], exit_code=0)],
        components=RunComponents(**{key: State.COMPLETE for key in RunComponents.model_fields}),
    )


def script(tmp_path) -> str:
    path = tmp_path / "steps.json"
    path.write_text("[[]]")
    return f"scripted:{path}"


def patched(monkeypatch, run: RunEvidence, read: ReadOutcome = CLEAN):
    monkeypatch.setattr("run.scan.detonate", lambda *a, **k: run)
    monkeypatch.setattr("run.scan.default_read_scanner", lambda path: read)


def test_allow_exits_zero_with_json_on_stdout_and_report_on_stderr(monkeypatch, tmp_path):
    patched(monkeypatch, complete_run())
    result = runner.invoke(app, ["scan", str(tmp_path), "--llm", script(tmp_path)])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["verdict"] == "ALLOW"
    jsonschema.validate(data, verdict_schema())
    assert "ALLOW" in result.stderr


def test_flag_exits_four(monkeypatch, tmp_path):
    patched(monkeypatch, RunEvidence(errors=[RunError(code="EXEC_TIMEOUT", message="late")]))
    result = runner.invoke(app, ["scan", str(tmp_path), "--llm", script(tmp_path)])
    assert result.exit_code == 4, result.output
    assert json.loads(result.stdout)["verdict"] == "FLAG"
    assert "EXEC_TIMEOUT" in result.stderr


def test_block_exits_five(monkeypatch, tmp_path):
    run = complete_run()
    run.dns_hits.append(NetworkHit(source_ip="10.13.37.20", destination="exfil.evil.example"))
    patched(monkeypatch, run)
    result = runner.invoke(app, ["scan", str(tmp_path), "--llm", script(tmp_path)])
    assert result.exit_code == 5, result.output
    data = json.loads(result.stdout)
    assert data["verdict"] == "BLOCK"
    jsonschema.validate(data, verdict_schema())


def test_json_option_writes_the_file_and_reports_on_stdout(monkeypatch, tmp_path):
    run = complete_run()
    run.honeytoken_hits.append(HoneytokenHit(token_id="fixture", source="dns"))
    patched(monkeypatch, run)
    target = tmp_path / "verdict.json"
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--llm", script(tmp_path), "--json", str(target)]
    )
    assert result.exit_code == 5, result.output
    data = json.loads(target.read_text())
    assert data["verdict"] == "BLOCK"
    jsonschema.validate(data, verdict_schema())
    assert '"verdict"' not in result.stdout
    assert "BLOCK" in result.stdout


def test_an_unusable_llm_spec_errors_without_scanning(monkeypatch, tmp_path):
    scanned = []
    monkeypatch.setattr("run.scan.detonate", lambda *a, **k: scanned.append(1))
    result = runner.invoke(app, ["scan", str(tmp_path), "--llm", "nope:nothing"])
    assert result.exit_code == 3, result.output
    assert "scan:" in result.stderr
    assert not scanned


def test_a_usage_error_exits_two_without_a_verdict(monkeypatch, tmp_path):
    patched(monkeypatch, complete_run())
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 2, result.output
    assert '"verdict"' not in result.stdout
    assert "--llm" in result.output


def test_repo_control_characters_are_escaped_in_the_human_report(monkeypatch, tmp_path):
    run = complete_run()
    run.dns_hits.append(NetworkHit(source_ip="10.13.37.20", destination="x\x9b5m.evil.example"))
    patched(monkeypatch, run)
    result = runner.invoke(app, ["scan", str(tmp_path), "--llm", script(tmp_path)])
    assert result.exit_code == 5, result.output
    assert "\x9b" not in result.stderr
    assert "<U+009B>" in result.stderr
