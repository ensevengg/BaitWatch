from typer.testing import CliRunner

from run.cli import app
from run.evidence import RunError, RunEvidence

runner = CliRunner()


def test_diagnostic_success_is_not_an_allow_exit(monkeypatch, tmp_path):
    monkeypatch.setattr("run.cli.detonate", lambda *args, **kwargs: RunEvidence())
    result = runner.invoke(app, ["sandbox", str(tmp_path), "--", "true"])
    assert result.exit_code == 2
    assert '"status": "incomplete"' in result.stdout


def test_diagnostic_error_is_nonzero(monkeypatch, tmp_path):
    evidence = RunEvidence(
        status="error", errors=[RunError(code="TEST_ERROR", message="synthetic failure")]
    )
    monkeypatch.setattr("run.cli.detonate", lambda *args, **kwargs: evidence)
    result = runner.invoke(app, ["sandbox", str(tmp_path), "--", "true"])
    assert result.exit_code == 3
    assert "TEST_ERROR" in result.stdout


def test_invalid_diagnostic_configuration_exits_three(monkeypatch, tmp_path):
    monkeypatch.setattr("run.cli.detonate", lambda *a, **k: RunEvidence())
    for path, extra in (
        (tmp_path, ["--image", ""]),
        (tmp_path / "absent", []),
        (tmp_path, ["--timeout", "nan"]),
    ):
        result = runner.invoke(app, ["sandbox", str(path), *extra, "--", "true"])
        assert result.exit_code == 3, result.output


def test_decoy_hits_never_exit_zero(monkeypatch, tmp_path):
    from run.evidence import NetworkHit, RunComponents, State

    evidence = RunEvidence(
        status="complete",
        components=RunComponents(**{k: State.COMPLETE for k in RunComponents.model_fields}),
        dns_hits=[NetworkHit(source_ip="192.0.2.20", destination="evil.example")],
    )
    monkeypatch.setattr("run.cli.detonate", lambda *a, **k: evidence)
    monkeypatch.setattr("run.llm.make_backend", lambda spec: object())
    result = runner.invoke(app, ["decoy", str(tmp_path), "--llm", "scripted:unused"])
    assert result.exit_code == 2
