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
