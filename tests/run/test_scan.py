from pathlib import Path

import pytest

from run.evidence import CommandResult, RunComponents, RunEvidence, State
from run.scan import _outcome_from, default_read_scanner, run_scan
from run.verdict import READ_BLOCK_SCORE, ReadOutcome, fuse


def complete_run() -> RunEvidence:
    return RunEvidence(
        status="complete",
        tool_log=[CommandResult(command=["run_cmd", "true"], exit_code=0)],
        components=RunComponents(**{key: State.COMPLETE for key in RunComponents.model_fields}),
    )


def clean_read() -> ReadOutcome:
    return ReadOutcome(status=State.COMPLETE, verdict="clean")


def fake_result(verdict: str, max_score: float, reasons: list[str] | None = None):
    result = real_scan_result(reasons=reasons or [])
    if verdict == "attack":
        result.findings = [flagged(max_score)]
    return result


def test_run_scan_fuses_the_read_outcome_with_the_run_evidence(monkeypatch, tmp_path):
    seen = {}

    def fake_detonate(path, *, config, backend, max_steps):
        seen.update(path=path, config=config, backend=backend, max_steps=max_steps)
        return complete_run()

    monkeypatch.setattr("run.scan.detonate", fake_detonate)
    config, backend = object(), object()
    report = run_scan(
        tmp_path,
        config=config,
        backend=backend,
        max_steps=7,
        read_scanner=lambda path: clean_read(),
    )
    assert seen == {"path": tmp_path, "config": config, "backend": backend, "max_steps": 7}
    assert report.verdict == "ALLOW"
    assert report.run.status == "complete"
    assert report.read.status == State.COMPLETE


def test_a_raising_read_scanner_is_fail_closed(monkeypatch, tmp_path):
    monkeypatch.setattr("run.scan.detonate", lambda *a, **k: complete_run())

    def broken(path):
        raise RuntimeError("scanner exploded")

    report = run_scan(tmp_path, backend=object(), read_scanner=broken)
    assert report.verdict == "FLAG"
    assert "scanner exploded" in report.reason


def test_a_raising_detonate_is_fail_closed(monkeypatch, tmp_path):
    def broken(path, **kwargs):
        raise RuntimeError("docker gone")

    monkeypatch.setattr("run.scan.detonate", broken)
    report = run_scan(tmp_path, backend=object(), read_scanner=lambda path: clean_read())
    assert report.verdict == "FLAG"
    assert "SCAN_ABORTED" in report.reason
    assert [error.code for error in report.run.errors] == ["SCAN_ABORTED"]
    assert report.run.errors[0].message == "docker gone"


def test_default_read_scanner_fails_closed_on_a_missing_target(tmp_path):
    outcome = default_read_scanner(tmp_path / "absent")
    assert outcome.status == State.ERROR
    assert "absent" in outcome.reason


def test_an_unrunnable_read_flags_the_whole_scan(monkeypatch, tmp_path):
    monkeypatch.setattr("run.scan.detonate", lambda *a, **k: complete_run())
    report = run_scan(tmp_path / "absent", backend=object())
    assert report.verdict == "FLAG"
    assert "READ could not run" in report.reason


def test_outcome_mapping_keeps_a_clean_scan_clean():
    outcome = _outcome_from(fake_result("clean", 0.0))
    assert outcome.status == State.COMPLETE
    assert outcome.verdict == "clean"
    assert outcome.max_score == 0.0
    assert outcome.reason == ""


def test_outcome_mapping_keeps_incomplete_reasons():
    outcome = _outcome_from(fake_result("incomplete", 0.4, ["file cap: 2 file(s) not scanned"]))
    assert outcome.verdict == "incomplete"
    assert "file cap" in outcome.reason


def test_outcome_mapping_keeps_attack_scores():
    outcome = _outcome_from(fake_result("attack", 0.99))
    assert outcome.verdict == "attack"
    assert outcome.max_score >= READ_BLOCK_SCORE


def real_scan_result(findings=(), reasons=()):
    from read.scan import ScanResult, ScanStats

    stats = ScanStats(model_path="fixture")
    stats.incomplete_reasons = list(reasons)
    return ScanResult(findings=list(findings), stats=stats)


def flagged(score: float):
    from read.findings import Finding

    return Finding(file="AGENTS.md", chunk_id=1, score=score, layer="model", evidence={})


def test_a_real_incomplete_scan_result_flags_and_never_allows():
    # read.scan derives read_verdict itself; coverage gaps must surface as
    # FLAG, not slip through as clean.
    result = real_scan_result(reasons=["file cap: 2 file(s) not scanned"])
    assert result.read_verdict == "incomplete"
    report = fuse(_outcome_from(result), complete_run())
    assert report.verdict == "FLAG"
    assert "file cap" in report.reason


def test_a_real_attack_scan_result_blocks_even_with_coverage_gaps():
    result = real_scan_result(
        findings=[flagged(0.97)],
        reasons=["judge budget: 1 review-band chunk(s) not judged"],
    )
    assert result.read_verdict == "attack"
    outcome = _outcome_from(result)
    assert outcome.max_score == 0.97
    assert "judge budget" in outcome.reason
    assert fuse(outcome, complete_run()).verdict == "BLOCK"


def test_run_scan_uses_the_default_read_scanner(monkeypatch, tmp_path: Path):
    monkeypatch.setattr("run.scan.detonate", lambda *a, **k: RunEvidence())
    monkeypatch.setattr(
        "run.scan.default_read_scanner",
        lambda path: ReadOutcome(status=State.ERROR, reason="injected"),
    )
    report = run_scan(tmp_path, backend=object())
    assert report.verdict == "FLAG"
    assert "injected" in report.reason


@pytest.mark.parametrize(
    "field",
    [
        "partial_files",
        "files_truncated",
        "truncated_scan",
        "files_over_cap",
        "chunks_dropped",
        "views_dropped",
        "views_skipped_chunk_budget",
        "decoded_views_uncovered",
    ],
)
def test_real_partial_read_stats_never_allow(field):
    result = real_scan_result()
    setattr(result.stats, field, 1)
    assert result.read_verdict == "clean"
    outcome = _outcome_from(result)
    assert outcome.verdict == "incomplete"
    assert "coverage" in outcome.reason
    assert fuse(outcome, complete_run()).verdict == "FLAG"


def test_default_read_scanner_requests_strict_coverage(monkeypatch, tmp_path):
    from read.config import ReadConfig

    seen = []
    monkeypatch.setattr("read.config.config_from_model_config", lambda: ReadConfig())

    def scanner(path, config):
        seen.append(config)
        return real_scan_result()

    import importlib

    monkeypatch.setattr(importlib.import_module("read.scan"), "scan", scanner)
    outcome = default_read_scanner(tmp_path)
    assert outcome.verdict == "clean"
    assert len(seen) == 1
    assert seen[0].strict_coverage is True
