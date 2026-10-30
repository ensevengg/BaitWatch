"""Harness: staging, recall, zero-extra-file, recovery, CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from attacks import harness
from attacks.manifests import load_manifest
from attacks.synth.generate import build_repos
from attacks.synth.training import build_training_repos

REPO_ROOT = Path(__file__).resolve().parents[2]
REPOS = REPO_ROOT / "attacks" / "repos"
TWINS = {repo.name for repo in build_training_repos() if repo.threat.startswith("none:")}


def test_every_repo_passes_the_read_gate() -> None:
    reports = harness.run_all(scanner=harness.keyword_scanner, layer="READ")
    assert len(reports) == len(build_repos())
    for report in reports:
        assert report.ok, (report.repo, report.missed, report.extra)
        assert report.recovered == report.recoverable


def test_every_repo_passes_the_run_coverage_gate() -> None:
    reports = harness.run_all(scanner=harness.keyword_scanner, layer="RUN")
    for report in reports:
        if report.repo in TWINS:
            # Harmless lookalikes: the READ scanner must not bite, and every
            # payload is still recoverable from its file.
            assert report.flagged == set(), report.repo
            assert report.recovered == report.recoverable, report.repo
            continue
        assert report.ok, (report.repo, report.missed, report.extra)


def test_twin_run_gate_expects_no_flags() -> None:
    reports = harness.run_all(scanner=harness.keyword_scanner, layer="RUN")
    twins = [report for report in reports if report.repo in TWINS]
    assert len(twins) == 5
    for report in twins:
        assert report.expected == set(), report.repo
        assert report.ok, (report.repo, report.missed, report.extra)


def test_flagged_twin_is_a_false_positive() -> None:
    manifest = load_manifest(REPOS / "twin-release-train" / "MANIFEST.json")
    outcome = harness.ScanOutcome(flagged={"README.md": 1.0})
    report = harness.evaluate(outcome, manifest, "READ", "test")
    assert report.extra == {"README.md"}
    assert not report.ok


def test_staging_removes_the_answer_key(tmp_path: Path) -> None:
    source = REPOS / "readme-bait-curl"
    staged = harness.stage_repo(source, tmp_path / "staged")
    assert not (staged / "MANIFEST.json").exists()
    assert (staged / "README.md").exists()
    assert (source / "MANIFEST.json").exists()
    assert not (staged / ".git").exists()


def test_extra_file_fails_the_gate() -> None:
    manifest = load_manifest(REPOS / "readme-bait-curl" / "MANIFEST.json")
    outcome = harness.ScanOutcome(flagged={"README.md": 1.0, "notes.txt": 0.9})
    report = harness.evaluate(outcome, manifest, "READ", "test")
    assert report.extra == {"notes.txt"}
    assert not report.ok


def test_missed_file_fails_the_gate() -> None:
    manifest = load_manifest(REPOS / "markdown-ghost" / "MANIFEST.json")
    report = harness.evaluate(harness.ScanOutcome(), manifest, "READ", "test")
    assert report.missed == harness.expected_files(manifest, "READ")
    assert not report.ok


def test_incomplete_evidence_never_passes() -> None:
    manifest = load_manifest(REPOS / "readme-bait-curl" / "MANIFEST.json")
    expected = harness.expected_files(manifest, "READ")
    outcome = harness.ScanOutcome(flagged={name: 1.0 for name in expected}, incomplete=True)
    report = harness.evaluate(outcome, manifest, "READ", "test")
    assert report.incomplete
    assert not report.ok


def test_keyword_scanner_ignores_benign_repo(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "# demo\n\nCopy `.env.example` to `.env` and run `python -m pytest`.\n", encoding="utf-8"
    )
    (tmp_path / ".env.example").write_text("TOKEN=replace-me\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": "node doctor.js"}}), encoding="utf-8"
    )
    outcome = harness.keyword_scanner(tmp_path)
    assert outcome.flagged == {}
    assert not outcome.incomplete


def test_keyword_scanner_skips_manifest(tmp_path: Path) -> None:
    (tmp_path / "MANIFEST.json").write_text(
        '{"target": "evil.example", "title": "exfiltration"}\n', encoding="utf-8"
    )
    assert harness.keyword_scanner(tmp_path).flagged == {}


def test_read_scanner_reports_a_missing_dependency(monkeypatch, tmp_path: Path) -> None:
    """The lazy import is the CI guard, so exercise it with or without torch."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name in ("read.config", "read.scan"):
            raise ModuleNotFoundError("No module named 'torch'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError, match="missing a dependency.*install torch"):
        harness.read_scanner(tmp_path)


def test_cli_json_report(capsys: pytest.CaptureFixture[str]) -> None:
    code = harness.main(["--json", "--repo", "readme-bait-curl"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["reports"][0]["repo"] == "readme-bait-curl"
    assert payload["reports"][0]["missed"] == []


def test_recovery_counts_every_generated_payload() -> None:
    for name, repo in build_repos().items():
        recovered, total = harness.recover_generated(name)
        assert total == len(repo.entries)
        assert recovered == total


def test_gate_report_fails_when_recovery_is_incomplete() -> None:
    report = harness.GateReport(
        repo="demo",
        layer="READ",
        expected={"README.md"},
        flagged={"README.md"},
        missed=set(),
        extra=set(),
        incomplete=False,
        recovered=1,
        recoverable=2,
        scanner="keyword",
    )
    assert not report.ok
    report.recovered = 2
    assert report.ok


def test_cli_exits_nonzero_when_recovery_is_incomplete(monkeypatch) -> None:
    monkeypatch.setattr(harness, "recover_generated", lambda _name: (0, 3))
    assert harness.main(["--repo", "readme-bait-curl"]) == 1
