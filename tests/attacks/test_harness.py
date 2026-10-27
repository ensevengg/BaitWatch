"""Harness: staging, recall, zero-extra-file, recovery, CLI."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from attacks import harness
from attacks.manifests import load_manifest
from attacks.synth.generate import build_repos

REPO_ROOT = Path(__file__).resolve().parents[2]
REPOS = REPO_ROOT / "attacks" / "repos"


def test_every_repo_passes_the_read_gate() -> None:
    reports = harness.run_all(scanner=harness.keyword_scanner, layer="READ")
    assert len(reports) == 5
    for report in reports:
        assert report.ok, (report.repo, report.missed, report.extra)
        assert report.recovered == report.recoverable


def test_every_repo_passes_the_run_coverage_gate() -> None:
    reports = harness.run_all(scanner=harness.keyword_scanner, layer="RUN")
    for report in reports:
        assert report.ok, (report.repo, report.missed, report.extra)


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


def test_read_scanner_is_lazy_without_torch() -> None:
    if importlib.util.find_spec("torch") is not None:
        pytest.skip("torch is installed; the real scanner is available")
    with pytest.raises(RuntimeError, match="needs torch"):
        harness.read_scanner(REPOS / "readme-bait-curl")


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
