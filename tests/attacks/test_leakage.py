"""Leakage: attack payloads must not appear in the training corpus."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from attacks.leakage import check_corpus, discover_corpus, frozen_payloads, main
from attacks.synth.generate import build_examples, build_repos


def _payload() -> str:
    return build_repos()["markdown-ghost"].entries[0].payload


def _jsonl(tmp_path: Path, rows: list[str], name: str = "train.jsonl") -> Path:
    path = tmp_path / name
    path.write_text("\n".join(json.dumps({"text": row}) for row in rows) + "\n", encoding="utf-8")
    return path


def test_frozen_payloads_cover_every_entry() -> None:
    expected = sum(len(repo.entries) for repo in build_repos().values())
    expected += sum(len(example.entries) for example in build_examples())
    payloads = frozen_payloads()
    assert len(payloads) == expected
    assert all(payload.text for payload in payloads)


def test_manifest_hashes_match_frozen_payloads() -> None:
    from attacks.leakage import _manifest_hashes

    manifest = _manifest_hashes()
    for payload in frozen_payloads():
        assert manifest[payload.name] == payload.sha256


def test_exact_leak_is_detected(tmp_path: Path) -> None:
    report = check_corpus(frozen_payloads(), [_jsonl(tmp_path, [_payload()])])
    assert not report.clean
    assert report.leaks[0].kind == "exact"


def test_embedded_leak_is_detected(tmp_path: Path) -> None:
    row = f"tool output: {_payload()} end of tool output"
    report = check_corpus(frozen_payloads(), [_jsonl(tmp_path, [row])])
    assert any(leak.kind == "embedded" for leak in report.leaks)


def test_fuzzy_leak_is_detected(tmp_path: Path) -> None:
    words = _payload().split()
    near = "changed prefix " + " ".join(words[2:])
    report = check_corpus(frozen_payloads(), [_jsonl(tmp_path, [near])])
    assert any(leak.kind == "fuzzy" for leak in report.leaks)


def test_clean_corpus_passes(tmp_path: Path) -> None:
    rows = ["def add(a, b):\n    return a + b", "Run the tests before committing."]
    report = check_corpus(frozen_payloads(), [_jsonl(tmp_path, rows)])
    assert report.clean
    assert report.rows == 2


def test_missing_corpus_is_skipped(tmp_path: Path) -> None:
    report = check_corpus(frozen_payloads(), [])
    assert report.skipped
    assert report.clean


def test_discover_corpus_finds_splits(tmp_path: Path) -> None:
    (tmp_path / "train.jsonl").write_text("{}\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("benign\n", encoding="utf-8")
    found = discover_corpus(tmp_path)
    assert tmp_path / "train.jsonl" in found


def test_cli_skips_without_data(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--data-dir", str(tmp_path / "missing")]) == 0
    assert "skipped" in capsys.readouterr().out


def test_cli_reports_a_leak(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _jsonl(tmp_path, [_payload()])
    assert main(["--data-dir", str(tmp_path)]) == 3
    assert "LEAK" in capsys.readouterr().err


def test_parquet_corpus_if_available(tmp_path: Path) -> None:
    pyarrow = pytest.importorskip("pyarrow")
    import pyarrow.parquet as pq

    table = pyarrow.table({"text": [_payload(), "benign row"]})
    path = tmp_path / "train.parquet"
    pq.write_table(table, path)
    report = check_corpus(frozen_payloads(), [path])
    assert report.rows == 2
    assert any(leak.kind == "exact" for leak in report.leaks)
