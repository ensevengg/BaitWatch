import os
import subprocess
import sys
from pathlib import Path

import pytest

from run.trace import (
    Entry,
    TraceError,
    TraceLimits,
    diff,
    error_paths,
    manifest_from_json,
    manifest_to_json,
    snapshot,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TRACE_CLI = PROJECT_ROOT / "run" / "trace.py"
GOOD_DIGEST = "0" * 64


def test_unchanged_tree_produces_no_diffs(repo: Path):
    before = snapshot(repo)
    assert before["README.md"].kind == "file"
    assert len(before["README.md"].sha256) == 64
    assert diff(before, snapshot(repo)) == []


def test_empty_tree_snapshots_to_an_empty_manifest(tmp_path: Path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert snapshot(empty) == {}
    assert manifest_from_json(manifest_to_json({})) == {}


def test_added_modified_and_deleted_files(repo: Path):
    (repo / "new.txt").write_text("first")
    before = snapshot(repo)
    (repo / "new.txt").write_text("second")
    (repo / "gone.txt").write_text("delete me")
    (repo / "README.md").unlink()
    assert diff(before, snapshot(repo)) == [
        ("README.md", "deleted"),
        ("gone.txt", "added"),
        ("new.txt", "modified"),
    ]


def test_file_mode_change_is_a_diff(repo: Path):
    before = snapshot(repo)
    (repo / "README.md").chmod(0o755)
    assert diff(before, snapshot(repo)) == [("README.md", "modified")]


def test_directory_mode_change_is_a_diff_but_mtime_churn_is_not(repo: Path):
    scratch = repo / "scratch"
    scratch.mkdir()
    original = scratch.stat().st_mode & 0o7777
    before = snapshot(repo)
    scratch.chmod(0o700)
    assert diff(before, snapshot(repo)) == [("scratch", "modified")]
    scratch.chmod(original)
    (scratch / "churn.txt").write_text("x")
    (scratch / "churn.txt").unlink()
    assert diff(before, snapshot(repo)) == []


def test_file_replaced_by_symlink_is_modified(repo: Path, tmp_path: Path):
    outside = tmp_path / "outside.txt"
    outside.write_text("HOST-ONLY-FIXTURE")
    before = snapshot(repo)
    (repo / "README.md").unlink()
    (repo / "README.md").symlink_to(outside)
    after = snapshot(repo)
    assert diff(before, after) == [("README.md", "modified")]
    assert after["README.md"].kind == "symlink"
    assert after["README.md"].target == str(outside)
    assert after["README.md"].sha256 is None


def test_retargeted_symlink_is_modified(repo: Path, tmp_path: Path):
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("one")
    second.write_text("two")
    (repo / "link").symlink_to(first)
    before = snapshot(repo)
    (repo / "link").unlink()
    (repo / "link").symlink_to(second)
    assert diff(before, snapshot(repo)) == [("link", "modified")]


def test_symlink_pointing_outside_the_root_is_never_followed(repo: Path, tmp_path: Path):
    outside = tmp_path / "outside.txt"
    outside.write_text("before")
    (repo / "escape").symlink_to(outside)
    before = snapshot(repo)
    outside.write_text("after")
    assert before["escape"].kind == "symlink"
    assert diff(before, snapshot(repo)) == []


def test_fifo_is_recorded_without_blocking(repo: Path):
    os.mkfifo(repo / "pipe")
    entry = snapshot(repo)["pipe"]
    assert entry.kind == "other"
    assert entry.error is None
    assert entry.sha256 is None


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_unreadable_file_becoming_readable_is_modified(repo: Path):
    secret = repo / "secret.txt"
    secret.write_text("hidden")
    secret.chmod(0)
    before = snapshot(repo)
    assert before["secret.txt"].error == "EACCES"
    assert before["secret.txt"].sha256 is None
    assert manifest_from_json(manifest_to_json(before)) == before
    secret.chmod(0o644)
    assert diff(before, snapshot(repo)) == [("secret.txt", "modified")]


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_unreadable_directory_is_marked(repo: Path):
    locked = repo / "locked"
    locked.mkdir()
    (locked / "inner.txt").write_text("hidden")
    locked.chmod(0)
    before = snapshot(repo)
    assert before["locked"].error == "EACCES"
    locked.chmod(0o755)
    after = snapshot(repo)
    assert after["locked"].error is None
    # Children hidden behind the unreadable dir surface as additions.
    assert diff(before, after) == [("locked", "modified"), ("locked/inner.txt", "added")]


def test_non_utf8_names_round_trip(repo: Path):
    name = os.fsdecode(b"attack-\xff-name.txt")
    (repo / name).write_text("payload")
    manifest = snapshot(repo)
    assert manifest[name].kind == "file"
    assert manifest_from_json(manifest_to_json(manifest)) == manifest


@pytest.mark.parametrize(
    "limits",
    [
        TraceLimits(max_entries=1),
        TraceLimits(max_file_bytes=1),
        TraceLimits(max_bytes=1),
        TraceLimits(max_depth=1),
    ],
)
def test_limits_fail_closed(repo: Path, limits: TraceLimits):
    nested = repo / "nested"
    nested.mkdir()
    deep = nested / "deeper"
    deep.mkdir()
    (deep / "deep.txt").write_text("12")
    with pytest.raises(TraceError, match="limit"):
        snapshot(repo, limits)


def test_root_symlink_is_rejected(repo: Path, tmp_path: Path):
    link = tmp_path / "root-link"
    link.symlink_to(repo, target_is_directory=True)
    with pytest.raises(TraceError, match="root"):
        snapshot(link)


def test_cli_snapshot_matches_the_in_process_snapshot(repo: Path):
    name = os.fsdecode(b"weird-\xff.txt")
    (repo / name).write_text("payload")
    (repo / "sub").mkdir()
    (repo / "sub" / "nested.txt").write_text("nested")
    completed = subprocess.run(
        [sys.executable, str(TRACE_CLI), "snapshot", str(repo)],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert manifest_from_json(completed.stdout) == snapshot(repo)


@pytest.mark.parametrize(
    "limits",
    ['{"max_entries": 1}', '{"max_bytes": 1}', '{"max_file_bytes": 1}'],
)
def test_cli_enforces_supplied_snapshot_limits(repo: Path, limits: str):
    (repo / "extra").touch()
    completed = subprocess.run(
        [sys.executable, str(TRACE_CLI), "snapshot", str(repo), "--limits", limits],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 1
    assert "limit" in completed.stderr
    assert completed.stdout == ""


@pytest.mark.parametrize("limits", ["{", "[]", '{"max_bytes": 0}', '{"unknown": 1}'])
def test_cli_rejects_invalid_snapshot_limits(repo: Path, limits: str):
    completed = subprocess.run(
        [sys.executable, str(TRACE_CLI), "snapshot", str(repo), "--limits", limits],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 1
    assert "trace error" in completed.stderr
    assert completed.stdout == ""


def test_cli_reports_failures_on_stderr(tmp_path: Path):
    completed = subprocess.run(
        [sys.executable, str(TRACE_CLI), "snapshot", str(tmp_path / "absent")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 1
    assert "trace error" in completed.stderr
    assert completed.stdout == ""


def test_cli_rejects_unknown_commands():
    completed = subprocess.run(
        [sys.executable, str(TRACE_CLI), "tamper", "/"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 2
    assert "usage" in completed.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_cli_unlock_makes_locked_directories_deletable(repo: Path):
    locked = repo / "locked"
    (locked / "deep").mkdir(parents=True)
    (locked / "a.txt").write_text("x")
    (locked / "deep" / "b.txt").write_text("y")
    (locked / "deep").chmod(0)
    locked.chmod(0)
    completed = subprocess.run(
        [sys.executable, str(TRACE_CLI), "unlock", str(repo)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    # The root itself is never chmodded; only the directories inside it.
    for path in (locked, locked / "deep"):
        assert path.stat().st_mode & 0o777 == 0o777
    assert [item.name for item in (locked / "deep").iterdir()] == ["b.txt"]


def test_unlock_does_not_follow_symlinks(repo: Path, tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "inner").mkdir()
    outside.chmod(0o700)
    (repo / "linked").mkdir()
    (repo / "linked" / "inside.txt").write_text("x")
    (repo / "escape").symlink_to(outside)
    completed = subprocess.run(
        [sys.executable, str(TRACE_CLI), "unlock", str(repo)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert outside.stat().st_mode & 0o777 == 0o700
    assert (repo / "linked").stat().st_mode & 0o777 == 0o777


def test_cli_unlock_reports_a_bad_root(tmp_path: Path):
    completed = subprocess.run(
        [sys.executable, str(TRACE_CLI), "unlock", str(tmp_path / "absent")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 1
    assert "trace error" in completed.stderr
    assert completed.stdout == ""


def test_manifest_accepts_unreadable_markers():
    manifest = manifest_from_json(
        '{"locked": {"kind": "dir", "mode": 0, "size": 0, "error": "EACCES"}}'
    )
    assert manifest["locked"].error == "EACCES"


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        "[]",
        '{"README.md": {"kind": "file", "mode": 420, "size": 17}}',
        '{"/etc/passwd": {"kind": "dir", "mode": 493}}',
        '{"../escape": {"kind": "dir", "mode": 493}}',
        '{"a//b": {"kind": "dir", "mode": 493}}',
        '{"": {"kind": "dir", "mode": 493}}',
        '{"a": {"kind": "wormhole", "mode": 0}}',
        '{"a": {"kind": "dir", "mode": true}}',
        '{"a": {"kind": "dir", "mode": 4096}}',
        '{"a": {"kind": "dir", "mode": 493, "size": 5}}',
        '{"a": {"kind": "dir", "mode": 493, "extra": 1}}',
        '{"a": {"kind": "file", "mode": 0, "size": 3, "sha256": "abc"}}',
        '{"a": {"kind": "file", "mode": 0, "size": 3, "sha256": "'
        + GOOD_DIGEST
        + '", "error": "EACCES"}}',
        '{"a": {"kind": "symlink", "mode": 511, "size": 0}}',
        '{"a": {"kind": "symlink", "mode": 511, "target": "b", "sha256": "' + GOOD_DIGEST + '"}}',
    ],
)
def test_malformed_manifests_are_rejected(payload: str):
    with pytest.raises(TraceError):
        manifest_from_json(payload)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_entries": True},
        {"max_bytes": 1.5},
        {"max_file_bytes": 0},
        {"max_depth": -3},
        {"timeout_seconds": 0},
        {"timeout_seconds": -1.0},
        {"timeout_seconds": float("inf")},
        {"timeout_seconds": True},
    ],
)
def test_limit_validation_rejects_bad_values(kwargs: dict):
    with pytest.raises(ValueError):
        TraceLimits(**kwargs)


def test_manifest_from_json_rejects_deeply_nested_input():
    with pytest.raises(TraceError):
        manifest_from_json("[" * 100_000 + "]" * 100_000)


def test_error_paths_lists_sorted_paths_with_markers():
    manifest = {
        "clean.txt": Entry(kind="file", mode=0o644, sha256=GOOD_DIGEST),
        "b/locked": Entry(kind="dir", mode=0, error="EACCES"),
        "a/unreadable": Entry(kind="file", mode=0o600, error="EPERM"),
    }
    assert error_paths(manifest) == ["a/unreadable", "b/locked"]
    assert error_paths({}) == []
