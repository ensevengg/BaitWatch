import os
from pathlib import Path

import pytest

from run import staging
from run.staging import StagingError, StagingLimits, stage_repository


def test_copy_preserves_symlinks_without_reading_their_targets(repo: Path, tmp_path: Path):
    outside = tmp_path / "outside"
    outside.write_text("HOST-ONLY-FIXTURE")
    (repo / "link").symlink_to(outside)
    (repo / "broken").symlink_to("absent")
    (repo / "empty").mkdir()
    script = repo / "script.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o4755)
    target = tmp_path / "staged"
    stage_repository(repo, target, StagingLimits())
    assert (target / "link").is_symlink()
    assert os.readlink(target / "link") == str(outside)
    assert (target / "broken").is_symlink()
    assert (target / "empty").is_dir()
    # Writable for the cage's uid, but the setuid bit is still stripped.
    assert (target / "script.sh").stat().st_mode & 0o7777 == 0o777
    assert (target / "README.md").stat().st_mode & 0o7777 == 0o666
    assert not any(
        "HOST-ONLY-FIXTURE" in p.read_text()
        for p in target.iterdir()
        if p.is_file() and not p.is_symlink()
    )
    assert script.stat().st_mode & 0o7777 == 0o4755


def test_fifo_is_rejected_without_blocking(repo: Path, tmp_path: Path):
    os.mkfifo(repo / "pipe")
    with pytest.raises(StagingError, match="FIFO"):
        stage_repository(repo, tmp_path / "staged", StagingLimits())


@pytest.mark.parametrize("limits", [StagingLimits(max_file_bytes=1), StagingLimits(max_bytes=1)])
def test_size_limits_fail_instead_of_silently_truncating(repo: Path, tmp_path: Path, limits):
    with pytest.raises(StagingError, match="byte limit"):
        stage_repository(repo, tmp_path / "staged", limits)


def test_entry_limit(repo: Path, tmp_path: Path):
    (repo / "second").write_text("two")
    with pytest.raises(StagingError, match="entry limit"):
        stage_repository(repo, tmp_path / "staged", StagingLimits(max_entries=1))


def test_depth_limit(repo: Path, tmp_path: Path):
    (repo / "nested").mkdir()
    with pytest.raises(StagingError, match="nesting limit"):
        stage_repository(repo, tmp_path / "staged", StagingLimits(max_depth=0))


def test_cannot_copy_into_the_source(repo: Path):
    with pytest.raises(StagingError, match="outside"):
        stage_repository(repo, repo / "recursive", StagingLimits())


def test_source_root_symlink_is_not_followed(repo: Path, tmp_path: Path):
    link = tmp_path / "source-link"
    link.symlink_to(repo, target_is_directory=True)
    with pytest.raises(OSError):
        stage_repository(link, tmp_path / "staged", StagingLimits())


def test_file_swap_to_symlink_cannot_copy_a_host_file(repo: Path, tmp_path: Path, monkeypatch):
    outside = tmp_path / "outside"
    outside.write_text("HOST-ONLY-FIXTURE")
    original_open = os.open

    def race(path, flags, *args, **kwargs):
        if path == "README.md" and kwargs.get("dir_fd") is not None:
            (repo / "README.md").unlink()
            (repo / "README.md").symlink_to(outside)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(staging.os, "open", race)
    with pytest.raises(OSError):
        stage_repository(repo, tmp_path / "staged", StagingLimits())
    assert not (tmp_path / "staged/README.md").exists()


def test_hard_link_to_host_file_is_rejected(repo: Path, tmp_path: Path):
    outside = tmp_path / "host-data"
    outside.write_text("HOST-ONLY-FIXTURE")
    os.link(outside, repo / "hardlink")
    with pytest.raises(StagingError, match="hard-linked"):
        stage_repository(repo, tmp_path / "staged", StagingLimits())
    assert outside.read_text() == "HOST-ONLY-FIXTURE"


def test_runtime_copy_excludes_host_state_but_keeps_agent_hooks(repo: Path, tmp_path: Path):
    (repo / ".env").write_text("HOST-ENV-FIXTURE")
    (repo / ".env.local").write_text("HOST-ENV-FIXTURE")
    (repo / ".env.example").write_text("PLACEHOLDER")
    for name in (".venv", ".git", ".aws"):
        (repo / name).mkdir()
        (repo / name / "private-fixture").write_text("HOST-ONLY-FIXTURE")
    for name in (".muse", ".claude"):
        (repo / name).mkdir()
        (repo / name / "hooks.json").write_text("{}")
    target = tmp_path / "staged"
    excluded = stage_repository(repo, target, StagingLimits())
    assert set(excluded) == {".env", ".env.local", ".venv", ".git", ".aws"}
    assert (target / ".env.example").read_text() == "PLACEHOLDER"
    assert (target / ".muse/hooks.json").exists()
    assert (target / ".claude/hooks.json").exists()
    assert not (target / ".env").exists()
    assert not (target / ".venv").exists()
    assert (repo / ".env").read_text() == "HOST-ENV-FIXTURE"


def test_top_level_git_symlink_is_refused(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    git = source / ".git"
    git.symlink_to("missing")
    with pytest.raises(StagingError, match=".git"):
        stage_repository(source, tmp_path / "staged", StagingLimits())


@pytest.mark.parametrize(
    "name", [".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults"]
)
def test_committed_env_templates_are_scanned_and_can_allow(repo, tmp_path, name):
    from run.verdict import fuse
    from tests.run.test_verdict import CLEAN, complete_run

    (repo / name).write_text("PLACEHOLDER")
    target = tmp_path / "staged"
    run = complete_run()
    run.staging_exclusions = stage_repository(repo, target, StagingLimits())
    assert (target / name).read_text() == "PLACEHOLDER"
    assert fuse(CLEAN, run).verdict == "ALLOW"


@pytest.mark.parametrize(
    "name", [".env", ".env.development", ".env.test", ".env.local", ".env.other"]
)
def test_potential_secret_env_files_remain_excluded_and_flag(repo, tmp_path, name):
    from run.verdict import fuse
    from tests.run.test_verdict import CLEAN, complete_run

    (repo / name).write_text("SECRET-FIXTURE")
    target = tmp_path / "staged"
    run = complete_run()
    run.staging_exclusions = stage_repository(repo, target, StagingLimits())
    assert not (target / name).exists()
    assert fuse(CLEAN, run).verdict == "FLAG"


def test_regular_top_level_git_pointer_is_excluded_and_can_allow(repo, tmp_path):
    from run.verdict import fuse
    from tests.run.test_verdict import CLEAN, complete_run

    (repo / ".git").write_text("gitdir: ../metadata/worktrees/fixture\n")
    target = tmp_path / "staged"
    run = complete_run()
    run.staging_exclusions = stage_repository(repo, target, StagingLimits())
    assert run.staging_exclusions == [".git"]
    assert not (target / ".git").exists()
    assert fuse(CLEAN, run).verdict == "ALLOW"


@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_nested_git_metadata_remains_excluded_and_flags(repo, tmp_path, kind):
    from run.verdict import fuse
    from tests.run.test_verdict import CLEAN, complete_run

    (repo / "nested").mkdir()
    metadata = repo / "nested/.git"
    if kind == "file":
        metadata.write_text("gitdir: ../metadata\n")
    elif kind == "directory":
        metadata.mkdir()
    else:
        metadata.symlink_to("missing")
    run = complete_run()
    run.staging_exclusions = stage_repository(repo, tmp_path / "staged", StagingLimits())
    assert run.staging_exclusions == ["nested/.git"]
    assert fuse(CLEAN, run).verdict == "FLAG"
