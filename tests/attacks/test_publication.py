"""Publication check: the public tree carries no personal workstation paths.

The sample paths below are assembled at runtime.  Writing them literally would
make this test file itself a publication violation - which is the point of the
check, so it is not exempted.
"""

from __future__ import annotations

from pathlib import Path

from attacks.publication import publication_violations, text_files

REPO_ROOT = Path(__file__).resolve().parents[2]


def _win(*parts: str) -> str:
    return "C:" + "\\" + "\\".join(parts)


def _posix(*parts: str) -> str:
    return "/" + "/".join(parts)


def _check(tmp_path: Path, name: str, body: str):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return publication_violations(tmp_path)


def test_committed_tree_is_clean() -> None:
    assert publication_violations(REPO_ROOT) == []


def test_windows_home_is_flagged(tmp_path: Path) -> None:
    violations = _check(tmp_path, "docs/a.md", f"copied from {_win('Users', 'someone')}\n")
    assert [v.kind for v in violations] == ["windows-user-home"]


def test_posix_home_is_flagged(tmp_path: Path) -> None:
    violations = _check(tmp_path, "notes.txt", f"ran {_posix('home', 'someone', 'train.py')}\n")
    assert [v.kind for v in violations] == ["posix-home"]


def test_wsl_mount_is_flagged(tmp_path: Path) -> None:
    violations = _check(tmp_path, "README.md", f"data lives at {_posix('mnt', 'd', 'sets')}\n")
    assert [v.kind for v in violations] == ["wsl-drive-mount"]


def test_generic_shared_data_mounts_are_allowed(tmp_path: Path) -> None:
    body = (
        f"models: {_posix('mnt', 'd', 'hf_models')}\n"
        f"data: {_posix('mnt', 'd', 'hf_datasets')}\n"
    )
    assert _check(tmp_path, "config.py", body) == []
    other = _check(tmp_path, "other.py", f"mine: {_posix('mnt', 'c', 'Users', 'x', 'train.py')}\n")
    assert {v.kind for v in other} == {"posix-home", "wsl-drive-mount"}


def test_local_checkout_is_flagged(tmp_path: Path) -> None:
    violations = _check(tmp_path, "a.py", f'ROOT = r"{_win("Hackathon")}"\n')
    assert [v.kind for v in violations] == ["local-checkout"]


def test_placeholders_are_allowed(tmp_path: Path) -> None:
    body = (
        "checkpoint: <model-dir>/v15f_22m\n"
        "data: <data-dir>/train.parquet\n"
        "clone: git clone <checkout>\n"
    )
    assert _check(tmp_path, "docs/SETUP.md", body) == []


def test_skips_vendored_and_generated_directories(tmp_path: Path) -> None:
    body = _win("Users", "someone", "x") + "\n"
    for name in (".git/config", ".venv/lib/a.py", "node_modules/pkg/a.js", "build/a.md"):
        _check(tmp_path, name, body)
    assert publication_violations(tmp_path) == []


def test_only_text_suffixes_are_read(tmp_path: Path) -> None:
    (tmp_path / "blob.parquet").write_bytes((_win("Users", "someone")).encode())
    assert text_files(tmp_path) == []
    assert publication_violations(tmp_path) == []


def test_worktree_git_pointer_file_is_skipped(tmp_path: Path) -> None:
    """A linked worktree's ``.git`` is a file holding a local gitdir pointer."""
    pointer = "gitdir: " + _posix("home", "someone", "repo", ".git", "worktrees", "wt") + "\n"
    (tmp_path / ".git").write_text(pointer, encoding="utf-8")
    assert text_files(tmp_path) == []
    assert publication_violations(tmp_path) == []
