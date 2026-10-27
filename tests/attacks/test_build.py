"""Build reproducibility: deterministic bytes, LF endings, no drift."""

from __future__ import annotations

from pathlib import Path

from attacks import build

REPO_ROOT = Path(__file__).resolve().parents[2]
ATTACKS = REPO_ROOT / "attacks"


def test_build_tree_is_deterministic() -> None:
    assert build.build_tree() == build.build_tree()


def test_committed_tree_has_no_drift() -> None:
    assert build.check_tree() == []


def test_expected_file_count() -> None:
    tree = build.build_tree()
    assert len(tree) == 57
    assert sum(1 for path in tree if path.name == "MANIFEST.json") == 5
    assert sum(1 for path in tree if path.name == "manifest.json") == 1


def test_generated_files_use_lf() -> None:
    for path in ATTACKS.rglob("*"):
        if path.is_file() and path.suffix in (
            ".md",
            ".json",
            ".py",
            ".js",
            ".sh",
            ".toml",
            ".txt",
            ".rules",
            "",
        ):
            assert b"\r\n" not in path.read_bytes(), path


def test_package_data_covers_every_generated_file() -> None:
    """Wheel data globs skip dotfiles; every artifact needs an explicit match."""
    import glob
    import tomllib

    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = config["tool"]["setuptools"]["package-data"]["attacks"]
    covered: set[str] = set()
    for pattern in patterns:
        for hit in glob.glob(str(ATTACKS / pattern)):
            cover = Path(hit)
            if cover.is_file() and "__pycache__" not in cover.parts:
                covered.add(cover.relative_to(ATTACKS).as_posix())

    missing = sorted(
        rel
        for rel in (path.relative_to(ATTACKS).as_posix() for path in build.build_tree())
        if rel not in covered
    )
    assert missing == []


def test_manifests_are_json_objects() -> None:
    import json

    for path in ATTACKS.rglob("MANIFEST.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["schema_version"] == 1
        assert data["entries"]
