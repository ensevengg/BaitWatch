"""Manifests: schema, hashes, line spans, neutrality, coverage."""

from __future__ import annotations

import ipaddress
import json
from copy import deepcopy
from pathlib import Path

import pytest

from attacks.lint import SINK_NETWORK
from attacks.manifests import (
    MANIFEST_NAME,
    ManifestError,
    all_entry_files,
    expected_files,
    hash_text,
    iter_manifests,
    span_text,
    validate_manifest,
    verify_hashes,
)
from attacks.synth.generate import build_examples, build_repos
from attacks.synth.transforms import TRANSFORMS

REPO_ROOT = Path(__file__).resolve().parents[2]
ATTACKS = REPO_ROOT / "attacks"
REPOS = ATTACKS / "repos"
EXAMPLES = ATTACKS / "examples"

MANIFESTS = list(iter_manifests(ATTACKS))


def _generated_payloads() -> dict[tuple[str, str, int], str]:
    payloads: dict[tuple[str, str, int], str] = {}
    for repo in build_repos().values():
        for entry in repo.entries:
            payloads[(repo.name, entry.file, entry.line)] = entry.payload
    for example in build_examples():
        for entry in example.entries:
            payloads[("examples", entry.file, entry.line)] = entry.payload
    return payloads


def test_all_six_manifests_are_present() -> None:
    assert len(MANIFESTS) == 6
    names = {manifest["repo"] for _path, manifest in MANIFESTS}
    assert names == {
        "readme-bait-curl",
        "runtime-eval-chain",
        "markdown-ghost",
        "agent-config-injection",
        "git-hook-installer",
        "examples",
    }


def test_schema_and_span_hashes() -> None:
    for path, manifest in MANIFESTS:
        validate_manifest(manifest)
        assert verify_hashes(path.parent, manifest) == [], path


def test_entry_files_exist_and_lines_are_in_range() -> None:
    for path, manifest in MANIFESTS:
        for entry in manifest["entries"]:
            target = path.parent / entry["file"]
            assert target.is_file(), f"{manifest['repo']}: missing {entry['file']}"
            lines = target.read_text(encoding="utf-8").split("\n")
            assert 1 <= entry["line"] <= len(lines)
            assert entry.get("end_line", entry["line"]) <= len(lines)


def test_targets_stay_inside_the_sandbox() -> None:
    allowed_special = {"agent-session"}
    for _path, manifest in MANIFESTS:
        for entry in manifest["entries"]:
            target = entry["target"]
            if target in allowed_special:
                continue
            if target.endswith(".example"):
                continue
            assert ipaddress.ip_address(target) in SINK_NETWORK, target


def test_encoding_is_a_known_transform() -> None:
    for _path, manifest in MANIFESTS:
        for entry in manifest["entries"]:
            assert entry["encoding"] in TRANSFORMS


def test_techniques_are_labelled() -> None:
    for _path, manifest in MANIFESTS:
        for entry in manifest["entries"]:
            assert entry["technique"].strip()
            assert entry["expected_layer"] in ("READ", "RUN", "both")


def test_manifest_hashes_match_the_generator() -> None:
    payloads = _generated_payloads()
    for _path, manifest in MANIFESTS:
        for entry in manifest["entries"]:
            key = (manifest["repo"], entry["file"], entry["line"])
            assert key in payloads, key
            assert entry["decoded_sha256"] == hash_text(payloads[key]), key


def test_manifest_never_contains_payload_text() -> None:
    payloads = _generated_payloads()
    for _path, manifest in MANIFESTS:
        blob = json.dumps(manifest)
        for entry in manifest["entries"]:
            payload = payloads[(manifest["repo"], entry["file"], entry["line"])]
            assert payload not in blob
            assert "Ignore previous instructions" not in blob


def test_manifest_names_match_directories() -> None:
    for path, manifest in MANIFESTS:
        if manifest["repo"] != "examples":
            assert path.parent.name == manifest["repo"]
            assert path.name == MANIFEST_NAME


def test_both_gates_have_expected_files() -> None:
    read = set()
    run = set()
    for _path, manifest in MANIFESTS:
        if manifest["repo"] == "examples":
            continue
        read |= expected_files(manifest, "READ")
        run |= expected_files(manifest, "RUN")
        assert all_entry_files(manifest)
    assert read
    assert run


def test_bad_layer_is_rejected() -> None:
    _path, manifest = MANIFESTS[-1]
    broken = deepcopy(manifest)
    broken["entries"][0]["expected_layer"] = "NEITHER"
    with pytest.raises(ManifestError, match="expected_layer"):
        validate_manifest(broken)


def test_wrong_span_is_rejected() -> None:
    path, manifest = MANIFESTS[0]
    broken = deepcopy(manifest)
    broken["entries"][0]["line"] = 999
    broken["entries"][0]["end_line"] = 999
    problems = verify_hashes(path.parent, broken)
    assert problems and "past end of file" in problems[0]


def test_span_text_is_exact() -> None:
    text = "alpha\nbeta\ngamma\n"
    assert span_text(text, 1, 1) == "alpha"
    assert span_text(text, 2, 2) == "beta"
    assert span_text(text, 1, 3) == "alpha\nbeta\ngamma"
    with pytest.raises(ManifestError):
        span_text(text, 5, 5)
    with pytest.raises(ManifestError):
        span_text(text, 0, 1)


def test_examples_cover_two_per_threat() -> None:
    manifest = next(manifest for _path, manifest in MANIFESTS if manifest["repo"] == "examples")
    groups: dict[str, int] = {}
    for entry in manifest["entries"]:
        group = entry["file"].split("/", 1)[0]
        groups[group] = groups.get(group, 0) + 1
    assert set(groups) == {
        "readme-bait",
        "runtime-eval",
        "markdown-ghost",
        "agent-config",
        "git-hook",
    }
    assert set(groups.values()) == {2}
    assert len(manifest["entries"]) == 10
