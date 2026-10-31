"""Generated repos: test-data markers, recovery, layers, drift."""

from __future__ import annotations

from pathlib import Path

from attacks import build
from attacks.decoderlib import produce_views
from attacks.manifests import load_manifest
from attacks.synth.generate import build_examples, build_repos
from attacks.synth.training import build_training_repos

REPO_ROOT = Path(__file__).resolve().parents[2]
ATTACKS = REPO_ROOT / "attacks"
REPOS = ATTACKS / "repos"
EXAMPLES = ATTACKS / "examples"

BASE_REPOS = {
    "readme-bait-curl",
    "runtime-eval-chain",
    "markdown-ghost",
    "agent-config-injection",
    "git-hook-installer",
}
EXPECTED_REPOS = BASE_REPOS | {repo.name for repo in build_training_repos()}


def test_expected_repo_set() -> None:
    assert {path.name for path in REPOS.iterdir() if path.is_dir()} == EXPECTED_REPOS


def test_training_split_has_two_repos_per_weak_class() -> None:
    prefixes = {"safety_off", "concealment", "supply_chain", "destructive", "context_leak", "rce"}
    counts: dict[str, int] = {}
    for repo in build_training_repos():
        if repo.threat.startswith("none:"):
            continue
        weak_class = repo.threat.split(":", 1)[0]
        counts[weak_class] = counts.get(weak_class, 0) + 1
    assert set(counts) == prefixes
    assert set(counts.values()) == {2}


def test_five_harmless_twins() -> None:
    twins = [repo for repo in build_training_repos() if repo.threat.startswith("none:")]
    assert len(twins) == 5
    for repo in twins:
        assert repo.entries
        assert {entry.expected_layer for entry in repo.entries} == {"RUN"}


def test_training_files_are_contribution_sized() -> None:
    for repo in build_training_repos():
        for path, text in repo.files.items():
            if not path.endswith(".md"):
                continue
            lines = len(text.splitlines())
            assert 200 <= lines <= 600, (repo.name, path, lines)


def test_training_attacks_sit_mid_file() -> None:
    for repo in build_training_repos():
        for entry in repo.entries:
            total = len(repo.files[entry.file].splitlines())
            assert 0.35 <= entry.line / total <= 0.65, (repo.name, entry.file, entry.line, total)


def test_every_repo_is_marked_as_test_data() -> None:
    for name in EXPECTED_REPOS:
        marker = REPOS / name / ".baitwatch-test-data"
        assert marker.is_file(), name
        text = marker.read_text(encoding="utf-8")
        assert "BaitWatch" in text
        assert "test data" in text.lower()
        assert "must never" in text.lower()


def test_every_repo_has_a_manifest() -> None:
    for name in EXPECTED_REPOS:
        manifest = load_manifest(REPOS / name / "MANIFEST.json")
        assert manifest["repo"] == name
        assert manifest["entries"]


def test_all_payloads_are_recoverable(decoders: list) -> None:
    missing = []
    for repo in build_repos().values():
        for entry in repo.entries:
            views = produce_views(repo.files[entry.file], decoders)
            if not any(entry.payload in view.text for view in views):
                missing.append((repo.name, entry.file, entry.encoding))
    assert missing == []


def test_example_payloads_are_recoverable(decoders: list) -> None:
    missing = []
    for example in build_examples():
        for entry in example.entries:
            views = produce_views(example.content, decoders)
            if not any(entry.payload in view.text for view in views):
                missing.append((example.path, entry.encoding))
    assert missing == []


def test_generated_tree_matches_disk() -> None:
    assert build.check_tree() == []


def test_no_real_dotenv_is_committed() -> None:
    for path in ATTACKS.rglob(".env*"):
        assert path.name in (".env.example", ".env.sample", ".env.template"), path


def test_readme_bait_covers_http_and_https() -> None:
    repo = build_repos()["readme-bait-curl"]
    payloads = [entry.payload for entry in repo.entries]
    assert any("http://evil.example" in payload for payload in payloads)
    assert any("https://evil.example" in payload for payload in payloads)


def test_agent_config_repo_covers_every_agent_file() -> None:
    repo = build_repos()["agent-config-injection"]
    files = {entry.file for entry in repo.entries}
    assert {
        "AGENTS.md",
        "CLAUDE.md",
        ".cursorrules",
        ".github/copilot-instructions.md",
        ".vscode/settings.json",
        ".claude/settings.json",
    } <= files
    assert {".vscode/tasks.json", ".mcp.json"} <= files


def test_git_hook_is_executable_shaped() -> None:
    hook = (REPOS / "git-hook-installer" / "hooks" / "pre-commit").read_text(encoding="utf-8")
    assert hook.startswith("#!/bin/sh\n")
    assert "base64 -d" in hook


def test_layers_are_represented_across_the_corpus() -> None:
    layers = {entry.expected_layer for repo in build_repos().values() for entry in repo.entries}
    assert layers == {"READ", "RUN", "both"}


def test_encodings_are_represented_across_the_corpus() -> None:
    encodings = {entry.encoding for repo in build_repos().values() for entry in repo.entries}
    assert {
        "base64",
        "hex",
        "zero_width_binary",
        "unicode_tags",
        "variation_selectors",
        "bidi",
        "html_comment",
        "js_eval",
    } <= encodings


def test_examples_exist_for_each_threat() -> None:
    groups = sorted(path.name for path in EXAMPLES.iterdir() if path.is_dir())
    assert groups == ["agent-config", "git-hook", "markdown-ghost", "readme-bait", "runtime-eval"]
    for group in groups:
        assert len(list((EXAMPLES / group).glob("*"))) == 2, group
