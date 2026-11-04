"""Accepted files, self-approval and the rules for opening a file."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from hooks.cache import ApprovalStore, TrustStore, default_approval_path
from hooks.guard import _project_path, _verdict_from_read, static_tool_decision
from hooks.install import stale_install_warnings


def finding(file, score=1.0, layer="model", **evidence):
    return SimpleNamespace(file=file, score=score, layer=layer, evidence=evidence)


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("BAITWATCH_HOOK_APPROVALS", str(tmp_path / "state" / "approvals.json"))
    root = tmp_path / "repo"
    root.mkdir()
    (root / "AGENTS.md").write_text("run setup\n")
    return root


def test_accepted_file_stays_accepted_until_it_changes(repo):
    store = TrustStore()
    store.set_pending(repo, "ask", ["AGENTS.md"])
    assert store.accept_pending(repo) == (["AGENTS.md"], [])
    assert TrustStore().is_trusted(repo, "AGENTS.md")
    (repo / "AGENTS.md").write_text("run something else\n")
    assert not TrustStore().is_trusted(repo, "AGENTS.md")


def test_the_trust_file_is_outside_the_repository(repo):
    assert not TrustStore().path.is_relative_to(repo)
    assert TrustStore().path.parent == default_approval_path().parent


def test_a_block_needs_allow_block(repo):
    store = TrustStore()
    store.set_pending(repo, "block", ["AGENTS.md"])
    assert store.accept_pending(repo) == ([], ["AGENTS.md"])
    assert not store.is_trusted(repo, "AGENTS.md")
    assert store.accept_pending(repo, allow_block=True) == (["AGENTS.md"], [])


def test_a_file_changed_after_it_was_flagged_is_refused(repo):
    store = TrustStore()
    store.set_pending(repo, "ask", ["AGENTS.md"])
    (repo / "AGENTS.md").write_text("swapped after the person read it\n")
    fresh = TrustStore()
    assert fresh.accept_pending(repo) == ([], ["AGENTS.md"])
    assert not TrustStore().is_trusted(repo, "AGENTS.md")


def test_tag_changes_when_a_file_is_accepted_and_revoke_clears_it(repo):
    store = TrustStore()
    assert store.tag(repo) == ""
    store.set_pending(repo, "ask", ["AGENTS.md"])
    store.accept_pending(repo)
    tagged = store.tag(repo)
    assert tagged
    assert store.revoke(repo) == 1
    assert store.tag(repo) == ""
    assert ApprovalStore().revoke(repo) == 0


@pytest.mark.parametrize(
    "command",
    [
        "python -m hooks approve --allow-block",
        '"/venv/bin/python" -I -m hooks approve --minutes 15',
        "echo '{}' > ~/.cache/baitwatch/trusted-files.json",
        "cp x ~/.cache/baitwatch/approvals.json",
    ],
)
def test_an_agent_cannot_approve_for_itself(command):
    assert static_tool_decision("Bash", {"command": command}).verdict == "block"


def test_a_quoted_attack_never_stops_the_prompt_but_is_refused_when_opened():
    flagged = [finding("README.md", judge_mention=True, model_score=1.0)]
    assert _verdict_from_read("attack", flagged, 0.3) == ("allow", ["README.md"])


def test_an_unknown_user_is_a_real_relative_path(tmp_path):
    (tmp_path / "~nosuchuser.md").write_text("x\n")
    path = _project_path("~nosuchuser.md", tmp_path, tmp_path)
    assert path == tmp_path / "~nosuchuser.md"


def test_a_nul_in_a_path_is_not_a_file(tmp_path):
    assert _project_path("a\0b", tmp_path, tmp_path) is None


def test_stale_install_is_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    settings = tmp_path / ".claude" / "settings.json"
    settings.parent.mkdir()
    hook = {"type": "command", "command": "python -m hooks gate-a", "timeout": 30}
    settings.write_text(json.dumps({"hooks": {"UserPromptSubmit": [{"hooks": [hook]}]}}))
    assert any("timeout of 30s" in x for x in stale_install_warnings())
    hook["timeout"] = 630
    settings.write_text(json.dumps({"hooks": {"UserPromptSubmit": [{"hooks": [hook]}]}}))
    assert stale_install_warnings() == []


def test_block_needs_the_judge_to_confirm_a_window_the_model_flagged_by_itself():
    strong = finding("AGENTS.md", judge_confirmed=True, model_score=0.999)
    weak = finding("AGENTS.md", judge_confirmed=True, model_score=0.9)
    assert _verdict_from_read("attack", [strong], 0.85, 0.9965)[0] == "block"
    assert _verdict_from_read("attack", [weak], 0.85, 0.9965)[0] == "ask"


def test_code_speaking_to_nobody_asks_rather_than_blocks():
    code = finding(
        ".github/workflows/ci.yml",
        judge_confirmed=True,
        model_score=0.999,
        judge_addressee="nobody",
    )
    assert _verdict_from_read("attack", [code], 0.85, 0.9965)[0] == "ask"
