"""Documentation and demo invariants that the team depends on."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_required_docs_exist() -> None:
    for rel in ("attacks/README.md", "docs/HOOKS.md", "demo/README.md", "demo/run_demo.sh"):
        assert (REPO_ROOT / rel).is_file(), rel


def test_demo_stays_inside_three_minutes() -> None:
    text = (REPO_ROOT / "demo" / "run_demo.sh").read_text(encoding="utf-8")
    beats = re.findall(r'beat "(\d+):(\d+)"', text)
    assert beats
    assert max(int(minutes) * 60 + int(seconds) for minutes, seconds in beats) <= 180


def test_demo_uses_the_cpu_stand_in_and_writes_nothing() -> None:
    text = (REPO_ROOT / "demo" / "run_demo.sh").read_text(encoding="utf-8")
    assert "BAITWATCH_HOOK_SCANNER=keyword" in text
    assert "--dry-run" in text
    assert "attacks check" in text
    assert "attacks/harness" in text or "attacks.harness" in text


def test_hook_docs_cover_fail_closed_and_bypass() -> None:
    text = (REPO_ROOT / "docs" / "HOOKS.md").read_text(encoding="utf-8")
    assert "BAITWATCH_ON_ERROR" in text
    assert "BAITWATCH_HOOK=off" in text
    assert "BAITWATCH_HOOK_SCANNER" in text
    assert "fail" in text.lower()
    assert "UserPromptSubmit" in text
    assert "PreToolUse" in text


def test_attack_readme_names_prior_work_without_a_url() -> None:
    text = (REPO_ROOT / "attacks" / "README.md").read_text(encoding="utf-8")
    assert "De-Caffeinator" in text
    assert "http://" not in text
    assert "https://" not in text
