"""Shared fixtures for the ATTACK-side tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from attacks.decoderlib import builtin_decoders, external_decoders

REPO_ROOT = Path(__file__).resolve().parents[2]
ATTACKS = REPO_ROOT / "attacks"
REPOS = ATTACKS / "repos"
EXAMPLES = ATTACKS / "examples"

HOOK_ENV = (
    "BAITWATCH_HOOK",
    "BAITWATCH_ON_ERROR",
    "BAITWATCH_HOOK_SCANNER",
    "BAITWATCH_REPO",
    "BAITWATCH_HOOK_CACHE",
    "BAITWATCH_HOOK_TTL",
    "BAITWATCH_HOOK_REFRESH",
    "BAITWATCH_HOOK_JUDGE",
    "BAITWATCH_MODEL_PATH",
    "BAITWATCH_SPEND_LEDGER",
)


@pytest.fixture(autouse=True)
def clean_hook_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in HOOK_ENV:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture(scope="session")
def decoders() -> list:
    return builtin_decoders() + external_decoders()


@pytest.fixture(scope="session")
def decoder_names(decoders: list) -> set[str]:
    return {decoder.name for decoder in decoders}
