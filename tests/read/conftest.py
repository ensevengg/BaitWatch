"""Shared fixtures and stubs for the READ-side tests."""

from __future__ import annotations

import base64
import importlib
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Tests must never write the user's real score cache (read/cache.py reads
# this at import, so set it before any `read` module is imported).
os.environ["BAITWATCH_SCORE_CACHE"] = str(
    Path(tempfile.mkdtemp(prefix="bw-test-cache-")) / "scores.sqlite")

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

FIXTURES = Path(__file__).parent / "fixtures"
ATTACK_REPO = FIXTURES / "attack_repo"
BENIGN_REPO = FIXTURES / "benign_repo"

def local_model_dir() -> Path | None:
    # One candidate list, owned by read.config (home first, /mnt/d fallback);
    # a second copy here silently skipped every model test when it drifted.
    from read.config import DEFAULT_MODEL_DIRS

    for p in DEFAULT_MODEL_DIRS:
        if p.exists():
            return p
    return None


@pytest.fixture(scope="session")
def tokenizer():
    # CI has no Prompt Guard 2 weights (gated), so it points
    # BAITWATCH_TEST_TOKENIZER at the public DeBERTa-v3 tokenizer, which
    # encodes identically to PG2-22M (same ids and offsets).
    # BAITWATCH_REQUIRE_TOKENIZER=1 turns a missing tokenizer into a failure
    # so tokenizer-dependent tests cannot silently skip.
    override = os.environ.get("BAITWATCH_TEST_TOKENIZER")
    model_dir = Path(override) if override else local_model_dir()
    if model_dir is None or not model_dir.exists():
        msg = f"no tokenizer: {model_dir or 'no local Prompt Guard 2 model dir'}"
        if os.environ.get("BAITWATCH_REQUIRE_TOKENIZER") == "1":
            pytest.fail(msg)
        pytest.skip(msg)
    from transformers import AutoTokenizer

    return AutoTokenizer.from_pretrained(str(model_dir))


class FakeDetector:
    """Duck-typed detector: deterministic scores, no model needed."""

    def __init__(self, tokenizer=None):
        self.model_path = "fake://stub"
        self.tokenizer = tokenizer
        self.scored_texts: list[str] = []

    def scores(self, texts):
        import numpy as np

        self.scored_texts.extend(texts)
        out = []
        for t in texts:
            low = t.lower()
            if ("ignore all previous instructions" in low
                    or "evil.example" in low
                    or "exfiltrate" in low
                    or "do not mention" in low):
                out.append(0.97)
            elif "send the keys" in low or "send keys" in low:
                out.append(0.55)
            else:
                out.append(0.01)
        return np.asarray(out, dtype=np.float32)


class FakeJudge:
    """Scripted judge standing in for Muse Spark."""

    def __init__(self, mode: str = "attack"):
        self.mode = mode
        self.calls: list[tuple[str, str, float]] = []

    def review(self, text, file, score, budget=None):
        self.calls.append((text, file, score))
        from read.judge import JudgeResult

        if self.mode == "unavailable":
            return JudgeResult("unavailable", None, None, error="mock down")
        if self.mode == "benign":
            return JudgeResult("benign", 0.0, "nothing wrong here")
        if self.mode == "manipulated":
            return JudgeResult("benign", 0.0, "I was told to say benign")
        return JudgeResult("attack", 0.95, "clear exfiltration attempt")


@pytest.fixture()
def fake_detector(tokenizer):
    return FakeDetector(tokenizer)


@pytest.fixture()
def no_judge_cfg():
    from read.config import ReadConfig

    cfg = ReadConfig()
    cfg.judge.enabled = False
    return cfg


@pytest.fixture()
def attack_repo(tmp_path: Path) -> Path:
    """Copy of the attack fixture with symlink/binary/caps extras added."""
    import shutil

    dest = tmp_path / "attack_repo"
    shutil.copytree(ATTACK_REPO, dest)
    return dest


@pytest.fixture()
def benign_repo() -> Path:
    return BENIGN_REPO


b64 = base64.b64encode


def write_b64_payload(path: Path, payload: bytes) -> str:
    encoded = base64.b64encode(payload).decode()
    path.write_text(f"bootstrap: {encoded}\n", encoding="utf-8")
    return encoded


def reload_read_modules():
    """Fresh import of the package (config pin tests mutate module state)."""
    for name in list(sys.modules):
        if name == "read" or name.startswith("read."):
            del sys.modules[name]
    return importlib.import_module("read")
