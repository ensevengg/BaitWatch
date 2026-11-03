"""The judge client: reply length and failure handling."""

from __future__ import annotations

import json

from read.config import JudgeConfig
from read.judge import Judge


class _Response:
    def __init__(self, body):
        self.body = body

    def read(self):
        return json.dumps(self.body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _judge(tmp_path, **kw):
    endpoint = {"name": "main", "base_url": "http://judge.test/v1", "model": "m",
                "api_key_env": None, "reasoning_effort": "low", "can_clear": True}
    return Judge(JudgeConfig(endpoints=(endpoint,), ledger_path=tmp_path / "spend.json", **kw))


def _answer(verdict="benign"):
    return {"choices": [{"message": {"content": json.dumps(
        {"verdict": verdict, "severity": 0.1, "explanation": "x"})}}], "usage": {}}


def test_request_leaves_room_for_reasoning(tmp_path, monkeypatch):
    sent = {}

    def fake(req, timeout):
        sent.update(json.loads(req.data))
        return _Response(_answer())

    monkeypatch.setattr("urllib.request.urlopen", fake)
    _judge(tmp_path).review("t", "f", 0.5)
    assert sent["max_tokens"] >= 1000
    assert sent["reasoning_effort"] == "low"


def test_one_timeout_does_not_end_judging(tmp_path, monkeypatch):
    def slow(req, timeout):
        raise TimeoutError("slow")

    monkeypatch.setattr("urllib.request.urlopen", slow)
    judge = _judge(tmp_path)
    judge.review("a", "f", 0.5)
    assert not judge._is_dead("main")
    judge.review("b", "f", 0.5)
    judge.review("c", "f", 0.5)
    assert judge._is_dead("main")


def test_padding_cannot_push_text_out_of_the_judges_view(tmp_path):
    judge = _judge(tmp_path)
    for pad in (" " * 6000, "\n" * 6000, "\u200b" * 6000, "\t \n" * 2000):
        snippet, cut = judge._prepare("intro" + pad + "PAYLOAD")
        assert "PAYLOAD" in snippet and not cut


def test_window_over_the_limit_keeps_both_ends_and_cannot_clear(tmp_path, monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout: _Response(_answer()))
    judge = _judge(tmp_path)
    text = "HEAD " + "word " * 3000 + "TAIL"
    snippet, cut = judge._prepare(text)
    assert cut and "HEAD" in snippet and "TAIL" in snippet
    result = judge.review(text, "f", 0.99)
    assert result.verdict == "benign" and result.can_clear is False
