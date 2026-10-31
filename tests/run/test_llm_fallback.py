import json
import time

import pytest

from run.llm import FallbackBackend, LLMError, OpenAICompatBackend
from tests.run.test_llm import completion, fake_server, reply


def _backend(server, **kw):
    return OpenAICompatBackend(server.base_url, "m", **kw)


def test_usage_from_api_is_used():
    payload = {
        "choices": [{"finish_reason": "stop", "message": {"content": "done"}}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14},
    }
    with fake_server(reply(payload)) as server:
        result = _backend(server).chat([{"role": "user", "content": "hi"}], [])
    assert (result.prompt_tokens, result.completion_tokens, result.total_tokens) == (11, 3, 14)
    assert result.usage_estimated is False
    assert result.backend.startswith("openai:m@")


def test_usage_missing_uses_char_estimate():
    with fake_server(reply(completion({"content": "hello world"}))) as server:
        result = _backend(server).chat([{"role": "user", "content": "scan this repo please"}], [])
    assert result.usage_estimated is True
    assert result.total_tokens > 0
    assert result.total_tokens == result.prompt_tokens + result.completion_tokens


@pytest.mark.parametrize("status", [500, 503, 429])
def test_fallback_on_retryable_http(status):
    with (
        fake_server(lambda _r: (status, b"{}")) as primary,
        fake_server(reply(completion({"content": "fallback ok"}))) as fallback,
    ):
        backend = FallbackBackend(_backend(primary), _backend(fallback))
        assert backend.chat([], []).text == "fallback ok"
        assert backend.fallback_count == 1
        assert backend.last_backend.startswith("openai:")


def test_fallback_on_refused_and_missing_key(monkeypatch):
    monkeypatch.delenv("MISSING_KEY_XYZ", raising=False)
    with fake_server(reply(completion({"content": "ok"}))) as fallback:
        primary = OpenAICompatBackend("http://127.0.0.1:1/v1", "m", api_key_env="MISSING_KEY_XYZ")
        backend = FallbackBackend(primary, _backend(fallback))
        assert backend.chat([], []).text == "ok"
        assert backend.fallback_count == 1


def test_fallback_on_timeout():
    def slow(_raw):
        time.sleep(0.3)
        return 200, b"{}"

    with (
        fake_server(slow) as primary,
        fake_server(reply(completion({"content": "ok"}))) as fallback,
    ):
        backend = FallbackBackend(
            OpenAICompatBackend(primary.base_url, "m", timeout_seconds=0.05),
            _backend(fallback),
        )
        assert backend.chat([], []).text == "ok"


def test_no_fallback_on_4xx():
    with (
        fake_server(lambda _r: (400, b"{}")) as primary,
        fake_server(reply(completion({"content": "ok"}))) as fallback,
    ):
        backend = FallbackBackend(_backend(primary), _backend(fallback))
        with pytest.raises(LLMError) as caught:
            backend.chat([], [])
        assert caught.value.kind == "http_4xx"
        assert backend.fallback_count == 0
        assert fallback.requests == []


def test_both_fail_raises():
    with (
        fake_server(lambda _r: (500, b"{}")) as primary,
        fake_server(lambda _r: (400, b"{}")) as fallback,
    ):
        backend = FallbackBackend(_backend(primary), _backend(fallback))
        with pytest.raises(LLMError, match="both") as caught:
            backend.chat([], [])
        assert caught.value.kind == "both_failed"
        assert "primary=http_5xx" in str(caught.value)
        assert "fallback=http_4xx" in str(caught.value)


def test_chat_payload_carries_token_bound():
    seen = {}

    def capture(raw):
        seen.update(json.loads(raw))
        return 200, json.dumps(completion({"content": "ok"})).encode()

    with fake_server(capture) as server:
        assert _backend(server).chat([], [], max_tokens=123).text == "ok"
    assert seen["max_tokens"] == 123


def test_fallback_passes_same_token_bound():
    seen = {}

    def capture(raw):
        seen.update(json.loads(raw))
        return 200, json.dumps(completion({"content": "ok"})).encode()

    with (
        fake_server(lambda _r: (500, b"{}")) as primary,
        fake_server(capture) as fallback,
    ):
        backend = FallbackBackend(_backend(primary), _backend(fallback))
        assert backend.chat([], [], max_tokens=77).text == "ok"
    assert seen["max_tokens"] == 77


def test_fallback_sends_temperature_and_seed():
    seen = {}

    def capture(raw):
        seen.update(json.loads(raw))
        body = json.dumps(completion({"content": "ok"})).encode()
        return 200, body

    with (
        fake_server(lambda _r: (500, b"{}")) as primary,
        fake_server(capture) as fallback,
    ):
        fb = OpenAICompatBackend(fallback.base_url, "llama", temperature=0, seed=0)
        assert FallbackBackend(_backend(primary), fb).chat([], []).text == "ok"
    assert seen["temperature"] == 0 and seen["seed"] == 0
