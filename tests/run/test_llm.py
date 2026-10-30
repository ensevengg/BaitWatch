import json
import random
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from run.llm import (
    LLMError,
    LLMReply,
    OpenAICompatBackend,
    ScriptedBackend,
    ToolCall,
    _parse_reply,
    make_backend,
)

ENV = "BAITWATCH_TEST_API_KEY"
SECRET = "sk-test-secret-never-leak"

Responder = Callable[[bytes], tuple[int, bytes]]


@dataclass
class Recorded:
    path: str
    headers: dict[str, str]
    body: bytes


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        self.server.requests.append(
            Recorded(self.path, {key.lower(): value for key, value in self.headers.items()}, raw)
        )
        status, body = self.server.responder(raw)
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass

    def log_message(self, fmt: str, *args: object) -> None:
        pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, responder: Responder) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.responder = responder
        self.requests: list[Recorded] = []

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}/v1"


@contextmanager
def fake_server(responder: Responder) -> Iterator[_Server]:
    server = _Server(responder)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def reply(payload: dict[str, object]) -> Responder:
    body = json.dumps(payload).encode()
    return lambda _raw: (200, body)


def completion(message: dict[str, object]) -> dict[str, object]:
    return {"choices": [{"message": message}]}


def test_scripted_replays_each_step_then_done():
    backend = ScriptedBackend(
        [
            [ToolCall(name="read_file", arguments={"path": "README.md"})],
            [
                ToolCall(name="run", arguments={"command": ["true"]}),
                ToolCall(name="noop", arguments={}),
            ],
        ]
    )
    assert backend.chat([{"role": "user", "content": "ignored"}], [{"not": "tools"}]) == LLMReply(
        tool_calls=[ToolCall(name="read_file", arguments={"path": "README.md"}, id="call-0")]
    )
    assert backend.chat([], []).tool_calls == [
        ToolCall(name="run", arguments={"command": ["true"]}, id="call-1"),
        ToolCall(name="noop", arguments={}, id="call-2"),
    ]
    assert backend.chat([], []) == LLMReply(text="done")
    assert backend.chat([], []) == LLMReply(text="done")


def test_scripted_snapshots_arguments_and_empty_scripts_are_done():
    arguments = {"path": "README.md"}
    backend = ScriptedBackend([[ToolCall(name="read_file", arguments=arguments)]])
    arguments["path"] = "changed"
    assert backend.chat([], []).tool_calls[0].arguments == {"path": "README.md"}
    assert ScriptedBackend([]).chat([], []) == LLMReply(text="done")


@pytest.mark.parametrize(
    "steps",
    [
        "not-a-step-list",
        [["not-a-call"]],
        [[ToolCall(name="", arguments={})]],
        [[ToolCall(name="read_file", arguments=[])]],
        [[ToolCall(name="read_file", arguments={1: "not-json"})]],
    ],
)
def test_scripted_rejects_bad_steps(steps):
    with pytest.raises(LLMError):
        ScriptedBackend(steps)


def test_scripted_from_json_replays_and_assigns_ids(tmp_path):
    path = tmp_path / "script.json"
    path.write_text(
        json.dumps(
            [
                [{"name": "read_file", "arguments": {"path": "a"}}],
                [{"name": "write_file", "arguments": {"path": "b", "content": "x"}}],
            ]
        )
    )
    backend = ScriptedBackend.from_json(path)
    assert backend.chat([], []).tool_calls == [
        ToolCall(name="read_file", arguments={"path": "a"}, id="call-0")
    ]
    assert backend.chat([], []).tool_calls == [
        ToolCall(name="write_file", arguments={"path": "b", "content": "x"}, id="call-1")
    ]
    assert backend.chat([], []) == LLMReply(text="done")


@pytest.mark.parametrize(
    "payload",
    [
        "{",
        {},
        [1],
        [[1]],
        [[{"name": "read_file"}]],
        [[{"arguments": {}}]],
        [[{"name": "read_file", "arguments": []}]],
        [[{"name": 1, "arguments": {}}]],
        [[{"name": "", "arguments": {}}]],
        [[{"name": "read_file", "arguments": {}, "id": "call-0"}]],
    ],
)
def test_scripted_from_json_rejects_bad_shapes(tmp_path, payload):
    path = tmp_path / "script.json"
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload))
    with pytest.raises(LLMError):
        ScriptedBackend.from_json(path)


def test_scripted_from_json_reads_file_failures_as_llm_errors(tmp_path):
    with pytest.raises(LLMError, match="cannot read"):
        ScriptedBackend.from_json(tmp_path / "missing.json")


def test_openai_request_shape_and_tool_call_parsing(monkeypatch):
    monkeypatch.setenv(ENV, SECRET)
    message = {
        "content": "checking",
        "tool_calls": [
            {
                "id": "call_a",
                "type": "function",
                "function": {"name": "read_file", "arguments": '{"path": "README.md"}'},
            },
            {
                "id": "call_b",
                "type": "function",
                "function": {"name": "noop", "arguments": "{}"},
            },
        ],
    }
    messages = [{"role": "user", "content": "scan this"}]
    tools = [{"type": "function", "function": {"name": "noop", "parameters": {}}}]
    with fake_server(reply(completion(message))) as server:
        backend = OpenAICompatBackend(
            server.base_url,
            "decoy-model",
            api_key_env=ENV,
            temperature=0,
            seed=0,
        )
        assert backend.chat(messages, tools) == LLMReply(
            text="checking",
            tool_calls=[
                ToolCall(name="read_file", arguments={"path": "README.md"}, id="call_a"),
                ToolCall(name="noop", arguments={}, id="call_b"),
            ],
        )
        request = server.requests[0]
    assert request.path == "/v1/chat/completions"
    assert request.headers["authorization"] == f"Bearer {SECRET}"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(request.body) == {
        "model": "decoy-model",
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
        "temperature": 0,
        "seed": 0,
    }


@pytest.mark.parametrize("finish_reason", ["length", "content_filter"])
@pytest.mark.parametrize("with_tool_calls", [False, True])
def test_openai_unfinished_replies_raise(finish_reason, with_tool_calls):
    message: dict[str, object] = {"content": "starting..."}
    if with_tool_calls:
        message["tool_calls"] = [{"id": "call_1", "function": {"name": "noop", "arguments": "{}"}}]
    payload = {"choices": [{"finish_reason": finish_reason, "message": message}]}
    with fake_server(reply(payload)) as server:
        backend = OpenAICompatBackend(server.base_url, "m")
        with pytest.raises(LLMError, match=finish_reason):
            backend.chat([], [])


@pytest.mark.parametrize("finish_reason", ["stop", None, "missing"])
def test_openai_finished_replies_are_accepted(finish_reason):
    choice: dict[str, object] = {"message": {"content": "done"}}
    if finish_reason != "missing":
        choice["finish_reason"] = finish_reason
    payload = {"choices": [choice]}
    with fake_server(reply(payload)) as server:
        backend = OpenAICompatBackend(server.base_url, "m")
        assert backend.chat([], []) == LLMReply(text="done")


@pytest.mark.parametrize(
    "finish_reason",
    ["length", "content_filter", "max_tokens", "error", "tool_use", "bogus", "", 5, True, [], {}],
)
@pytest.mark.parametrize("with_tool_calls", [False, True])
def test_openai_any_other_finish_reason_raises(finish_reason, with_tool_calls):
    message: dict[str, object] = {"content": "partial"}
    if with_tool_calls:
        message["tool_calls"] = [{"id": "call_1", "function": {"name": "noop", "arguments": "{}"}}]
    payload = {"choices": [{"finish_reason": finish_reason, "message": message}]}
    with fake_server(reply(payload)) as server:
        backend = OpenAICompatBackend(server.base_url, "m")
        with pytest.raises(LLMError, match="did not finish"):
            backend.chat([], [])


def test_openai_tool_calls_reason_without_calls_raises():
    payload = {"choices": [{"finish_reason": "tool_calls", "message": {"content": "no calls"}}]}
    with fake_server(reply(payload)) as server:
        backend = OpenAICompatBackend(server.base_url, "m")
        with pytest.raises(LLMError, match="tool calls"):
            backend.chat([], [])


@pytest.mark.parametrize("finish_reason", ["stop", "tool_calls", None, "missing"])
def test_openai_replies_with_calls_are_tool_steps_whatever_stop_servers_send(finish_reason):
    message = {
        "content": None,
        "tool_calls": [
            {"id": "call_1", "type": "function", "function": {"name": "noop", "arguments": "{}"}}
        ],
    }
    choice: dict[str, object] = {"message": message}
    if finish_reason != "missing":
        choice["finish_reason"] = finish_reason
    with fake_server(reply({"choices": [choice]})) as server:
        backend = OpenAICompatBackend(server.base_url, "m")
        assert backend.chat([], []) == LLMReply(
            tool_calls=[ToolCall(name="noop", arguments={}, id="call_1")]
        )


def test_openai_text_reply_without_calls_or_key(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    with fake_server(reply(completion({"content": "done"}))) as server:
        backend = OpenAICompatBackend(server.base_url, "m")
        assert backend.chat([], []) == LLMReply(text="done")
        request = server.requests[0]
    assert "authorization" not in request.headers


def test_openai_null_content_and_missing_seed(monkeypatch):
    message = {
        "content": None,
        "tool_calls": [
            {
                "id": "call_1",
                "function": {"name": "noop", "arguments": "{}"},
            }
        ],
    }
    with fake_server(reply(completion(message))) as server:
        backend = OpenAICompatBackend(server.base_url, "m", seed=None)
        assert backend.chat([], []) == LLMReply(
            text="", tool_calls=[ToolCall(name="noop", arguments={}, id="call_1")]
        )
        body = json.loads(server.requests[0].body)
    assert "seed" not in body


def test_api_key_is_read_at_call_time(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    with fake_server(reply(completion({"content": "ok"}))) as server:
        backend = OpenAICompatBackend(server.base_url, "m", api_key_env=ENV)
        with pytest.raises(LLMError, match=ENV):
            backend.chat([], [])
        monkeypatch.setenv(ENV, "late-key")
        assert backend.chat([], []).text == "ok"
        assert server.requests[0].headers["authorization"] == "Bearer late-key"


@pytest.mark.parametrize("value", ["", "bad\nkey", "bad\rkey"])
def test_api_key_values_with_control_characters_are_rejected(monkeypatch, value):
    monkeypatch.setenv(ENV, value)
    backend = OpenAICompatBackend("http://127.0.0.1:1/v1", "m", api_key_env=ENV)
    with pytest.raises(LLMError, match=ENV):
        backend.chat([], [])


def test_api_key_never_appears_in_repr_or_errors(monkeypatch):
    monkeypatch.setenv(ENV, SECRET)
    with fake_server(lambda _raw: (500, b'{"error": "nope"}')) as server:
        backend = OpenAICompatBackend(server.base_url, "m", api_key_env=ENV)
        assert SECRET not in repr(backend)
        with pytest.raises(LLMError) as caught:
            backend.chat([], [])
    assert SECRET not in str(caught.value)
    assert SECRET not in repr(caught.value)


@pytest.mark.parametrize("status", [400, 401, 403, 429, 500])
def test_openai_non_2xx_raises_short_error(status):
    with fake_server(lambda _raw: (status, b'{"error": "boom"}')) as server:
        backend = OpenAICompatBackend(server.base_url, "m")
        with pytest.raises(LLMError, match=f"HTTP {status}"):
            backend.chat([], [])


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b"\xff",
        b"[]",
        b'{"choices": "x"}',
        b'{"choices": []}',
        b'{"choices": [{}]}',
        b'{"choices": [{"message": {"content": 5}}]}',
        b'{"choices": [{"message": {"tool_calls": {}}}]}',
        b'{"choices": [{"message": {"tool_calls": [{}]}}]}',
        b'{"choices": [{"message": {"tool_calls": [{"function": {"arguments": "{}"}}]}}]}',
        b'{"choices": [{"message": {"tool_calls": [{"function": {"name": "x", '
        b'"arguments": "not-json"}}]}}]}',
        b'{"choices": [{"message": {"tool_calls": [{"function": {"name": "x", '
        b'"arguments": "[1]"}}]}}]}',
        b'{"choices": [{"message": {"tool_calls": [{"id": 5, "function": {"name": "x", '
        b'"arguments": "{}"}}]}}]}',
    ],
)
def test_openai_malformed_responses_raise(payload):
    with fake_server(lambda _raw: (200, payload)) as server:
        backend = OpenAICompatBackend(server.base_url, "m")
        with pytest.raises(LLMError):
            backend.chat([], [])


def test_openai_oversize_response_raises():
    payload = b'{"choices": []}' + b" " * 100
    with fake_server(lambda _raw: (200, payload)) as server:
        backend = OpenAICompatBackend(server.base_url, "m", max_response_bytes=10)
        with pytest.raises(LLMError, match="exceeds"):
            backend.chat([], [])


def test_openai_timeout_raises(monkeypatch):
    def slow(_raw: bytes) -> tuple[int, bytes]:
        time.sleep(0.3)
        return 200, b"{}"

    with fake_server(slow) as server:
        backend = OpenAICompatBackend(server.base_url, "m", timeout_seconds=0.05)
        with pytest.raises(LLMError, match="timed out"):
            backend.chat([], [])


def test_openai_dripping_body_hits_the_wall_clock_deadline():
    # One byte per drip is slower than any single socket operation, so only the
    # overall deadline per chat() call can end this.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def drip() -> None:
        with listener:
            conn, _ = listener.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: 1000000\r\n\r\n"
                )
                try:
                    while True:
                        conn.sendall(b"x")
                        time.sleep(0.05)
                except OSError:
                    pass

    threading.Thread(target=drip, daemon=True).start()
    backend = OpenAICompatBackend(f"http://127.0.0.1:{port}/v1", "m", timeout_seconds=0.5)
    started = time.monotonic()
    with pytest.raises(LLMError, match="timed out"):
        backend.chat([], [])
    assert time.monotonic() - started < 5


def test_openai_network_error_raises():
    with fake_server(reply(completion({"content": "ok"}))) as server:
        base_url = server.base_url
    backend = OpenAICompatBackend(base_url, "m", timeout_seconds=1)
    with pytest.raises(LLMError, match="request failed"):
        backend.chat([], [])


def test_openai_max_calls_cap():
    with fake_server(reply(completion({"content": "ok"}))) as server:
        backend = OpenAICompatBackend(server.base_url, "m", max_calls=2)
        assert backend.chat([], []).text == "ok"
        assert backend.chat([], []).text == "ok"
        with pytest.raises(LLMError, match="budget"):
            backend.chat([], [])
        assert len(server.requests) == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        {"temperature": True},
        {"temperature": -0.1},
        {"temperature": float("nan")},
        {"temperature": float("inf")},
        {"temperature": 10**400},
        {"seed": True},
        {"seed": -1},
        {"seed": 1.0},
        {"timeout_seconds": 0},
        {"timeout_seconds": -1},
        {"timeout_seconds": True},
        {"timeout_seconds": float("inf")},
        {"max_calls": 0},
        {"max_calls": True},
        {"max_calls": 1.0},
        {"max_response_bytes": -1},
        {"max_response_bytes": True},
    ],
)
def test_openai_rejects_invalid_numeric_options(kwargs):
    with pytest.raises(ValueError):
        OpenAICompatBackend("http://127.0.0.1:1/v1", "m", **kwargs)


@pytest.mark.parametrize(
    "base_url",
    [
        "",
        "ftp://127.0.0.1/v1",
        "file:///tmp/model",
        "127.0.0.1:11434/v1",
        "http://",
        "http://user:pass@127.0.0.1/v1",
        "http://127.0.0.1/v1?query=1",
        "http://127.0.0.1:0/v1",
        "http://127.0.0.1:notaport/v1",
        "http://127.0.0.1/v1 extra",
    ],
)
def test_openai_rejects_bad_base_urls(base_url):
    with pytest.raises(ValueError):
        OpenAICompatBackend(base_url, "m")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"model": ""},
        {"model": None},
        {"model": "m", "api_key_env": ""},
        {"model": "m", "api_key_env": 5},
    ],
)
def test_openai_rejects_bad_model_and_key_env(kwargs):
    with pytest.raises(ValueError):
        OpenAICompatBackend("http://127.0.0.1:1/v1", **kwargs)


def test_make_backend_scripted(tmp_path):
    path = tmp_path / "script.json"
    path.write_text(json.dumps([[{"name": "read_file", "arguments": {"path": "a"}}]]))
    backend = make_backend(f"scripted:{path}")
    assert isinstance(backend, ScriptedBackend)
    assert backend.chat([], []).tool_calls == [
        ToolCall(name="read_file", arguments={"path": "a"}, id="call-0")
    ]


def test_make_backend_ollama_keeps_model_colon():
    backend = make_backend("ollama:llama3.1:8b")
    assert isinstance(backend, OpenAICompatBackend)
    assert backend.base_url == "http://127.0.0.1:11434/v1"
    assert backend.model == "llama3.1:8b"
    assert backend.api_key_env is None


def test_make_backend_openai():
    backend = make_backend("openai:http://127.0.0.1:8000/v1#decoy#DECOY_KEY")
    assert isinstance(backend, OpenAICompatBackend)
    assert backend.base_url == "http://127.0.0.1:8000/v1"
    assert backend.model == "decoy"
    assert backend.api_key_env == "DECOY_KEY"
    keyless = make_backend("openai:https://example.invalid/v1#decoy")
    assert keyless.api_key_env is None


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "scripted",
        "scripted:",
        "ollama:",
        "openai:",
        "openai:http://127.0.0.1:1/v1#",
        "openai:#model",
        "openai:http://127.0.0.1:1/v1#model#env#extra",
        "openai:ftp://127.0.0.1/v1#model",
        "other:value",
    ],
)
def test_make_backend_rejects_bad_specs(spec):
    with pytest.raises(ValueError):
        make_backend(spec)


def _random_json_value(rng: random.Random, depth: int = 0) -> Any:
    kinds = ["str", "int", "float", "bool", "none"]
    if depth < 4:
        kinds += ["dict", "list"]
    kind = rng.choice(kinds)
    if kind == "str":
        return "".join(rng.choice('ab"\\\n\t xé\U0001f600') for _ in range(rng.randrange(0, 12)))
    if kind == "int":
        return rng.randrange(-(10**12), 10**12)
    if kind == "float":
        return rng.choice([0.5, -1.25, 1e300])
    if kind == "bool":
        return rng.choice([True, False])
    if kind == "none":
        return None
    if kind == "dict":
        return {
            rng.choice("abc"): _random_json_value(rng, depth + 1)
            for _ in range(rng.randrange(0, 4))
        }
    return [_random_json_value(rng, depth + 1) for _ in range(rng.randrange(0, 4))]


def _random_arguments_json(rng: random.Random) -> str:
    roll = rng.random()
    if roll < 0.5:
        return json.dumps(_random_json_value(rng))
    if roll < 0.7:
        return "{" * rng.randrange(1, 10)
    if roll < 0.9:
        return "9" * rng.randrange(1, 6000)
    return "[" * 250000 + "]" * 250000


def _random_body(rng: random.Random) -> bytes:
    roll = rng.random()
    if roll < 0.4:
        return json.dumps(_random_json_value(rng)).encode()
    if roll < 0.9:
        message: dict[str, Any] = {}
        if rng.random() < 0.8:
            message["content"] = rng.choice([None, "text", 5, ["list"]])
        if rng.random() < 0.8:
            message["tool_calls"] = rng.choice(
                [
                    {},
                    "no",
                    [
                        rng.choice(
                            [
                                None,
                                5,
                                {"id": rng.choice(["c1", 5, None])},
                                {"function": rng.choice([None, {}, "f"])},
                                {
                                    "function": {
                                        "name": rng.choice(["t", "", 5]),
                                        "arguments": _random_arguments_json(rng),
                                    }
                                },
                            ]
                        )
                        for _ in range(rng.randrange(0, 3))
                    ],
                ]
            )
        choice: dict[str, Any] = {"message": message}
        if rng.random() < 0.7:
            choice["finish_reason"] = rng.choice(
                ["stop", "tool_calls", None, "length", "content_filter", 5]
            )
        return json.dumps({"choices": rng.choice([[choice], [], ["x"], [choice, choice]])}).encode()
    if roll < 0.95:
        return ("[" * 250000 + "]" * 250000).encode()
    return ("9" * rng.randrange(1, 6000)).encode()


def test_parse_reply_returns_a_reply_or_an_llm_error_never_anything_else():
    rng = random.Random(20261028)
    for case in range(300):
        body = _random_body(rng)
        try:
            reply = _parse_reply(body)
        except LLMError:
            continue
        except Exception as exc:
            pytest.fail(f"case {case}: _parse_reply raised {type(exc).__name__}: {exc}")
        assert isinstance(reply, LLMReply)
        assert isinstance(reply.text, str)
        for call in reply.tool_calls:
            assert isinstance(call, ToolCall)
            assert isinstance(call.name, str) and call.name
            assert isinstance(call.arguments, dict)
            assert isinstance(call.id, str)


def test_parse_reply_roundtrips_tool_names_and_arguments():
    rng = random.Random(20261029)
    for _ in range(300):
        text = rng.choice([None, "", "checking", "a€\U0001f600b"])
        calls = [
            {
                "id": f"call-{index}",
                "type": "function",
                "function": {
                    "name": rng.choice(["read_file", "run_cmd", "tél"]),
                    "arguments": json.dumps(
                        {
                            rng.choice("abc"): _random_json_value(rng, 2)
                            for _ in range(rng.randrange(0, 4))
                        }
                    ),
                },
            }
            for index in range(rng.randrange(0, 4))
        ]
        message = {"tool_calls": calls} if calls else {"content": text}
        content_sent = not calls
        if calls and rng.random() < 0.5:
            message["content"] = text
            content_sent = True
        finish_reason = "tool_calls" if calls else rng.choice(["stop", None])
        body = json.dumps(
            {"choices": [{"finish_reason": finish_reason, "message": message}]}
        ).encode()
        reply = _parse_reply(body)
        assert isinstance(reply, LLMReply)
        assert reply.text == ((text or "") if content_sent else "")
        for parsed, raw in zip(reply.tool_calls, calls, strict=True):
            assert parsed.name == raw["function"]["name"]
            assert parsed.id == raw["id"]
            assert parsed.arguments == json.loads(raw["function"]["arguments"])


def _mutate(rng: random.Random, text: str) -> str:
    for _ in range(rng.randrange(0, 4)):
        if not text:
            text = rng.choice(":#sox")
            continue
        position = rng.randrange(len(text))
        action = rng.random()
        if action < 0.4:
            text = text[:position] + rng.choice(":#/\\ .téx") + text[position:]
        elif action < 0.8:
            text = text[:position] + text[position + 1 :]
        else:
            text = text[:position] + rng.choice(":x#") + text[position + 1 :]
    return text


def test_make_backend_returns_or_raises_only_value_error_or_llm_error(monkeypatch):
    monkeypatch.setenv(ENV, SECRET)
    templates = [
        "",
        ":",
        "scripted",
        "scripted:",
        "scripted:/tmp/does-not-exist.json",
        "ollama:",
        "ollama:llama3.1:8b",
        "openai:",
        "openai:http://127.0.0.1:1/v1#m",
        f"openai:http://127.0.0.1:1/v1#m#{ENV}",
        "openai:ftp://127.0.0.1:1/v1#m#env",
        "unknown:whatever",
    ]
    rng = random.Random(20261030)
    specs = [_mutate(rng, rng.choice(templates)) for _ in range(300)]
    specs += [
        "".join(rng.choice(":#/\\ab01 .\t") for _ in range(rng.randrange(0, 24)))
        for _ in range(200)
    ]
    for spec in specs:
        try:
            backend = make_backend(spec)
        except (ValueError, LLMError) as exc:
            assert SECRET not in str(exc)
        except Exception as exc:
            pytest.fail(f"make_backend({spec!r}) raised {type(exc).__name__}: {exc}")
        else:
            assert callable(backend.chat)
            assert SECRET not in repr(backend)


def test_make_backend_rejects_hostile_scripted_files(tmp_path):
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 250000 + "]" * 250000)
    with pytest.raises(LLMError):
        make_backend(f"scripted:{deep}")
    huge = tmp_path / "huge.json"
    huge.write_text("[9" + "9" * 5000 + "]")
    with pytest.raises(LLMError):
        make_backend(f"scripted:{huge}")


@pytest.mark.parametrize(
    "url", ["http://api.example/v1", "http://localhost.evil.example/v1", "http://127.0.0.2/v1"]
)
def test_api_keys_are_not_sent_to_remote_plain_http(monkeypatch, url):
    monkeypatch.setenv(ENV, SECRET)
    with pytest.raises(ValueError, match="HTTPS"):
        OpenAICompatBackend(url, "fixture", api_key_env=ENV)


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
@pytest.mark.parametrize("proxy_env", ["http_proxy", "HTTP_PROXY"])
@pytest.mark.parametrize("keyed", [False, True])
def test_local_http_key_bypasses_environment_proxy(monkeypatch, host, proxy_env, keyed):
    for name in (
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
        "REQUEST_METHOD",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(ENV, SECRET)
    with (
        fake_server(reply(completion({"content": "direct"}))) as endpoint,
        fake_server(reply(completion({"content": "proxy"}))) as proxy,
    ):
        monkeypatch.setenv(proxy_env, proxy.base_url.removesuffix("/v1"))
        monkeypatch.setenv("ALL_PROXY", proxy.base_url.removesuffix("/v1"))
        backend = OpenAICompatBackend(
            f"http://{host}:{endpoint.server_port}/v1",
            "m",
            api_key_env=ENV if keyed else None,
        )
        assert backend.chat([], []).text == ("direct" if keyed else "proxy")
        if keyed:
            assert endpoint.requests[0].headers["authorization"] == f"Bearer {SECRET}"
            assert proxy.requests == []
        else:
            assert endpoint.requests == []
            assert "authorization" not in proxy.requests[0].headers
