"""Decoy brain backends. Model calls only ever leave from the host; the cage stays offline."""

import http.client
import json
import math
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

ERROR_DETAIL_BYTES = 200
RESPONSE_CHUNK_BYTES = 64 * 1024


class LLMError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]
    id: str = ""


@dataclass(frozen=True)
class LLMReply:
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMBackend(Protocol):
    """`messages` and `tools` use the OpenAI chat-completions shapes."""

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMReply: ...


class ScriptedBackend:
    """Deterministic replay; CI uses this without any model endpoint."""

    def __init__(self, steps: Sequence[Sequence[ToolCall]]) -> None:
        if isinstance(steps, (str, bytes)) or not isinstance(steps, Sequence):
            raise LLMError("scripted steps must be a sequence of tool-call sequences")
        parsed: list[tuple[ToolCall, ...]] = []
        for step in steps:
            if isinstance(step, (str, bytes)) or not isinstance(step, Sequence):
                raise LLMError("each scripted step must be a sequence of tool calls")
            calls: list[ToolCall] = []
            for call in step:
                _validate_scripted_call(call)
                calls.append(ToolCall(name=call.name, arguments=dict(call.arguments)))
            parsed.append(tuple(calls))
        self._steps = tuple(parsed)
        self._index = 0
        self._next_id = 0

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMReply:
        if self._index >= len(self._steps):
            return LLMReply(text="done")
        step = self._steps[self._index]
        self._index += 1
        calls: list[ToolCall] = []
        for call in step:
            calls.append(
                ToolCall(
                    name=call.name,
                    arguments=dict(call.arguments),
                    id=f"call-{self._next_id}",
                )
            )
            self._next_id += 1
        return LLMReply(tool_calls=calls)

    @classmethod
    def from_json(cls, path: str | Path) -> "ScriptedBackend":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError) as exc:
            raise LLMError(f"cannot read scripted tool script: {exc}") from None
        except (ValueError, RecursionError) as exc:
            raise LLMError(f"scripted tool script is not valid JSON: {exc}") from None
        if not isinstance(data, list):
            raise LLMError("scripted tool script must be a list of steps")
        steps: list[list[ToolCall]] = []
        for step_index, step in enumerate(data):
            if not isinstance(step, list):
                raise LLMError(f"scripted step {step_index} must be a list")
            calls: list[ToolCall] = []
            for call_index, call in enumerate(step):
                where = f"scripted step {step_index} call {call_index}"
                if not isinstance(call, dict) or set(call) != {"name", "arguments"}:
                    raise LLMError(f"{where} must have exactly name and arguments")
                name = call["name"]
                arguments = call["arguments"]
                if not isinstance(name, str) or not name:
                    raise LLMError(f"{where} needs a nonempty string name")
                if not isinstance(arguments, dict):
                    raise LLMError(f"{where} arguments must be a JSON object")
                calls.append(ToolCall(name=name, arguments=arguments))
            steps.append(calls)
        return cls(steps)


def _validate_scripted_call(call: object) -> None:
    if not isinstance(call, ToolCall):
        raise LLMError("scripted steps must contain ToolCall values")
    if not isinstance(call.name, str) or not call.name:
        raise LLMError("scripted tool calls need a nonempty name")
    if not isinstance(call.arguments, dict) or not all(
        isinstance(key, str) for key in call.arguments
    ):
        raise LLMError("scripted tool arguments must be a JSON object")


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Following a redirect could forward the Authorization header to another host.
        return None


class OpenAICompatBackend:
    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        api_key_env: str | None = None,
        temperature: float = 0,
        seed: int | None = 0,
        timeout_seconds: float = 60,
        max_calls: int = 40,
        max_response_bytes: int = 1024 * 1024,
    ) -> None:
        self.base_url = _validated_base_url(base_url)
        if not isinstance(model, str) or not model:
            raise ValueError("model must be a nonempty string")
        if api_key_env is not None and (not isinstance(api_key_env, str) or not api_key_env):
            raise ValueError("api_key_env must be a nonempty environment variable name")
        if seed is not None and (type(seed) is not int or seed < 0):
            raise ValueError("seed must be a non-negative integer or None")
        self.model = model
        self.api_key_env = api_key_env
        self.temperature = _finite_number("temperature", temperature, allow_zero=True)
        self.seed = seed
        self.timeout_seconds = _finite_number("timeout_seconds", timeout_seconds, allow_zero=False)
        self.max_calls = _positive_int("max_calls", max_calls)
        self.max_response_bytes = _positive_int("max_response_bytes", max_response_bytes)
        self._calls = 0
        self._opener = urllib.request.build_opener(_NoRedirects())

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(base_url={self.base_url!r}, model={self.model!r}, "
            f"api_key_env={self.api_key_env!r})"
        )

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> LLMReply:
        if self._calls >= self.max_calls:
            raise LLMError(f"LLM call budget of {self.max_calls} is exhausted")
        self._calls += 1
        api_key = self._api_key()
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": self.temperature,
        }
        if self.seed is not None:
            payload["seed"] = self.seed
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if api_key is not None:
            headers["Authorization"] = f"Bearer {api_key}"
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        return _parse_reply(self._post(request))

    def _api_key(self) -> str | None:
        if self.api_key_env is None:
            return None
        key = os.environ.get(self.api_key_env)
        if not key or any(ord(char) < 0x20 or ord(char) == 0x7F for char in key):
            raise LLMError(f"API key environment variable {self.api_key_env} is missing or invalid")
        return key

    def _post(self, request: urllib.request.Request) -> bytes:
        # The socket timeout bounds one operation, so a body that drips a byte at
        # a time would never hit it; this deadline bounds the whole exchange.
        deadline = time.monotonic() + self.timeout_seconds
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                raw = _read_bounded(response, self.max_response_bytes, deadline)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise LLMError(f"LLM endpoint returned HTTP {exc.code}") from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise LLMError(f"LLM request timed out after {self.timeout_seconds}s") from None
            raise LLMError(f"LLM request failed: {_short_reason(exc.reason)}") from None
        except TimeoutError:
            raise LLMError(f"LLM request timed out after {self.timeout_seconds}s") from None
        except http.client.HTTPException as exc:
            raise LLMError(f"LLM request failed: {type(exc).__name__}") from None
        except ValueError as exc:
            # Invalid header values (for example a non-ASCII key) can include the
            # value in their message, so only the exception type is reported.
            raise LLMError(f"LLM request failed: {type(exc).__name__}") from None
        except OSError as exc:
            raise LLMError(f"LLM request failed: {_short_reason(exc)}") from None
        if len(raw) > self.max_response_bytes:
            raise LLMError(f"LLM response exceeds {self.max_response_bytes} bytes")
        return raw


def _read_bounded(response: http.client.HTTPResponse, limit: int, deadline: float) -> bytes:
    # read1 returns after one system call, so each drip lands as its own chunk
    # and the deadline is checked between them.
    chunks: list[bytes] = []
    total = 0
    while total <= limit:
        if time.monotonic() >= deadline:
            raise TimeoutError("the response body outlived the request deadline")
        chunk = response.read1(min(RESPONSE_CHUNK_BYTES, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _parse_reply(raw: bytes) -> LLMReply:
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        # A model endpoint can serve arbitrarily nested JSON or over-long
        # integer literals; both raise before decoding, neither a JSONDecodeError.
        raise LLMError("LLM response is not valid JSON") from None
    if not isinstance(data, dict):
        raise LLMError("LLM response must be a JSON object")
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise LLMError("LLM response has no choices")
    choice = choices[0]
    if not isinstance(choice, dict):
        raise LLMError("LLM response choice is malformed")
    finish_reason = choice.get("finish_reason")
    # An allowlist, not a denylist: only a plain stop and a tool step are finished
    # replies. Some OpenAI-compatible servers send stop alongside tool calls, so
    # a missing reason accepts either shape; everything else — length,
    # content_filter, max_tokens, undocumented or non-string values — is not.
    if finish_reason is not None and finish_reason not in ("stop", "tool_calls"):
        raise LLMError(f"LLM response did not finish: finish_reason={finish_reason!r}")
    message = choice.get("message")
    if not isinstance(message, dict):
        raise LLMError("LLM response message is malformed")
    content = message.get("content")
    if content is None:
        text = ""
    elif isinstance(content, str):
        text = content
    else:
        raise LLMError("LLM response content must be text")
    raw_calls = message.get("tool_calls")
    if raw_calls is None:
        raw_calls = []
    if not isinstance(raw_calls, list):
        raise LLMError("LLM response tool_calls must be a list")
    calls = [_parse_tool_call(call) for call in raw_calls]
    if not calls and finish_reason == "tool_calls":
        raise LLMError("LLM response promised tool calls but carried none")
    return LLMReply(text=text, tool_calls=calls)


def _parse_tool_call(raw: object) -> ToolCall:
    if not isinstance(raw, dict):
        raise LLMError("LLM response tool call is malformed")
    function = raw.get("function")
    if not isinstance(function, dict):
        raise LLMError("LLM response tool call has no function")
    name = function.get("name")
    if not isinstance(name, str) or not name:
        raise LLMError("LLM response tool call has no name")
    arguments_json = function.get("arguments")
    if not isinstance(arguments_json, str):
        raise LLMError("LLM tool call arguments must be a JSON string")
    try:
        arguments = json.loads(arguments_json)
    except (ValueError, RecursionError):
        raise LLMError("LLM tool call arguments are not valid JSON") from None
    if not isinstance(arguments, dict):
        raise LLMError("LLM tool call arguments must be a JSON object")
    call_id = raw.get("id", "")
    if not isinstance(call_id, str):
        raise LLMError("LLM tool call id must be text")
    return ToolCall(name=name, arguments=arguments, id=call_id)


def _validated_base_url(base_url: object) -> str:
    if not isinstance(base_url, str) or not base_url:
        raise ValueError("base_url must be a nonempty http(s) URL")
    if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in base_url):
        raise ValueError("base_url must not contain whitespace or control characters")
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base_url must be an http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("base_url must not embed credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain a query or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("base_url has an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("base_url has an invalid port")
    return base_url.rstrip("/")


def _finite_number(name: str, value: object, *, allow_zero: bool) -> int | float:
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be a finite number")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError(f"{name} must be a finite number")
    if value < 0 or (value == 0 and not allow_zero):
        raise ValueError(f"{name} must be {'non-negative' if allow_zero else 'positive'}")
    return value


def _positive_int(name: str, value: object) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _short_reason(value: object) -> str:
    text = str(value).strip()
    return text[:ERROR_DETAIL_BYTES] if text else type(value).__name__


def make_backend(spec: str) -> LLMBackend:
    if not isinstance(spec, str) or ":" not in spec:
        raise ValueError("LLM spec must be scripted:PATH, ollama:MODEL, or openai:BASE_URL#MODEL")
    kind, _, argument = spec.partition(":")
    if not argument:
        raise ValueError("LLM spec is missing its argument")
    if kind == "scripted":
        return ScriptedBackend.from_json(argument)
    if kind == "ollama":
        return OpenAICompatBackend("http://127.0.0.1:11434/v1", argument)
    if kind == "openai":
        parts = argument.split("#")
        if len(parts) not in (2, 3) or any(not part for part in parts):
            raise ValueError("openai spec must be openai:BASE_URL#MODEL[#API_KEY_ENV]")
        return OpenAICompatBackend(
            parts[0],
            parts[1],
            api_key_env=parts[2] if len(parts) == 3 else None,
        )
    raise ValueError(f"unknown LLM backend {kind!r}")
