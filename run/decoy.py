"""The decoy agent loop. Model calls leave only from the host; every tool call
runs inside the cage, and every call — reads included, since hash-diff only sees
writes — lands in `tool_log`."""

import json
import time
from typing import Any

from run.evidence import CommandResult, RunError, State
from run.llm import LLMBackend, LLMReply, ToolCall
from run.sandbox import Sandbox

DEFAULT_TASK = "Set up and test this repository following its README and instructions."
MAX_STEPS = 20
READ_BYTES = 16 * 1024
FEEDBACK_CHARS = 8 * 1024

_ARG_KEY = {"read_file": "path", "list_files": "path", "run_cmd": "command"}
_DEFAULTS = {"list_files": "."}


def _system_prompt(task: str) -> str:
    return (
        "You are a helpful autonomous coding agent working on a repository checkout "
        "mounted at /repo on a Linux machine.\n"
        f"Task: {task}\n"
        "Inspect the repository first (list_files, read README.md), then set it up and "
        "test it exactly as the repository's own instructions describe. "
        "Make one tool call per step. "
        "When the task is done, reply with a short summary and no tool call."
    )


def _tools() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": f"Read up to the first {READ_BYTES} bytes of a repository file.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "File path relative to /repo."}
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_files",
                "description": "List a directory of the repository.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Directory path, default '.'"}
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "run_cmd",
                "description": "Run a shell command string in the repository working directory.",
                "parameters": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
            },
        },
    ]


def _argv(name: str, value: str) -> list[str]:
    if name == "read_file":
        return ["head", "-c", str(READ_BYTES), "--", value]
    if name == "list_files":
        return ["ls", "-la", "--", value]
    # The one permitted shell string: it runs inside the cage, never on the host.
    return ["sh", "-c", value]


def _feedback(result: CommandResult) -> str:
    parts = [text for text in (result.stdout, result.stderr) if text]
    if result.timed_out:
        parts.append("the command was killed after its time limit")
    elif result.exit_code:
        parts.append(f"exit code {result.exit_code}")
    text = "\n".join(parts)
    if len(text) > FEEDBACK_CHARS:
        text = text[:FEEDBACK_CHARS] + f"\n[truncated; the full output was {len(text)} characters]"
    return text or "(no output)"


class _DecoyFailure(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _check_cage(sandbox: Sandbox, deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise _DecoyFailure("DECOY_DEADLINE", "the decoy exceeded its cage lifetime")
    checker = getattr(sandbox, "cage_running", None)
    if checker is None:
        return
    try:
        running = checker()
    except Exception:
        running = False
    if not running:
        raise _DecoyFailure("CAGE_EXITED", "the cage is not running")


def _failed_call(name: str, message: str) -> tuple[CommandResult, str]:
    return CommandResult(command=[name], stderr=message[:1000]), f"tool error: {message}"


def _run_tool(sandbox: Sandbox, call: ToolCall) -> tuple[CommandResult, str]:
    name = call.name if isinstance(call.name, str) else ""
    key = _ARG_KEY.get(name)
    if key is None:
        return _failed_call(name or "<invalid>", f"unknown tool {name!r}")
    arguments = call.arguments if isinstance(call.arguments, dict) else {}
    value = arguments.get(key, _DEFAULTS.get(name))
    if not isinstance(value, str) or not value:
        return _failed_call(name, f"{name} requires a nonempty string {key!r}")
    if "\0" in value:
        return _failed_call(name, f"{name} argument must not contain NUL")
    result = sandbox.exec(_argv(name, value))
    # tool_log records what the decoy asked for; the exec kept the cage-side argv.
    return result.model_copy(update={"command": [name, value]}), _feedback(result)


def _assistant_message(reply: LLMReply) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": reply.text or None,
        "tool_calls": [
            {
                "id": call.id,
                "type": "function",
                "function": {"name": call.name, "arguments": json.dumps(call.arguments)},
            }
            for call in reply.tool_calls
        ],
    }


def run_decoy(
    sandbox: Sandbox,
    backend: LLMBackend,
    *,
    max_steps: int = MAX_STEPS,
    task: str = DEFAULT_TASK,
) -> None:
    """Drive the model loop; runtime failures are recorded fail-closed.

    COMPLETE means the loop ended without a model or cage error, whether the
    model finished or spent its step budget. Invalid arguments raise ValueError
    before anything runs. The decoy alone never makes a run ALLOW; it only
    fills the evidence.
    """
    if type(max_steps) is not int or max_steps < 1:
        raise ValueError("max_steps must be a positive integer")
    evidence = sandbox.evidence
    baseline_errors = len(evidence.errors)
    config = getattr(sandbox, "config", None)
    seconds = getattr(config, "decoy_seconds", None)
    deadline = time.monotonic() + seconds if type(seconds) in (int, float) and seconds > 0 else None
    messages: list[dict[str, Any]] = [{"role": "system", "content": _system_prompt(task)}]
    try:
        for _ in range(max_steps):
            _check_cage(sandbox, deadline)
            reply = backend.chat(messages, _tools())
            _check_cage(sandbox, deadline)
            if not reply.tool_calls:
                break
            messages.append(_assistant_message(reply))
            for call in reply.tool_calls:
                result, feedback = _run_tool(sandbox, call)
                evidence.tool_log.append(result)
                if len(evidence.errors) > baseline_errors:
                    # exec recorded a cage failure but returned its result;
                    # continuing would let the loop end COMPLETE over it.
                    raise RuntimeError("the sandbox recorded an error during a tool call")
                messages.append({"role": "tool", "tool_call_id": call.id, "content": feedback})
        _check_cage(sandbox, deadline)
    except Exception as exc:
        evidence.components.decoy = State.ERROR
        code = exc.code if isinstance(exc, _DecoyFailure) else "DECOY_FAILED"
        evidence.errors.append(
            RunError(code=code, message=str(exc)[:1000] or "the decoy loop failed")
        )
        evidence.status = "error"
        return
    evidence.components.decoy = State.COMPLETE
