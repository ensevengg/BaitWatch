"""Decoy loop unit tests; fakes only, nothing runs in Docker or on the host."""

import pytest
from typer.testing import CliRunner

from run.cli import app
from run.decoy import DEFAULT_TASK, FEEDBACK_CHARS, READ_BYTES, run_decoy
from run.evidence import CommandResult, RunComponents, RunError, RunEvidence, State
from run.llm import LLMError, LLMReply, ToolCall
from run.sandbox import SandboxError

runner = CliRunner()


class FakeSandbox:
    def __init__(self, *results: CommandResult):
        self.evidence = RunEvidence()
        self.argv: list[list[str]] = []
        self._results = list(results)

    def exec(self, argv):
        self.argv.append(list(argv))
        if self._results:
            return self._results.pop(0)
        return CommandResult(command=list(argv))


class FakeBackend:
    def __init__(self, *replies: LLMReply):
        self.replies = list(replies)
        self.turns: list[tuple[list[dict], list[dict]]] = []

    def chat(self, messages, tools):
        self.turns.append((messages, tools))
        return self.replies.pop(0)


class ExplodingBackend:
    def chat(self, messages, tools):
        raise LLMError("provider down")


class ChatterBackend(FakeBackend):
    def chat(self, messages, tools):
        self.turns.append((messages, tools))
        return LLMReply(tool_calls=[ToolCall(id="n", name="list_files", arguments={})])


def test_tool_calls_dispatch_through_sandbox_exec():
    sandbox = FakeSandbox()
    backend = FakeBackend(
        LLMReply(
            tool_calls=[
                ToolCall(id="1", name="read_file", arguments={"path": "README.md"}),
                ToolCall(id="2", name="list_files", arguments={}),
                ToolCall(id="3", name="run_cmd", arguments={"command": "echo hi"}),
            ]
        ),
        LLMReply(text="done"),
    )
    run_decoy(sandbox, backend)
    assert sandbox.argv == [
        ["head", "-c", str(READ_BYTES), "--", "README.md"],
        ["ls", "-la", "--", "."],
        ["sh", "-c", "echo hi"],
    ]
    log = sandbox.evidence.tool_log
    assert [entry.command for entry in log] == [
        ["read_file", "README.md"],
        ["list_files", "."],
        ["run_cmd", "echo hi"],
    ]
    assert sandbox.evidence.components.decoy == State.COMPLETE
    assert not sandbox.evidence.errors
    messages, tools = backend.turns[1]
    assert [entry["role"] for entry in messages] == ["system", "assistant", "tool", "tool", "tool"]
    assert [entry["content"] for entry in messages[2:]] == ["(no output)"] * 3
    assert [entry["function"]["name"] for entry in tools] == [
        "read_file",
        "list_files",
        "run_cmd",
    ]


def test_system_prompt_carries_the_task():
    backend = FakeBackend(LLMReply(text="done"))
    run_decoy(FakeSandbox(), backend, task="audit the lockfile")
    messages, _ = backend.turns[0]
    assert "audit the lockfile" in messages[0]["content"]
    default = FakeBackend(LLMReply(text="done"))
    run_decoy(FakeSandbox(), default)
    assert DEFAULT_TASK in default.turns[0][0][0]["content"]


def test_unknown_tool_is_logged_and_reported_without_exec():
    sandbox = FakeSandbox()
    backend = FakeBackend(
        LLMReply(tool_calls=[ToolCall(id="1", name="rm_rf", arguments={"path": "/"})]),
        LLMReply(text="done"),
    )
    run_decoy(sandbox, backend)
    assert sandbox.argv == []
    entry = sandbox.evidence.tool_log[0]
    assert entry.command == ["rm_rf"]
    assert "unknown tool" in entry.stderr
    messages, _ = backend.turns[1]
    assert messages[2]["content"].startswith("tool error: unknown tool")
    assert sandbox.evidence.components.decoy == State.COMPLETE


def test_bad_arguments_are_logged_and_reported():
    sandbox = FakeSandbox()
    backend = FakeBackend(
        LLMReply(
            tool_calls=[
                ToolCall(id="1", name="read_file", arguments={}),
                ToolCall(id="2", name="run_cmd", arguments={"command": 42}),
                ToolCall(id="3", name="run_cmd", arguments="echo hi"),
            ]
        ),
        LLMReply(text="done"),
    )
    run_decoy(sandbox, backend)
    assert sandbox.argv == []
    assert [entry.command for entry in sandbox.evidence.tool_log] == [
        ["read_file"],
        ["run_cmd"],
        ["run_cmd"],
    ]
    assert all("requires a nonempty string" in entry.stderr for entry in sandbox.evidence.tool_log)
    assert sandbox.evidence.components.decoy == State.COMPLETE


def test_feedback_is_truncated_for_the_model_but_logged_in_full():
    sandbox = FakeSandbox(CommandResult(command=["head"], stdout="x" * 50_000))
    backend = FakeBackend(
        LLMReply(tool_calls=[ToolCall(id="1", name="read_file", arguments={"path": "big"})]),
        LLMReply(text="done"),
    )
    run_decoy(sandbox, backend)
    assert sandbox.evidence.tool_log[0].stdout == "x" * 50_000
    messages, _ = backend.turns[1]
    content = messages[2]["content"]
    assert content.startswith("x" * FEEDBACK_CHARS)
    assert "[truncated" in content
    assert len(content) < FEEDBACK_CHARS + 200


def test_stderr_and_exit_code_reach_the_model():
    sandbox = FakeSandbox(CommandResult(command=["sh"], exit_code=1, stderr="boom"))
    backend = FakeBackend(
        LLMReply(tool_calls=[ToolCall(id="1", name="run_cmd", arguments={"command": "false"})]),
        LLMReply(text="done"),
    )
    run_decoy(sandbox, backend)
    messages, _ = backend.turns[1]
    assert "boom" in messages[2]["content"]
    assert "exit code 1" in messages[2]["content"]


def test_llm_error_fails_the_decoy_closed():
    sandbox = FakeSandbox()
    run_decoy(sandbox, ExplodingBackend())
    assert sandbox.evidence.components.decoy == State.ERROR
    assert sandbox.evidence.errors[0].code == "DECOY_FAILED"
    assert "provider down" in sandbox.evidence.errors[0].message
    assert sandbox.evidence.status == "error"
    assert sandbox.evidence.tool_log == []


def test_cage_failure_fails_the_decoy_closed():
    class DeadCage:
        evidence = RunEvidence()

        def exec(self, argv):
            raise SandboxError("the cage is not running")

    backend = FakeBackend(
        LLMReply(tool_calls=[ToolCall(id="1", name="list_files", arguments={})]),
        LLMReply(text="done"),
    )
    run_decoy(DeadCage(), backend)
    evidence = DeadCage.evidence
    assert evidence.components.decoy == State.ERROR
    assert evidence.errors[0].code == "DECOY_FAILED"
    assert "the cage is not running" in evidence.errors[0].message
    assert evidence.status == "error"


def test_sandbox_error_recorded_during_a_tool_call_fails_the_decoy_closed():
    class SickCage(FakeSandbox):
        def exec(self, argv):
            result = super().exec(argv)
            self.evidence.errors.append(RunError(code="EXEC_KILL_FAILED", message="cannot kill"))
            self.evidence.components.sandbox = State.ERROR
            self.evidence.status = "error"
            return result

    sandbox = SickCage()
    backend = FakeBackend(
        LLMReply(tool_calls=[ToolCall(id="1", name="list_files", arguments={})]),
        LLMReply(text="done"),
    )
    run_decoy(sandbox, backend)
    assert len(backend.turns) == 1
    assert len(sandbox.evidence.tool_log) == 1
    assert sandbox.evidence.components.decoy == State.ERROR
    assert sandbox.evidence.errors[-1].code == "DECOY_FAILED"
    assert sandbox.evidence.status == "error"


def test_step_budget_exhaustion_ends_cleanly():
    sandbox = FakeSandbox()
    backend = ChatterBackend()
    run_decoy(sandbox, backend, max_steps=3)
    assert len(backend.turns) == 3
    assert len(sandbox.evidence.tool_log) == 3
    assert sandbox.evidence.components.decoy == State.COMPLETE
    assert not sandbox.evidence.errors


def test_invalid_max_steps_is_rejected():
    with pytest.raises(ValueError, match="max_steps"):
        run_decoy(FakeSandbox(), FakeBackend(), max_steps=0)
    with pytest.raises(ValueError, match="max_steps"):
        run_decoy(FakeSandbox(), FakeBackend(), max_steps="3")
    with pytest.raises(ValueError, match="max_steps"):
        run_decoy(FakeSandbox(), FakeBackend(), max_steps=True)


def _complete_evidence() -> RunEvidence:
    components = RunComponents(**{name: State.COMPLETE for name in RunComponents.model_fields})
    return RunEvidence(status="complete", components=components)


def test_decoy_cli_passes_backend_spec_and_steps(monkeypatch, tmp_path):
    seen: dict = {}

    def fake_make_backend(spec):
        seen["spec"] = spec
        return "backend"

    monkeypatch.setattr("run.llm.make_backend", fake_make_backend, raising=False)

    def fake_detonate(path, command=("true",), *, config=None, backend=None, max_steps=20):
        seen["backend"] = backend
        seen["max_steps"] = max_steps
        return RunEvidence()

    monkeypatch.setattr("run.cli.detonate", fake_detonate)
    result = runner.invoke(
        app, ["decoy", str(tmp_path), "--llm", "scripted:steps.json", "--max-steps", "7"]
    )
    assert result.exit_code == 2
    assert '"status": "incomplete"' in result.stdout
    assert seen == {"spec": "scripted:steps.json", "backend": "backend", "max_steps": 7}


def test_decoy_cli_exit_zero_only_when_complete(monkeypatch, tmp_path):
    monkeypatch.setattr("run.llm.make_backend", lambda spec: "backend", raising=False)
    monkeypatch.setattr("run.cli.detonate", lambda *args, **kwargs: _complete_evidence())
    result = runner.invoke(app, ["decoy", str(tmp_path), "--llm", "scripted:steps.json"])
    assert result.exit_code == 0
    assert '"status": "complete"' in result.stdout


def test_decoy_cli_error_exits_three(monkeypatch, tmp_path):
    monkeypatch.setattr("run.llm.make_backend", lambda spec: "backend", raising=False)
    evidence = RunEvidence(status="error", errors=[RunError(code="TEST", message="synthetic")])
    monkeypatch.setattr("run.cli.detonate", lambda *args, **kwargs: evidence)
    result = runner.invoke(app, ["decoy", str(tmp_path), "--llm", "scripted:steps.json"])
    assert result.exit_code == 3
