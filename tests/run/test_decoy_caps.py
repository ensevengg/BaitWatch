import time
from types import SimpleNamespace

from run.decoy import TURN_TOKENS, run_decoy
from run.evidence import CommandResult, RunEvidence, State
from run.llm import LLMReply, ToolCall
from run.verdict import ReadOutcome, fuse


class FakeSandbox:
    def __init__(self):
        self.evidence = RunEvidence()
        self.config = SimpleNamespace(decoy_seconds=120)
        self.argv = []

    def cage_running(self):
        return True

    def exec(self, argv):
        self.argv.append(list(argv))
        return CommandResult(command=list(argv), exit_code=0)


class Backend:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.name = "fake"
        self.bounds = []

    def chat(self, messages, tools, *, max_tokens=None):
        self.bounds.append(max_tokens)
        return self.replies.pop(0) if self.replies else LLMReply(text="done")


def _verdict(evidence):
    return fuse(ReadOutcome(status=State.COMPLETE, verdict="clean"), evidence)


def test_token_cap_is_non_allow():
    sandbox = FakeSandbox()
    reply = LLMReply(
        tool_calls=[ToolCall(id="1", name="run_cmd", arguments={"command": "true"})],
        prompt_tokens=900,
        completion_tokens=200,
        total_tokens=1100,
        backend="openai:m@x",
    )
    run_decoy(sandbox, Backend(reply), max_tokens=100)
    assert sandbox.evidence.components.decoy == State.ERROR
    assert sandbox.evidence.errors[-1].code == "DECOY_TOKEN_BUDGET"
    assert sandbox.evidence.decoy_total_tokens == 1100
    assert sandbox.argv == []
    assert _verdict(sandbox.evidence).verdict != "ALLOW"


def test_token_estimate_cap_is_non_allow():
    sandbox = FakeSandbox()
    reply = LLMReply(
        tool_calls=[ToolCall(id="1", name="run_cmd", arguments={"command": "true"})],
        text="x" * 500,
    )
    run_decoy(sandbox, Backend(reply), max_tokens=10)
    assert sandbox.evidence.errors[-1].code == "DECOY_TOKEN_BUDGET"
    assert sandbox.evidence.decoy_tokens_estimated is True
    assert _verdict(sandbox.evidence).verdict != "ALLOW"


def test_time_cap_is_non_allow():
    sandbox = FakeSandbox()

    class Slow:
        name = "slow"

        def chat(self, messages, tools):
            time.sleep(0.05)
            return LLMReply(text="done")

    run_decoy(sandbox, Slow(), max_seconds=0.01)
    assert sandbox.evidence.errors[-1].code == "DECOY_TIME_BUDGET"
    assert _verdict(sandbox.evidence).verdict != "ALLOW"


def test_wall_budget_wins_over_dead_cage():
    class DyingSandbox(FakeSandbox):
        alive = True

        def cage_running(self):
            return self.alive

    sandbox = DyingSandbox()

    class Slow:
        name = "slow"

        def chat(self, messages, tools):
            sandbox.alive = False
            time.sleep(0.05)
            return LLMReply(text="done")

    run_decoy(sandbox, Slow(), max_seconds=0.01)
    assert sandbox.evidence.errors[-1].code == "DECOY_TIME_BUDGET"
    assert _verdict(sandbox.evidence).verdict != "ALLOW"


def test_cli_configs_give_cage_grace_beyond_wall_budget(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from run.cli import app as run_app
    from run.evidence import RunComponents
    from run.scan_cli import app as scan_app

    seen = {}
    complete = RunEvidence(
        status="complete",
        tool_log=[CommandResult(command=["run_cmd", "true"], exit_code=0)],
        components=RunComponents(**{k: State.COMPLETE for k in RunComponents.model_fields}),
    )

    def fake_detonate(*args, **kwargs):
        seen.setdefault("configs", []).append(kwargs["config"])
        return complete

    monkeypatch.setattr("run.llm.make_backend", lambda spec: "backend", raising=False)
    monkeypatch.setattr("run.cli.detonate", fake_detonate)
    monkeypatch.setattr("run.scan_cli.make_backend_with_fallback", lambda spec, fb=None: object())
    monkeypatch.setattr("run.scan.detonate", fake_detonate)
    monkeypatch.setattr(
        "run.scan.default_read_scanner",
        lambda path, **kwargs: ReadOutcome(status=State.COMPLETE, verdict="clean"),
    )
    runner = CliRunner()
    decoy_result = runner.invoke(
        run_app, ["decoy", str(tmp_path), "--llm", "scripted:x", "--max-seconds", "30"]
    )
    scan_result = runner.invoke(
        scan_app, ["scan", str(tmp_path), "--llm", "scripted:x", "--max-seconds", "30"]
    )
    assert decoy_result.exit_code == 0, decoy_result.output
    assert scan_result.exit_code == 0, scan_result.output
    assert len(seen["configs"]) == 2
    for config in seen["configs"]:
        assert config.decoy_seconds > 30
        assert config.decoy_max_seconds == 30


def test_turn_cap_still_non_allow():
    sandbox = FakeSandbox()
    reply = LLMReply(tool_calls=[ToolCall(id="1", name="list_files", arguments={})])
    run_decoy(sandbox, Backend(reply, reply, reply), max_steps=2)
    assert sandbox.evidence.errors[-1].code == "DECOY_STEP_BUDGET"
    assert _verdict(sandbox.evidence).verdict != "ALLOW"


def test_backend_and_tokens_recorded_on_success():
    sandbox = FakeSandbox()
    reply = LLMReply(
        text="done", prompt_tokens=5, completion_tokens=2, total_tokens=7, backend="openai:m@x"
    )
    run_decoy(sandbox, Backend(reply))
    assert sandbox.evidence.components.decoy == State.COMPLETE
    assert sandbox.evidence.decoy_backend == "openai:m@x"
    assert sandbox.evidence.decoy_total_tokens == 7


def test_token_bound_shrinks_as_budget_is_spent():
    sandbox = FakeSandbox()
    first = LLMReply(
        tool_calls=[ToolCall(id="1", name="run_cmd", arguments={"command": "true"})],
        prompt_tokens=20,
        completion_tokens=10,
        total_tokens=30,
    )
    second = LLMReply(text="done", prompt_tokens=5, completion_tokens=5, total_tokens=10)
    backend = Backend(first, second)
    run_decoy(sandbox, backend, max_tokens=100)
    assert backend.bounds == [100, 70]
    assert sandbox.evidence.components.decoy == State.COMPLETE


def test_both_backend_failure_is_non_allow():
    from run.llm import LLMError

    sandbox = FakeSandbox()

    class Down:
        def chat(self, messages, tools):
            raise LLMError("both primary and fallback LLM backends failed", kind="both_failed")

    run_decoy(sandbox, Down())
    assert sandbox.evidence.components.decoy == State.ERROR
    assert _verdict(sandbox.evidence).verdict != "ALLOW"


def test_token_bound_never_exceeds_the_per_turn_ceiling():
    sandbox = FakeSandbox()
    backend = Backend(LLMReply(text="done", total_tokens=10))
    run_decoy(sandbox, backend)
    assert backend.bounds == [TURN_TOKENS]


def test_exhausted_budget_fails_before_the_next_request():
    sandbox = FakeSandbox()
    first = LLMReply(
        tool_calls=[ToolCall(id="1", name="run_cmd", arguments={"command": "true"})],
        total_tokens=50,
    )
    backend = Backend(first, LLMReply(text="never sent"))
    run_decoy(sandbox, backend, max_tokens=50)
    assert backend.bounds == [50]
    assert sandbox.evidence.components.decoy == State.ERROR
    assert [error.code for error in sandbox.evidence.errors] == ["DECOY_TOKEN_BUDGET"]
    assert _verdict(sandbox.evidence).verdict != "ALLOW"
