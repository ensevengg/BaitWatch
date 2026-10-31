import time
from types import SimpleNamespace

from run.decoy import run_decoy
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

    def chat(self, messages, tools):
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


def test_both_backend_failure_is_non_allow():
    from run.llm import LLMError

    sandbox = FakeSandbox()

    class Down:
        def chat(self, messages, tools):
            raise LLMError("both primary and fallback LLM backends failed", kind="both_failed")

    run_decoy(sandbox, Down())
    assert sandbox.evidence.components.decoy == State.ERROR
    assert _verdict(sandbox.evidence).verdict != "ALLOW"
