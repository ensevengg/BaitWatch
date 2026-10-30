from pathlib import Path

import pytest
from docker.errors import ImageNotFound

from run.evidence import State
from run.sandbox import Sandbox, SandboxConfig, SandboxError
from run.verdict import ReadOutcome, fuse
from tests.run.test_sandbox_failures import fake_client


def test_default_cage_image():
    assert SandboxConfig().image == "baitwatch-cage:1"


def test_missing_cage_image_fails_closed(repo):
    client = fake_client()
    client.images.get.side_effect = ImageNotFound("missing")
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(SandboxError, match="python -m run.cage build"), sandbox:
        pytest.fail("missing image must not start a scan")
    report = fuse(ReadOutcome(status=State.COMPLETE, verdict="clean"), sandbox.evidence)
    assert report.verdict == "FLAG"
    assert not client.networks.create.called


@pytest.mark.docker
def test_default_cage_has_setup_toolchain(repo: Path, engine, assert_no_leftovers):
    sandbox = Sandbox(repo)
    with sandbox:
        result = sandbox.run_command(
            [
                "sh",
                "-ec",
                "python --version; python3 --version; pip --version; curl --version; "
                "git --version; make --version; bash --version; node --version; npm --version; "
                'test -s /etc/ssl/certs/ca-certificates.crt; test "$(id -u)" = 65532',
            ]
        )
    assert result.exit_code == 0, result.stderr
    assert not sandbox.evidence.errors
    assert_no_leftovers(sandbox.evidence)


@pytest.mark.docker
@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("printf hook > .git/hooks/pre-commit", "BLOCK"),
        ("git config core.hooksPath ./hooks", "BLOCK"),
        ("true", "ALLOW"),
    ],
)
def test_staged_git_metadata_is_traced(repo, engine, assert_no_leftovers, command, expected):
    from run.llm import ScriptedBackend, ToolCall
    from run.sandbox import detonate

    (repo / ".git").mkdir()
    (repo / ".git" / "HOST_ONLY").write_text("never copy")
    evidence = detonate(
        repo,
        backend=ScriptedBackend(
            [
                [ToolCall("run_cmd", {"command": command})],
            ]
        ),
    )
    report = fuse(ReadOutcome(status=State.COMPLETE, verdict="clean"), evidence)
    assert report.verdict == expected, report.reason
    assert not evidence.errors
    assert evidence.staged_file_count == 1
    assert not any(
        change.is_repo_file and change.path.startswith(".git/") for change in evidence.file_diffs
    )
    assert not any("HOST_ONLY" in change.path for change in evidence.file_diffs)
    if expected == "ALLOW":
        assert not evidence.file_diffs
    assert (repo / ".git" / "HOST_ONLY").read_text() == "never copy"
    assert_no_leftovers(evidence)


def test_git_initialization_failure_stays_non_allow(repo, monkeypatch):
    from run.sandbox import detonate

    monkeypatch.setattr("run.sandbox.docker.DockerClient", lambda **kwargs: fake_client())

    def broken(self):
        raise SandboxError("trusted staged git initialization failed")

    monkeypatch.setattr(Sandbox, "prepare_repository", broken)
    evidence = detonate(repo)
    assert fuse(ReadOutcome(status=State.COMPLETE, verdict="clean"), evidence).verdict == "FLAG"
    assert any("git initialization failed" in error.message for error in evidence.errors)


@pytest.mark.parametrize(
    "result",
    [
        {"exit_code": 126},
        {"exit_code": 127},
        {"exit_code": None},
        {"exit_code": 0, "timed_out": True},
        {"exit_code": 0, "output_truncated": True},
    ],
)
def test_failed_git_helper_is_rejected(repo, monkeypatch, result):
    from run.evidence import CommandResult

    client = fake_client()
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["git"], **result),
    )
    with Sandbox(repo, client_factory=lambda: client) as sandbox:
        with pytest.raises(SandboxError, match="git initialization failed"):
            sandbox.prepare_repository()
        kwargs = client.containers.create.call_args.kwargs
        assert kwargs["network_mode"] == "none"
        assert kwargs["user"] == "65532:65532"
        assert kwargs["read_only"]
        assert kwargs["cap_drop"] == ["ALL"]
        assert kwargs["security_opt"] == ["no-new-privileges:true"]
        assert len(kwargs["mounts"]) == 1
        assert kwargs["mounts"][0]["Source"] == str(sandbox.staged_path)
