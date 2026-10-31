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


@pytest.mark.docker
@pytest.mark.parametrize("manager", ["pip", "npm"])
def test_offline_install_fails_before_tool_deadline(repo, engine, assert_no_leftovers, manager):
    from run.llm import ScriptedBackend, ToolCall
    from run.sandbox import detonate

    (repo / "pyproject.toml").write_text(
        '[build-system]\nrequires = ["setuptools>=77"]\n'
        'build-backend = "setuptools.build_meta"\n'
        '[project]\nname = "offline-fixture"\nversion = "0.0.1"\n'
    )
    (repo / "package.json").write_text(
        '{"name":"offline-fixture","version":"0.0.1","dependencies":{"is-number":"7.0.0"}}'
    )
    command = "pip install -e ." if manager == "pip" else "npm install"
    evidence = detonate(
        repo, backend=ScriptedBackend([[ToolCall("run_cmd", {"command": command})]])
    )
    result = evidence.tool_log[0]
    assert result.exit_code not in (None, 0, 126, 127)
    assert not result.timed_out
    assert result.duration_seconds < SandboxConfig().tool_timeout_seconds
    assert not evidence.errors
    report = fuse(ReadOutcome(status=State.COMPLETE, verdict="clean"), evidence)
    assert report.verdict == "ALLOW", report.reason
    assert evidence.tls_hits
    assert all(hit.hello_only is True for hit in evidence.tls_hits)
    assert_no_leftovers(evidence)


@pytest.mark.docker
def test_cage_environment_has_fast_fail_defaults(repo, engine, assert_no_leftovers):
    import json

    sandbox = Sandbox(repo)
    with sandbox:
        result = sandbox.run_command(
            ["python", "-c", "import json, os; print(json.dumps(dict(os.environ)))"]
        )
    assert result.exit_code == 0, result.stderr
    environment = json.loads(result.stdout)
    expected = {
        "PIP_RETRIES": "0",
        "PIP_TIMEOUT": "3",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INPUT": "1",
        "npm_config_fetch_retries": "0",
        "npm_config_fetch_timeout": "3000",
        "npm_config_fetch_retry_mintimeout": "100",
        "npm_config_fetch_retry_maxtimeout": "100",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_update_notifier": "false",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_HTTP_LOW_SPEED_LIMIT": "1",
        "GIT_HTTP_LOW_SPEED_TIME": "3",
    }
    assert {key: environment.get(key) for key in expected} == expected
    assert_no_leftovers(sandbox.evidence)
