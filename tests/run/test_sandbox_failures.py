import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from docker.errors import NotFound

from run.evidence import CommandResult, State
from run.sandbox import SCAN_LABEL, Sandbox, SandboxConfig, SandboxError, detonate


def fake_client(gateway: str = ""):
    client = MagicMock()
    client.info.return_value = {"OSType": "linux"}
    client.networks.create.return_value.attrs = {
        "IPAM": {"Config": [{"Subnet": "10.13.37.0/24", "Gateway": gateway}]}
    }
    client.containers.list.return_value = []
    client.networks.list.return_value = []
    return client


def test_network_with_a_host_gateway_fails_closed(repo: Path):
    client = fake_client(gateway="10.13.37.1")
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(SandboxError, match="host gateway"), sandbox:
        pytest.fail("a network the host can be reached through must not be used")
    assert sandbox.evidence.errors[0].code == "SANDBOX_SETUP"
    client.networks.create.return_value.remove.assert_called_once()
    assert not sandbox.staged_path.parent.exists()


def test_daemon_unavailable_becomes_error_evidence(repo: Path, monkeypatch):
    def unavailable(*args, **kwargs):
        raise RuntimeError("daemon unavailable")

    monkeypatch.setattr("run.sandbox.docker.DockerClient", unavailable)
    evidence = detonate(repo)
    assert evidence.status == "error"
    assert evidence.components.sandbox == State.ERROR
    assert evidence.errors[0].code == "SANDBOX_SETUP"


@pytest.mark.parametrize("host", ["tcp://example:2375", "ssh://example", "https://example"])
def test_remote_daemon_is_rejected(repo: Path, monkeypatch, host):
    monkeypatch.setenv("DOCKER_HOST", host)
    client = fake_client()
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(SandboxError, match="remote Docker"), sandbox:
        pytest.fail("remote daemon must not be used")
    client.ping.assert_not_called()
    assert sandbox.evidence.status == "error"


def test_network_setup_failure_removes_staging(repo: Path):
    client = fake_client()
    client.networks.create.side_effect = RuntimeError("subnet is occupied")
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(SandboxError, match="subnet"), sandbox:
        pytest.fail("cannot enter a sandbox without its network")
    assert not sandbox.staged_path.parent.exists()
    client.close.assert_called_once()
    assert sandbox.evidence.errors


def test_silent_exception_still_records_error_and_cleans_up(repo: Path):
    client = fake_client()
    client.networks.create.side_effect = TimeoutError()
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(SandboxError), sandbox:
        pytest.fail("a messageless exception must still fail the sandbox closed")
    assert sandbox.evidence.errors[0].code == "SANDBOX_SETUP"
    assert sandbox.evidence.errors[0].message
    assert not sandbox.staged_path.parent.exists()
    client.close.assert_called_once()


def test_keyboard_interrupt_during_setup_still_cleans_up(repo: Path):
    client = fake_client()
    client.networks.create.side_effect = KeyboardInterrupt()
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(KeyboardInterrupt), sandbox:
        pytest.fail("setup must not swallow interrupts")
    assert sandbox.evidence.status == "error"
    assert sandbox.evidence.errors[0].code == "SANDBOX_SETUP"
    assert not sandbox.staged_path.parent.exists()
    client.close.assert_called_once()


def test_exception_in_body_records_error_and_cleans_up(repo: Path):
    client = fake_client()
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(RuntimeError, match="unexpected"), sandbox:
        raise RuntimeError("unexpected test failure")
    assert sandbox.evidence.errors[0].code == "SANDBOX_ABORTED"
    assert not sandbox.staged_path.parent.exists()
    client.networks.create.return_value.remove.assert_called_once()


def test_cleanup_failure_is_observable_and_not_complete(repo: Path):
    client = fake_client()
    client.networks.create.return_value.remove.side_effect = RuntimeError("cleanup failed")
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        pass
    assert sandbox.evidence.status == "error"
    assert sandbox.evidence.errors[0].code == "NETWORK_CLEANUP"


def test_invalid_network_configuration_is_rejected():
    with pytest.raises(ValueError, match="distinct usable"):
        SandboxConfig(cage_ip="10.13.37.53")
    with pytest.raises(ValueError, match="positive"):
        SandboxConfig(max_output_bytes=0)


def test_attach_client_exit_code_mismatch_is_recorded(repo: Path, monkeypatch):
    client = fake_client()
    cage = client.containers.create.return_value
    cage.attrs = {"State": {"Status": "exited", "ExitCode": 0}}
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["true"], exit_code=1),
    )
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        result = sandbox.run_command(["true"])
    assert result.exit_code == 0
    assert sandbox.evidence.errors[0].code == "ATTACH_FAILED"
    assert sandbox.evidence.components.sandbox != State.COMPLETE


def test_network_the_daemon_kept_is_swept_by_label(repo: Path):
    client = fake_client()
    stray = MagicMock()
    stray.id = "net-stray"
    client.networks.create.side_effect = TimeoutError()
    client.networks.list.return_value = [stray]
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(SandboxError), sandbox:
        pytest.fail("a network the daemon kept must not outlive the sandbox")
    client.networks.list.assert_called_once_with(
        filters={"label": f"{SCAN_LABEL}={sandbox.evidence.scan_id}"}
    )
    stray.remove.assert_called_once()
    assert sandbox.evidence.status == "error"
    assert sandbox.evidence.errors[0].code == "SANDBOX_SETUP"
    assert not sandbox.staged_path.parent.exists()
    client.close.assert_called_once()


def test_keyboard_interrupt_during_network_create_still_sweeps(repo: Path):
    client = fake_client()
    stray = MagicMock()
    stray.id = "net-stray"
    interrupt = KeyboardInterrupt()
    client.networks.create.side_effect = interrupt
    client.networks.list.return_value = [stray]
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(KeyboardInterrupt) as excinfo, sandbox:
        pytest.fail("setup must not swallow interrupts")
    assert excinfo.value is interrupt
    stray.remove.assert_called_once()
    assert sandbox.evidence.status == "error"
    assert not sandbox.staged_path.parent.exists()
    client.close.assert_called_once()


def test_container_the_daemon_kept_is_swept_before_the_network(repo: Path):
    client = fake_client()
    stray = MagicMock()
    stray.id = "cage-stray"
    client.containers.create.side_effect = RuntimeError("create call lost")
    client.containers.list.return_value = [stray]
    order = []
    stray.remove.side_effect = lambda **kwargs: order.append(("container", kwargs))
    client.networks.create.return_value.remove.side_effect = lambda: order.append("network")
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.run_command(["true"])
    client.containers.list.assert_called_once_with(
        all=True,
        filters={"label": f"{SCAN_LABEL}={sandbox.evidence.scan_id}"},
        ignore_removed=True,
    )
    assert order == [("container", {"force": True, "v": True}), "network"]
    assert not sandbox.staged_path.parent.exists()
    client.close.assert_called_once()


def test_sweep_dedupes_against_tracked_resources(repo: Path, monkeypatch):
    client = fake_client()
    net = client.networks.create.return_value
    cage = client.containers.create.return_value
    cage.attrs = {"State": {"Status": "exited", "ExitCode": 0}}
    client.containers.list.return_value = [cage]
    client.networks.list.return_value = [net]
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["true"], exit_code=0),
    )
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        result = sandbox.run_command(["true"])
    assert result.exit_code == 0
    assert not sandbox.evidence.errors
    client.containers.list.assert_called_once_with(
        all=True,
        filters={"label": f"{SCAN_LABEL}={sandbox.evidence.scan_id}"},
        ignore_removed=True,
    )
    client.networks.list.assert_called_once_with(
        filters={"label": f"{SCAN_LABEL}={sandbox.evidence.scan_id}"}
    )
    assert cage.remove.call_count == 1
    assert net.remove.call_count == 1
    assert not sandbox.staged_path.parent.exists()


def test_sweep_ignores_resources_that_are_already_gone(repo: Path):
    client = fake_client()
    ghost_container = MagicMock()
    ghost_container.id = "cage-ghost"
    ghost_container.remove.side_effect = NotFound("already removed")
    ghost_network = MagicMock()
    ghost_network.id = "net-ghost"
    ghost_network.remove.side_effect = NotFound("already removed")
    client.networks.create.side_effect = TimeoutError()
    client.containers.list.return_value = [ghost_container]
    client.networks.list.return_value = [ghost_network]
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(SandboxError), sandbox:
        pytest.fail("setup must fail closed")
    ghost_container.remove.assert_called_once()
    ghost_network.remove.assert_called_once()
    assert not [error for error in sandbox.evidence.errors if error.code.endswith("_CLEANUP")]
    # A vanished container counts as removed, so the staging dir still goes.
    assert not sandbox.staged_path.parent.exists()


def test_container_sweep_failure_keeps_the_staging_dir(repo: Path, monkeypatch):
    client = fake_client()
    cage = client.containers.create.return_value
    cage.attrs = {"State": {"Status": "exited", "ExitCode": 0}}
    client.containers.list.side_effect = RuntimeError("label listing failed")
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["true"], exit_code=0),
    )
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.run_command(["true"])
    codes = [error.code for error in sandbox.evidence.errors]
    assert "CONTAINER_CLEANUP" in codes
    assert sandbox.evidence.status == "error"
    assert sandbox.evidence.components.sandbox != State.COMPLETE
    client.networks.create.return_value.remove.assert_called_once()
    assert sandbox.staged_path.parent.exists()
    shutil.rmtree(sandbox.staged_path.parent)
    client.close.assert_called_once()


def test_network_sweep_failure_still_removes_the_tracked_network(repo: Path):
    client = fake_client()
    client.networks.list.side_effect = RuntimeError("label listing failed")
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        pass
    assert sandbox.evidence.errors[0].code == "NETWORK_CLEANUP"
    client.networks.create.return_value.remove.assert_called_once()
    assert not sandbox.staged_path.parent.exists()
    client.close.assert_called_once()
