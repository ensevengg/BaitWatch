from pathlib import Path
from unittest.mock import MagicMock

import pytest

from run.evidence import State
from run.sandbox import Sandbox, SandboxConfig, SandboxError, detonate


def fake_client(gateway: str = ""):
    client = MagicMock()
    client.info.return_value = {"OSType": "linux"}
    client.networks.create.return_value.attrs = {
        "IPAM": {"Config": [{"Subnet": "10.13.37.0/24", "Gateway": gateway}]}
    }
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
