import ipaddress
import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from docker.errors import APIError, NotFound

from run.evidence import CommandResult, State
from run.sandbox import (
    SCAN_LABEL,
    SUBNET_ATTEMPTS,
    Sandbox,
    SandboxConfig,
    SandboxError,
    detonate,
)
from run.staging import StagingLimits

OVERLAP = "Pool overlaps with other one on this address space"


def fake_client(gateway: str = "", create_side_effect=None):
    client = MagicMock()
    client.info.return_value = {"OSType": "linux"}
    network = MagicMock()
    network.attrs = {"IPAM": {"Config": [{"Subnet": "10.13.37.0/24", "Gateway": gateway}]}}
    client.networks.create.return_value = network
    if create_side_effect is not None:
        client.networks.create.side_effect = create_side_effect
    client.containers.list.return_value = []
    client.networks.list.return_value = []
    return client


def requested_subnets(client) -> list[str]:
    return [
        str(call.kwargs["ipam"]["Config"][0]["Subnet"])
        for call in client.networks.create.call_args_list
    ]


def test_default_subnet_and_addresses_are_preserved_when_free(repo: Path):
    client = fake_client()
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(SandboxError):
        _ = sandbox.cage_ip
    with sandbox:
        assert client.networks.create.call_count == 1
        assert requested_subnets(client) == ["10.13.37.0/24"]
        assert sandbox.subnet == "10.13.37.0/24"
        assert sandbox.cage_ip == "10.13.37.20"
        assert sandbox.dns_ip == "10.13.37.53"
        assert sandbox.http_ip == "10.13.37.9"


def test_overlap_on_default_subnet_falls_back_to_a_free_one(repo: Path):
    network = MagicMock()
    network.attrs = {"IPAM": {"Config": [{"Subnet": "10.13.200.0/24", "Gateway": ""}]}}
    client = fake_client(create_side_effect=[APIError(OVERLAP), network])
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        requests = requested_subnets(client)
        assert requests[0] == "10.13.37.0/24"
        assert len(requests) == 2
        assert requests[1] != "10.13.37.0/24"
        assert ipaddress.IPv4Network(requests[1]).subnet_of(ipaddress.IPv4Network("10.13.0.0/16"))
        assert sandbox.subnet == requests[1]
        chosen = ipaddress.IPv4Network(sandbox.subnet)
        assert sandbox.cage_ip == str(chosen.network_address + 20)
        assert sandbox.dns_ip == str(chosen.network_address + 53)
        assert sandbox.http_ip == str(chosen.network_address + 9)
        assert ipaddress.IPv4Address(sandbox.cage_ip) in chosen.hosts()


def test_explicit_subnet_overlap_fails_closed_without_retry(repo: Path):
    client = fake_client(create_side_effect=APIError(OVERLAP))
    sandbox = Sandbox(repo, SandboxConfig(subnet="10.13.37.0/24"), client_factory=lambda: client)
    with pytest.raises(SandboxError, match="overlaps"), sandbox:
        pytest.fail("an explicitly configured overlap must fail closed")
    assert client.networks.create.call_count == 1
    assert sandbox.evidence.errors[0].code == "SANDBOX_SETUP"
    assert not sandbox.staged_path.parent.exists()
    client.close.assert_called_once()


def test_non_overlap_api_error_is_not_retried(repo: Path):
    client = fake_client(create_side_effect=APIError("physics broke, please reboot the daemon"))
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(SandboxError, match="reboot"), sandbox:
        pytest.fail("only overlap errors may fall back to another subnet")
    assert client.networks.create.call_count == 1
    assert not sandbox.staged_path.parent.exists()


def test_all_fallback_subnets_overlapping_fails_closed(repo: Path):
    client = fake_client(create_side_effect=APIError(OVERLAP))
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(SandboxError, match="candidate subnets"), sandbox:
        pytest.fail("exhausted subnet fallbacks must fail closed")
    requests = requested_subnets(client)
    assert len(requests) == SUBNET_ATTEMPTS
    assert len(set(requests)) == SUBNET_ATTEMPTS
    assert requests[0] == "10.13.37.0/24"
    assert sandbox.evidence.errors[0].code == "SANDBOX_SETUP"
    assert not sandbox.staged_path.parent.exists()
    client.close.assert_called_once()


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
    with pytest.raises(ValueError, match="distinct"):
        SandboxConfig(dns_host=53, http_host=53)
    with pytest.raises(ValueError, match="2..254"):
        SandboxConfig(cage_host=1)
    with pytest.raises(ValueError, match="2..254"):
        SandboxConfig(http_host=255)
    with pytest.raises(ValueError, match="/24"):
        SandboxConfig(subnet="10.13.0.0/16")
    with pytest.raises(ValueError, match="/24"):
        SandboxConfig(subnet="10.13.37.7/24")
    with pytest.raises(ValueError, match="/24"):
        SandboxConfig(subnet="not-a-network")
    with pytest.raises(ValueError, match="positive"):
        SandboxConfig(max_output_bytes=0)


def test_non_integer_host_offsets_are_rejected():
    with pytest.raises(ValueError, match="distinct integers"):
        SandboxConfig(cage_host=20.5)
    with pytest.raises(ValueError, match="distinct integers"):
        SandboxConfig(dns_host=53.0)
    with pytest.raises(ValueError, match="distinct integers"):
        SandboxConfig(http_host=True)
    with pytest.raises(ValueError, match="distinct integers"):
        SandboxConfig(cage_host="20")


def test_non_integer_resource_limits_are_rejected():
    with pytest.raises(ValueError, match="integers"):
        SandboxConfig(memory_bytes=256.0 * 1024 * 1024)
    with pytest.raises(ValueError, match="integers"):
        SandboxConfig(nano_cpus=True)
    with pytest.raises(ValueError, match="integers"):
        SandboxConfig(pids_limit=64.0)
    with pytest.raises(ValueError, match="integers"):
        SandboxConfig(tmpfs_bytes="32m")
    with pytest.raises(ValueError, match="integers"):
        SandboxConfig(max_output_bytes=True)


def test_timeout_seconds_accepts_float_but_not_bool_or_string():
    assert SandboxConfig(timeout_seconds=0.5).timeout_seconds == 0.5
    with pytest.raises(ValueError, match="int or float"):
        SandboxConfig(timeout_seconds=True)
    with pytest.raises(ValueError, match="int or float"):
        SandboxConfig(timeout_seconds="20")


def test_staging_limits_reject_non_integer_counts():
    with pytest.raises(ValueError, match="integers"):
        StagingLimits(max_entries=10_000.0)
    with pytest.raises(ValueError, match="integers"):
        StagingLimits(max_bytes=True)
    with pytest.raises(ValueError, match="integers"):
        StagingLimits(max_file_bytes=float("inf"))
    with pytest.raises(ValueError, match="integers"):
        StagingLimits(max_depth="64")
    with pytest.raises(ValueError, match="int or float"):
        StagingLimits(timeout_seconds=True)
    assert StagingLimits(timeout_seconds=0.5).timeout_seconds == 0.5


def test_non_finite_timeout_seconds_are_rejected():
    for timeout in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError, match="finite int or float"):
            SandboxConfig(timeout_seconds=timeout)
        with pytest.raises(ValueError, match="finite int or float"):
            StagingLimits(timeout_seconds=timeout)


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


def test_malformed_config_values_raise_value_error():
    with pytest.raises(ValueError, match="distinct integers"):
        SandboxConfig(cage_host=[20])
    with pytest.raises(ValueError, match="finite"):
        SandboxConfig(timeout_seconds=10**400)
    with pytest.raises(ValueError, match="finite"):
        StagingLimits(timeout_seconds=10**400)


def test_sink_that_never_becomes_ready_fails_closed(repo: Path):
    client = fake_client()
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}
    sandbox = Sandbox(repo, SandboxConfig(sink_ready_seconds=0.05), client_factory=lambda: client)
    with sandbox:
        sandbox.start_sinks()
    assert [error.code for error in sandbox.evidence.errors] == ["SERVICE_START", "SERVICE_START"]
    assert "never wrote its ready record" in sandbox.evidence.errors[0].message
    components = sandbox.evidence.components
    assert components.dns_sink == State.ERROR
    assert components.http_sink == State.ERROR
    assert components.tls_sink == State.ERROR
    assert sandbox.evidence.status == "error"
    assert not sandbox.staged_path.parent.exists()


def test_sink_container_that_exits_fails_closed(repo: Path):
    client = fake_client()
    client.containers.create.return_value.attrs = {"State": {"Status": "exited", "ExitCode": 1}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.start_sinks()
    assert [error.code for error in sandbox.evidence.errors] == ["SERVICE_START", "SERVICE_START"]
    assert "exited during startup" in sandbox.evidence.errors[0].message
    assert sandbox.evidence.components.dns_sink == State.ERROR
    assert sandbox.evidence.components.tls_sink == State.ERROR


def test_dirty_sink_logs_fail_closed_at_collection(repo: Path, monkeypatch):
    monkeypatch.setattr(Sandbox, "_wait_ready", lambda self, container, log, role: None)
    client = fake_client()
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.start_sinks()
        sandbox._sink_logs["dns"].write_text(
            '{"kind":"ready","sink":"dns"}\nnot-json\n', encoding="utf-8"
        )
        sandbox._sink_logs["http"].write_text(
            '{"kind":"ready","sink":"http"}\n{"kind":"log_truncated","ts":1.0}\n',
            encoding="utf-8",
        )
        sandbox.collect_sinks()
    assert [error.code for error in sandbox.evidence.errors] == ["SINK_LOG", "SINK_LOG"]
    components = sandbox.evidence.components
    assert components.dns_sink == State.ERROR
    assert components.http_sink == State.ERROR
    assert components.tls_sink == State.ERROR
    assert not sandbox.evidence.dns_hits and not sandbox.evidence.http_hits
    assert sandbox.evidence.status == "error"


def test_sink_that_died_before_collection_fails_closed(repo: Path, monkeypatch):
    monkeypatch.setattr(Sandbox, "_wait_ready", lambda self, container, log, role: None)
    client = fake_client()
    client.containers.create.return_value.attrs = {"State": {"Status": "exited", "ExitCode": 137}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.start_sinks()
        sandbox._sink_logs["dns"].write_text('{"kind":"ready","sink":"dns"}\n', encoding="utf-8")
        sandbox._sink_logs["http"].write_text('{"kind":"ready","sink":"http"}\n', encoding="utf-8")
        sandbox.collect_sinks()
    assert [error.code for error in sandbox.evidence.errors] == ["SINK_FAILED", "SINK_FAILED"]
    assert "not running" in sandbox.evidence.errors[0].message
    assert sandbox.evidence.components.tls_sink == State.ERROR
    assert not sandbox.evidence.tls_hits
