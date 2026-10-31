import ipaddress
import shutil
import socket
import struct
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from docker.errors import APIError, NotFound

from run.evidence import CommandResult, State
from run.sandbox import (
    EXEC_START_MARKER,
    KILL_LINGERING,
    SCAN_LABEL,
    SUBNET_ATTEMPTS,
    Sandbox,
    SandboxConfig,
    SandboxError,
    detonate,
)
from run.staging import StagingLimits
from run.trace import Entry

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


def stoppable_client(exit_code: int = 0, stops: bool = True):
    client = fake_client()
    containers = []
    for _ in range(2):
        container = MagicMock()
        state = {"Status": "running", "ExitCode": None}

        def kill(signal=None, state=state):
            if stops:
                state.update({"Status": "exited", "ExitCode": exit_code})

        container.attrs = {"State": state}
        container.kill.side_effect = kill
        container.reload.side_effect = lambda: None
        containers.append(container)
    client.containers.create.side_effect = containers
    return client


def exec_api(client, *, exit_code=0, running=False, inspect_failure=None):
    client.api.exec_create.return_value = {"Id": "exec-1"}
    if inspect_failure is not None:
        client.api.exec_inspect.side_effect = inspect_failure
    else:
        client.api.exec_inspect.return_value = {"Running": running, "ExitCode": exit_code}
    return client.api


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
    client = stoppable_client()
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.start_sinks()
        sandbox._sink_logs["dns"].write_text(
            '{"kind":"ready","sink":"dns"}\nnot-json\n{"kind":"stopped","sink":"dns"}\n',
            encoding="utf-8",
        )
        sandbox._sink_logs["http"].write_text(
            '{"kind":"ready","sink":"http"}\n'
            '{"kind":"log_truncated","ts":1.0}\n{"kind":"stopped","sink":"http"}\n',
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


def test_sink_without_a_stopped_record_fails_closed(repo: Path, monkeypatch):
    monkeypatch.setattr(Sandbox, "_wait_ready", lambda self, container, log, role: None)
    client = stoppable_client()
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.start_sinks()
        sandbox._sink_logs["dns"].write_text(
            '{"kind":"ready","sink":"dns"}\n'
            '{"kind":"dns","ts":1.0,"source_ip":"10.13.37.20","qname":"a.evil.example",'
            '"qtype":"A","decoded":[]}\n',
            encoding="utf-8",
        )
        sandbox._sink_logs["http"].write_text('{"kind":"ready","sink":"http"}\n', encoding="utf-8")
        sandbox.collect_sinks()
    assert [error.code for error in sandbox.evidence.errors] == ["SINK_LOG", "SINK_LOG"]
    assert "no stopped record" in sandbox.evidence.errors[0].message
    # The parsed hit stays evidence even though the component failed.
    assert [hit.destination for hit in sandbox.evidence.dns_hits] == ["a.evil.example"]
    assert sandbox.evidence.components.dns_sink == State.ERROR


def test_sink_exiting_nonzero_on_stop_fails_closed(repo: Path, monkeypatch):
    monkeypatch.setattr(Sandbox, "_wait_ready", lambda self, container, log, role: None)
    client = stoppable_client(exit_code=1)
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.start_sinks()
        for role, sink in (("dns", "dns"), ("http", "http")):
            sandbox._sink_logs[role].write_text(
                f'{{"kind":"ready","sink":"{sink}"}}\n{{"kind":"stopped","sink":"{sink}"}}\n',
                encoding="utf-8",
            )
        sandbox.collect_sinks()
    assert [error.code for error in sandbox.evidence.errors] == ["SINK_FAILED", "SINK_FAILED"]
    assert "exited with code 1" in sandbox.evidence.errors[0].message
    assert sandbox.evidence.components.http_sink == State.ERROR


def test_sink_that_does_not_stop_fails_closed(repo: Path, monkeypatch):
    monkeypatch.setattr(Sandbox, "_wait_ready", lambda self, container, log, role: None)
    monkeypatch.setattr("run.sandbox.SINK_STOP_SECONDS", 0.05)
    client = stoppable_client(stops=False)
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.start_sinks()
        sandbox.collect_sinks()
    assert [error.code for error in sandbox.evidence.errors] == ["SINK_FAILED", "SINK_FAILED"]
    assert "did not stop" in sandbox.evidence.errors[0].message
    assert sandbox.evidence.components.tls_sink == State.ERROR


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


def test_dead_sink_with_a_partial_log_keeps_its_hits(repo: Path, monkeypatch):
    monkeypatch.setattr(Sandbox, "_wait_ready", lambda self, container, log, role: None)
    client = fake_client()
    client.containers.create.return_value.attrs = {"State": {"Status": "exited", "ExitCode": 137}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.start_sinks()
        sandbox._sink_logs["dns"].write_text(
            '{"kind":"ready","sink":"dns"}\n'
            '{"kind":"dns","ts":1.0,"source_ip":"10.13.37.20","qname":"dead.evil.example",'
            '"qtype":"A","decoded":[]}\n',
            encoding="utf-8",
        )
        sandbox._sink_logs["http"].write_text('{"kind":"ready","sink":"http"}\n', encoding="utf-8")
        sandbox.collect_sinks()
    assert [hit.destination for hit in sandbox.evidence.dns_hits] == ["dead.evil.example"]
    assert sandbox.evidence.errors[0].code == "SINK_FAILED"
    assert sandbox.evidence.components.dns_sink == State.ERROR


def test_log_cap_flood_keeps_the_exfil_hit_and_marks_the_log(repo: Path, monkeypatch):
    monkeypatch.setattr(Sandbox, "_wait_ready", lambda self, container, log, role: None)
    client = stoppable_client()
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.start_sinks()
        sandbox._sink_logs["dns"].write_text(
            '{"kind":"ready","sink":"dns"}\n'
            '{"kind":"dns","ts":1.0,"source_ip":"10.13.37.20","qname":"exfil.evil.example",'
            '"qtype":"A","decoded":[]}\n'
            '{"kind":"log_truncated","ts":2.0}\n',
            encoding="utf-8",
        )
        sandbox._sink_logs["http"].write_text(
            '{"kind":"ready","sink":"http"}\n{"kind":"stopped","sink":"http"}\n',
            encoding="utf-8",
        )
        sandbox.collect_sinks()
    assert [hit.destination for hit in sandbox.evidence.dns_hits] == ["exfil.evil.example"]
    assert sandbox.evidence.errors[0].code == "SINK_LOG"
    assert "size cap" in sandbox.evidence.errors[0].message
    assert sandbox.evidence.components.dns_sink == State.ERROR
    assert sandbox.evidence.components.http_sink == State.COMPLETE


def test_collecting_twice_does_not_duplicate_hits(repo: Path, monkeypatch):
    monkeypatch.setattr(Sandbox, "_wait_ready", lambda self, container, log, role: None)
    client = stoppable_client()
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.start_sinks()
        sandbox._sink_logs["dns"].write_text(
            '{"kind":"ready","sink":"dns"}\n'
            '{"kind":"dns","ts":1.0,"source_ip":"10.13.37.20","qname":"once.evil.example",'
            '"qtype":"A","decoded":[]}\n'
            '{"kind":"stopped","sink":"dns"}\n',
            encoding="utf-8",
        )
        sandbox._sink_logs["http"].write_text(
            '{"kind":"ready","sink":"http"}\n{"kind":"stopped","sink":"http"}\n',
            encoding="utf-8",
        )
        sandbox.collect_sinks()
        sandbox.collect_sinks()
    assert [hit.destination for hit in sandbox.evidence.dns_hits] == ["once.evil.example"]
    assert not sandbox.evidence.errors
    assert sandbox.evidence.components.dns_sink == State.COMPLETE


def test_pre_command_trace_error_does_not_block_the_sandbox_state(repo: Path, monkeypatch):
    client = fake_client()
    cage = client.containers.create.return_value
    cage.attrs = {"State": {"Status": "exited", "ExitCode": 0}}
    results = [
        CommandResult(command=["snapshot"], exit_code=1),
        CommandResult(command=["true"], exit_code=0),
    ]
    monkeypatch.setattr("run.sandbox.capture_attached", lambda *args, **kwargs: results.pop(0))
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        assert not sandbox.trace_before()
        result = sandbox.run_command(["true"])
    assert result.exit_code == 0
    assert [error.code for error in sandbox.evidence.errors] == ["TRACE_FAILED"]
    assert sandbox.evidence.components.trace == State.ERROR
    assert sandbox.evidence.components.sandbox == State.COMPLETE


def test_trace_after_keeps_diffs_but_errors_on_after_snapshot_markers(repo: Path, monkeypatch):
    before = {"README.md": Entry(kind="file", mode=0o644, sha256="0" * 64)}
    after = {
        "README.md": Entry(kind="file", mode=0o644, sha256="1" * 64),
        "locked": Entry(kind="dir", mode=0, error="EACCES"),
    }
    manifests = iter([before, after])
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(repo, client_factory=lambda: fake_client())
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    assert [(item.path, item.change) for item in sandbox.evidence.file_diffs] == [
        ("README.md", "modified"),
        ("locked", "added"),
    ]
    assert [error.code for error in sandbox.evidence.errors] == ["TRACE_INCOMPLETE"]
    assert "locked" in sandbox.evidence.errors[0].message
    assert sandbox.evidence.components.trace == State.ERROR


def test_trace_after_errors_on_before_snapshot_markers(repo: Path, monkeypatch):
    before = {
        "README.md": Entry(kind="file", mode=0o644, sha256="0" * 64),
        "secret": Entry(kind="file", mode=0o600, error="EACCES"),
    }
    manifests = iter([before, dict(before)])
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(repo, client_factory=lambda: fake_client())
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    assert sandbox.evidence.file_diffs == []
    assert [error.code for error in sandbox.evidence.errors] == ["TRACE_INCOMPLETE"]
    assert "secret" in sandbox.evidence.errors[0].message
    assert sandbox.evidence.components.trace == State.ERROR


def test_trace_incomplete_names_a_bounded_set_of_paths(repo: Path, monkeypatch):
    after = {f"locked{i}": Entry(kind="dir", mode=0, error="EACCES") for i in range(9)}
    manifests = iter([{}, after])
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(repo, client_factory=lambda: fake_client())
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    message = sandbox.evidence.errors[0].message
    assert message.count("locked") == 5
    assert "(+4 more)" in message
    assert len(message) <= 1000


def _planted_manifest() -> dict:
    return {
        ".env": Entry(kind="file", mode=0o666, size=64, sha256="1" * 64),
        ".env.local": Entry(kind="file", mode=0o666, size=64, sha256="2" * 64),
        "config": Entry(kind="dir", mode=0o777),
        "config/credentials": Entry(kind="file", mode=0o666, size=64, sha256="3" * 64),
    }


def test_trace_after_does_not_charge_planted_files_to_the_write_limit(repo: Path, monkeypatch):
    manifests = iter([_planted_manifest(), _planted_manifest()])
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(
        repo,
        SandboxConfig(staging=StagingLimits(max_entries=1)),
        client_factory=lambda: fake_client(),
    )
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    assert not sandbox.evidence.errors
    assert sandbox.evidence.components.trace == State.COMPLETE


def test_trace_after_charges_planted_files_the_cage_rewrote(repo: Path, monkeypatch):
    before = _planted_manifest()
    after = dict(before)
    after[".env"] = Entry(kind="file", mode=0o666, size=4096, sha256="5" * 64)
    manifests = iter([before, after])
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(
        repo,
        SandboxConfig(staging=StagingLimits(max_bytes=1024)),
        client_factory=lambda: fake_client(),
    )
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    assert any(error.code == "REPO_WRITE_LIMIT" for error in sandbox.evidence.errors)


def test_trace_after_still_charges_cage_entries_past_the_write_limit(repo: Path, monkeypatch):
    before = _planted_manifest()
    before["README.md"] = Entry(kind="file", mode=0o644, size=64, sha256="0" * 64)
    after = dict(before)
    after["flood"] = Entry(kind="file", mode=0o666, size=64, sha256="4" * 64)
    manifests = iter([before, after])
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(
        repo,
        SandboxConfig(staging=StagingLimits(max_entries=1)),
        client_factory=lambda: fake_client(),
    )
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    assert any(error.code == "REPO_WRITE_LIMIT" for error in sandbox.evidence.errors)


def test_trace_after_is_complete_when_no_marker_exists(repo: Path, monkeypatch):
    after = {
        "README.md": Entry(kind="file", mode=0o644, sha256="0" * 64),
        "other": Entry(kind="symlink", mode=0o777, target="README.md"),
    }
    manifests = iter([{}, after])
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(repo, client_factory=lambda: fake_client())
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    assert not sandbox.evidence.errors
    assert sandbox.evidence.components.trace == State.COMPLETE


def test_staging_leak_stays_visible_when_the_unlock_helper_survives(
    repo: Path, monkeypatch, request
):
    client = fake_client()
    cage = MagicMock()
    cage.id = "cage"
    cage.attrs = {"State": {"Status": "exited", "ExitCode": 0}}
    helper = MagicMock()
    helper.id = "unlock-helper"
    helper.wait.return_value = {"StatusCode": 0}
    helper.remove.side_effect = RuntimeError("helper removal failed")
    client.containers.create.side_effect = [cage, helper]
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["true"], exit_code=0),
    )
    real_rmtree = shutil.rmtree
    rmtree = MagicMock(side_effect=[OSError("locked"), None])
    monkeypatch.setattr("run.sandbox.shutil.rmtree", rmtree)
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        request.addfinalizer(lambda: real_rmtree(sandbox.staged_path.parent))
        assert sandbox.run_command(["true"]).exit_code == 0
    assert [error.code for error in sandbox.evidence.errors] == [
        "CONTAINER_CLEANUP",
        "STAGING_CLEANUP",
    ]
    assert "not removed" in sandbox.evidence.errors[1].message
    assert rmtree.call_count == 1  # no retry while the helper may still hold the tree


def test_unlock_helper_with_a_lost_create_reply_is_swept_after_staging(
    repo: Path, monkeypatch, request
):
    client = fake_client()
    cage = MagicMock()
    cage.id = "cage"
    cage.attrs = {"State": {"Status": "exited", "ExitCode": 0}}
    stray = MagicMock()
    stray.id = "unlock-helper-stray"
    client.containers.create.side_effect = [cage, TimeoutError("create reply lost")]
    client.containers.list.side_effect = [[], [stray]]
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["true"], exit_code=0),
    )
    real_rmtree = shutil.rmtree
    rmtree = MagicMock(side_effect=OSError("locked"))
    monkeypatch.setattr("run.sandbox.shutil.rmtree", rmtree)
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        request.addfinalizer(lambda: real_rmtree(sandbox.staged_path.parent))
        assert sandbox.run_command(["true"]).exit_code == 0
    assert [error.code for error in sandbox.evidence.errors] == ["STAGING_CLEANUP"]
    assert rmtree.call_count == 1
    stray.remove.assert_called_once()
    assert client.containers.list.call_count == 2


def test_cleanup_unlock_gets_a_floor_timeout_and_a_covering_host_wait(repo: Path):
    client = fake_client()
    helper = MagicMock()
    helper.id = "unlock-helper"
    helper.wait.return_value = {"StatusCode": 0}
    client.containers.create.side_effect = [helper]
    sandbox = Sandbox(
        repo,
        SandboxConfig(staging=StagingLimits(timeout_seconds=0.25)),
        client_factory=lambda: client,
    )
    with sandbox:
        assert sandbox._trace_limits()["timeout_seconds"] == 0.25
        cleanup = sandbox._trace_limits(cleanup=True)
        assert sandbox._unlock_staging() == (True, True)
    assert cleanup["timeout_seconds"] >= 60
    limits = client.containers.create.call_args.kwargs["command"][-1]
    assert '"timeout_seconds": 60' in limits or '"timeout_seconds": 60.0' in limits
    assert helper.wait.call_args.kwargs["timeout"] >= 2 * cleanup["timeout_seconds"]


def test_decoy_time_limits_are_validated():
    assert SandboxConfig(decoy_seconds=0.5, tool_timeout_seconds=2).decoy_seconds == 0.5
    with pytest.raises(ValueError, match="finite int or float"):
        SandboxConfig(decoy_seconds=True)
    with pytest.raises(ValueError, match="finite int or float"):
        SandboxConfig(decoy_seconds="90")
    with pytest.raises(ValueError, match="finite int or float"):
        SandboxConfig(tool_timeout_seconds="10")
    with pytest.raises(ValueError, match="positive"):
        SandboxConfig(decoy_seconds=0)
    with pytest.raises(ValueError, match="positive"):
        SandboxConfig(tool_timeout_seconds=-1)


def test_cage_that_exits_at_startup_fails_closed(repo: Path):
    client = fake_client()
    client.containers.create.return_value.attrs = {"State": {"Status": "exited", "ExitCode": 1}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with pytest.raises(SandboxError, match="exited during startup"), sandbox:
        sandbox.open_cage()
    assert sandbox.evidence.errors[0].code == "CAGE_START"
    assert sandbox.evidence.components.sandbox == State.ERROR
    assert not sandbox.staged_path.parent.exists()


def test_open_cage_and_run_command_are_mutually_exclusive(repo: Path, monkeypatch):
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["true"], exit_code=0),
    )
    client = fake_client()
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.open_cage()
        with pytest.raises(SandboxError, match="one command per sandbox"):
            sandbox.run_command(["true"])
    other = Sandbox(repo, client_factory=lambda: client)
    with other:
        other.run_command(["true"])
        with pytest.raises(SandboxError, match="one cage per sandbox"):
            other.open_cage()


def test_exec_requires_an_open_cage(repo: Path):
    client = fake_client()
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox, pytest.raises(SandboxError, match="open_cage"):
        sandbox.exec(["true"])
    assert sandbox.evidence.errors[0].code == "EXEC_ERROR"
    assert sandbox.evidence.components.sandbox == State.ERROR
    assert sandbox.evidence.status == "error"


def test_exec_on_a_closed_cage_fails_closed(repo: Path, monkeypatch):
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["true"], exit_code=0),
    )
    client = fake_client()
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.open_cage()
    with pytest.raises(SandboxError, match="open_cage"):
        sandbox.exec(["true"])


def test_exec_is_rejected_after_the_sinks_are_collected(repo: Path, monkeypatch):
    # Collection ends the evidence; output after it would skip the
    # honeytoken search, so exec must refuse instead.
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["true"], exit_code=0),
    )
    client = fake_client()
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.open_cage()
        sandbox.collect_sinks()
        with pytest.raises(SandboxError, match="after the sinks"):
            sandbox.exec(["true"])
    assert any(error.code == "EXEC_ERROR" for error in sandbox.evidence.errors)
    assert sandbox.evidence.status == "error"


def test_run_command_is_rejected_after_the_sinks_are_collected(repo: Path, monkeypatch):
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["true"], exit_code=0),
    )
    client = fake_client()
    client.containers.create.return_value.attrs = {"State": {"Status": "exited", "ExitCode": 0}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.collect_sinks()
        with pytest.raises(SandboxError, match="after the sinks"):
            sandbox.run_command(["true"])
    assert sandbox.evidence.tool_log == []
    assert any(error.code == "COMMAND_ERROR" for error in sandbox.evidence.errors)
    assert sandbox.evidence.status == "error"


def test_exec_is_rejected_after_run_command(repo: Path, monkeypatch):
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["true"], exit_code=0),
    )
    client = fake_client()
    client.containers.create.return_value.attrs = {"State": {"Status": "exited", "ExitCode": 0}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.run_command(["true"])
        with pytest.raises(SandboxError, match="not running"):
            sandbox.exec(["true"])


def test_exec_rejects_shell_strings_and_nul(repo: Path):
    client = fake_client()
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.open_cage()
        with pytest.raises(ValueError, match="never a shell string"):
            sandbox.exec("echo hi")
        with pytest.raises(ValueError, match="never a shell string"):
            sandbox.exec(["true", "a\0b"])
        with pytest.raises(ValueError, match="never a shell string"):
            sandbox.exec([])


def test_exec_timeout_kills_lingering_cage_processes(repo: Path, monkeypatch):
    sweep_calls: list[list[str]] = []
    monkeypatch.setattr(
        "run.sandbox.capture_exec",
        lambda api, exec_id, command, **kwargs: (
            CommandResult(command=list(command), stderr=f"{EXEC_START_MARKER}\n"),
            None,
        ),
    )
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda attach_command, container_command, **kwargs: (
            sweep_calls.append(list(attach_command)),
            CommandResult(command=list(container_command), exit_code=0),
        )[1],
    )
    client = fake_client()
    exec_api(client, exit_code=137)
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.open_cage()
        result = sandbox.exec(["sh", "-c", "sleep 100; echo done"])
    assert result.timed_out
    assert result.exit_code == 137
    assert result.command == ["sh", "-c", "sleep 100; echo done"]
    assert result.stderr == ""
    wrapped = client.api.exec_create.call_args.args[1]
    assert wrapped[-4:] == ["baitwatch-exec", "sh", "-c", "sleep 100; echo done"]
    assert "timeout -s KILL" in wrapped[2]
    options = client.api.exec_create.call_args.kwargs
    assert options["user"] == "65532:65532" and options["workdir"] == "/repo"
    assert options["privileged"] is False and options["stdin"] is False
    assert len(sweep_calls) == 1
    assert "/proc/[0-9]*" in sweep_calls[0][-1]
    assert 'cat "$entry/stat"' in sweep_calls[0][-1]
    assert [error.code for error in sandbox.evidence.errors] == ["EXEC_TIMEOUT"]
    assert sandbox.evidence.components.sandbox == State.ERROR
    assert sandbox.evidence.status == "error"


def test_exec_kills_backgrounded_processes_after_a_clean_exit(repo: Path, monkeypatch):
    sweep_calls: list[list[str]] = []
    monkeypatch.setattr(
        "run.sandbox.capture_exec",
        lambda api, exec_id, command, **kwargs: (
            CommandResult(command=list(command), stdout="started\n", stderr=EXEC_START_MARKER),
            None,
        ),
    )
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda attach_command, container_command, **kwargs: (
            sweep_calls.append(list(attach_command)),
            CommandResult(command=list(container_command), exit_code=0),
        )[1],
    )
    client = fake_client()
    exec_api(client, exit_code=0)
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.open_cage()
        result = sandbox.exec(["sh", "-c", "sleep 100 & echo started"])
    assert not result.timed_out
    assert result.exit_code == 0
    assert result.stderr == ""
    assert len(sweep_calls) == 1
    assert "/proc/[0-9]*" in sweep_calls[0][-1]
    assert not sandbox.evidence.errors


def _exec_with_results(
    repo: Path,
    monkeypatch,
    capture: tuple,
    *,
    exit_code: int | None = 0,
    running: bool = False,
    inspect_failure=None,
):
    monkeypatch.setattr("run.sandbox.capture_exec", lambda *args, **kwargs: capture)
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["sh"], exit_code=0),
    )
    client = fake_client()
    exec_api(client, exit_code=exit_code, running=running, inspect_failure=inspect_failure)
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.open_cage()
        result = sandbox.exec(["sh", "-c", "echo hi"])
    return sandbox, result


def test_exec_output_truncation_fails_closed(repo: Path, monkeypatch):
    sandbox, result = _exec_with_results(
        repo,
        monkeypatch,
        (
            CommandResult(
                command=["sh"],
                stdout="flood",
                stderr=f"{EXEC_START_MARKER}\n",
                output_truncated=True,
            ),
            None,
        ),
    )
    assert result.output_truncated
    assert [error.code for error in sandbox.evidence.errors] == ["EXEC_OUTPUT_TRUNCATED"]
    assert sandbox.evidence.components.sandbox == State.ERROR
    assert sandbox.evidence.status == "error"
    sandbox._client.api.exec_inspect.assert_not_called()


def test_exec_stream_break_after_the_marker_is_a_transport_failure(repo: Path, monkeypatch):
    sandbox, result = _exec_with_results(
        repo,
        monkeypatch,
        (
            CommandResult(command=["sh"], stdout="partial", stderr=f"{EXEC_START_MARKER}\n"),
            RuntimeError("connection reset"),
        ),
        exit_code=0,
    )
    assert result.exit_code == 0  # docker's record survives the broken client
    assert result.stdout == "partial"
    assert [error.code for error in sandbox.evidence.errors] == ["EXEC_TRANSPORT_FAILED"]
    assert sandbox.evidence.components.sandbox == State.ERROR
    assert sandbox.evidence.status == "error"


def test_exec_frame_cut_mid_payload_with_a_clean_record_is_a_transport_failure(
    repo: Path,
    monkeypatch,
):
    """The transport probe: a clean exec record must not pass for a delivered stream."""
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["sh"], exit_code=0),
    )
    client = fake_client()
    exec_api(client, exit_code=0)
    peer, end = socket.socketpair()
    marker = f"{EXEC_START_MARKER}\n".encode()
    peer.sendall(struct.pack(">BxxxL", 2, len(marker)) + marker)
    peer.sendall(struct.pack(">BxxxL", 1, 12) + b"abc")  # declares 12 bytes, delivers 3
    peer.close()
    monkeypatch.setattr("run.capture._start_exec", lambda *args: end)
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.open_cage()
        result = sandbox.exec(["sh", "-c", "echo hi"])
    assert end.fileno() == -1
    assert result.stdout == "abc"
    assert result.exit_code == 0
    assert [error.code for error in sandbox.evidence.errors] == ["EXEC_TRANSPORT_FAILED"]
    assert sandbox.evidence.components.sandbox == State.ERROR
    assert sandbox.evidence.status == "error"


def test_exec_inspect_failure_is_a_transport_failure(repo: Path, monkeypatch):
    sandbox, _ = _exec_with_results(
        repo,
        monkeypatch,
        (CommandResult(command=["sh"], stderr=f"{EXEC_START_MARKER}\n"), None),
        inspect_failure=APIError("exec record gone"),
    )
    assert [error.code for error in sandbox.evidence.errors] == ["EXEC_TRANSPORT_FAILED"]
    assert sandbox.evidence.components.sandbox == State.ERROR


def test_exec_still_running_after_the_stream_ends_is_a_transport_failure(repo: Path, monkeypatch):
    sandbox, _ = _exec_with_results(
        repo,
        monkeypatch,
        (CommandResult(command=["sh"], stderr=f"{EXEC_START_MARKER}\n"), None),
        running=True,
        exit_code=None,
    )
    assert [error.code for error in sandbox.evidence.errors] == ["EXEC_TRANSPORT_FAILED"]


def test_exec_record_without_an_exit_code_is_a_transport_failure(repo: Path, monkeypatch):
    sandbox, result = _exec_with_results(
        repo,
        monkeypatch,
        (CommandResult(command=["sh"], stderr=f"{EXEC_START_MARKER}\n"), None),
        exit_code=None,
    )
    assert result.exit_code is None
    assert [error.code for error in sandbox.evidence.errors] == ["EXEC_TRANSPORT_FAILED"]


def test_exec_without_the_start_marker_is_a_transport_failure(repo: Path, monkeypatch):
    sandbox, _ = _exec_with_results(repo, monkeypatch, (CommandResult(command=["sh"]), None))
    assert [error.code for error in sandbox.evidence.errors] == ["EXEC_TRANSPORT_FAILED"]
    assert "did not reach the cage" in sandbox.evidence.errors[0].message


def test_exec_create_failure_fails_closed(repo: Path):
    client = fake_client()
    client.api.exec_create.side_effect = APIError("daemon refused the exec")
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.open_cage()
        with pytest.raises(SandboxError, match="daemon refused"):
            sandbox.exec(["true"])
    assert sandbox.evidence.errors[0].code == "EXEC_ERROR"
    assert sandbox.evidence.components.sandbox == State.ERROR


@pytest.mark.parametrize("exit_code", [1, 125, 126, 127])
def test_exec_tool_exit_codes_are_not_transport_failures(repo: Path, monkeypatch, exit_code):
    sandbox, result = _exec_with_results(
        repo,
        monkeypatch,
        (CommandResult(command=["sh"], stderr=f"{EXEC_START_MARKER}\ntool boom\n"), None),
        exit_code=exit_code,
    )
    assert result.exit_code == exit_code
    assert result.stderr == "tool boom\n"
    assert not sandbox.evidence.errors


def test_cage_that_dies_during_a_tool_call_fails_closed(repo: Path, monkeypatch):
    client = fake_client()
    exec_api(client, exit_code=137)
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}

    def fake_capture_exec(api, exec_id, command, **kwargs):
        client.containers.create.return_value.attrs = {
            "State": {"Status": "exited", "ExitCode": 137}
        }
        return CommandResult(command=["sleep"], stderr=f"{EXEC_START_MARKER}\n"), None

    monkeypatch.setattr("run.sandbox.capture_exec", fake_capture_exec)
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.open_cage()
        result = sandbox.exec(["sleep", "100"])
    assert result.timed_out
    assert sandbox.evidence.errors[0].code == "CAGE_EXITED"
    assert sandbox.evidence.components.sandbox == State.ERROR
    assert sandbox.evidence.status == "error"


def test_failed_cleanup_after_a_timeout_fails_closed(repo: Path, monkeypatch):
    monkeypatch.setattr(
        "run.sandbox.capture_exec",
        lambda api, exec_id, command, **kwargs: (
            CommandResult(command=list(command), stderr=EXEC_START_MARKER),
            None,
        ),
    )
    monkeypatch.setattr(
        "run.sandbox.capture_attached",
        lambda *args, **kwargs: CommandResult(command=["sh"], exit_code=1, stderr="cannot kill"),
    )
    client = fake_client()
    exec_api(client, exit_code=137)
    client.containers.create.return_value.attrs = {"State": {"Status": "running"}}
    sandbox = Sandbox(repo, client_factory=lambda: client)
    with sandbox:
        sandbox.open_cage()
        sandbox.exec(["sleep", "100"])
    assert [error.code for error in sandbox.evidence.errors] == [
        "EXEC_KILL_FAILED",
        "EXEC_TIMEOUT",
    ]
    assert sandbox.evidence.components.sandbox == State.ERROR


def test_the_kill_sweep_skips_only_zombies():
    # A live process can have an empty cmdline (execve with no argv), so liveness
    # is decided by the state field in /proc/<pid>/stat, never by cmdline. The
    # whole stat record is read: a single-line read would stop inside a comm
    # containing a newline and could mistake a live process for a zombie.
    assert 'cat "$entry/stat"' in KILL_LINGERING
    assert "read -r stat" not in KILL_LINGERING
    assert '"Z"' in KILL_LINGERING
    assert "cmdline" not in KILL_LINGERING
    assert '"1"' in KILL_LINGERING and '"$$"' in KILL_LINGERING


def test_exec_waits_for_the_daemon_exit_event(repo: Path, monkeypatch):
    sandbox, result = _exec_with_results(
        repo,
        monkeypatch,
        (CommandResult(command=["sh"], stderr=f"{EXEC_START_MARKER}\n"), None),
        inspect_failure=[{"Running": True, "ExitCode": None}, {"Running": False, "ExitCode": 0}],
    )
    assert not sandbox.evidence.errors
    assert result.exit_code == 0


def test_detonate_collects_evidence_after_a_late_exception(repo: Path, monkeypatch):
    from run.evidence import NetworkHit

    monkeypatch.setattr("run.sandbox.docker.DockerClient", lambda **kwargs: fake_client())
    monkeypatch.setattr(Sandbox, "start_sinks", lambda self: None)
    monkeypatch.setattr(Sandbox, "trace_before", lambda self: True)

    def broken(self, command):
        raise RuntimeError("late failure")

    def collect(self):
        self.evidence.dns_hits.append(
            NetworkHit(source_ip="192.0.2.20", destination="evil.example")
        )

    def trace(self):
        self.evidence.components.trace = State.COMPLETE

    monkeypatch.setattr(Sandbox, "run_command", broken)
    monkeypatch.setattr(Sandbox, "collect_sinks", collect)
    monkeypatch.setattr(Sandbox, "trace_after", trace)
    evidence = detonate(repo)
    assert evidence.status == "error"
    assert evidence.dns_hits[0].destination == "evil.example"
    assert evidence.components.trace == State.COMPLETE


def test_byte_filename_exclusions_serialize_after_staging(repo: Path):
    (repo / "bad\udcff").mkdir()
    (repo / "bad\udcff" / ".env").write_text("fixture")
    sandbox = Sandbox(repo, client_factory=fake_client)
    with sandbox:
        payload = sandbox.evidence.model_dump_json()
        assert ".env" in payload


@pytest.mark.parametrize("change", ["unchanged", "added", "modified"])
def test_only_added_or_modified_files_at_the_cap_trigger_write_limit(repo, monkeypatch, change):
    from run.staging import StagingLimits

    entry = Entry(kind="file", mode=0o666, size=4096, sha256="0" * 64)
    before = {} if change == "added" else {"fixture": entry}
    after = {
        "fixture": entry
        if change != "modified"
        else Entry(kind="file", mode=0o666, size=4096, sha256="1" * 64)
    }
    manifests = iter([before, after])
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(
        repo,
        SandboxConfig(staging=StagingLimits(max_file_bytes=4096)),
        client_factory=lambda: fake_client(),
    )
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    assert any(e.code == "REPO_WRITE_LIMIT" for e in sandbox.evidence.errors) is (
        change != "unchanged"
    )


@pytest.mark.parametrize("path", ["extra", ".env"])
def test_trace_charges_oversize_new_files_and_rewritten_bait(repo: Path, monkeypatch, path):
    before = _planted_manifest()
    before[".env"] = Entry(kind="file", mode=0o666, size=128, sha256="1" * 64)
    after = dict(before)
    after[path] = Entry(kind="file", mode=0o666, size=65, sha256="4" * 64)
    manifests = iter([before, after])
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(
        repo, SandboxConfig(staging=StagingLimits(max_file_bytes=64)), client_factory=fake_client
    )
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    assert "REPO_WRITE_LIMIT" in {error.code for error in sandbox.evidence.errors}
    assert sandbox.evidence.status == "error"


def test_home_snapshot_failure_keeps_repo_changes_and_trace_error(repo, monkeypatch):
    before = {"README.md": Entry(kind="file", mode=0o666, sha256="0" * 64)}
    after = {"README.md": Entry(kind="file", mode=0o666, sha256="1" * 64)}

    def snapshot_tree(self, role, root):
        if root == self.home_path:
            raise RuntimeError("home snapshot unavailable")
        return before if "before" in role else after

    monkeypatch.setattr(Sandbox, "_snapshot_tree", snapshot_tree)
    sandbox = Sandbox(repo, client_factory=fake_client)
    with sandbox:
        assert not sandbox.trace_before()
        sandbox.trace_after()
    assert sandbox.evidence.components.trace == State.ERROR
    assert [(entry.path, entry.change) for entry in sandbox.evidence.file_diffs] == [
        ("README.md", "modified")
    ]
    assert any(error.code == "TRACE_FAILED" for error in sandbox.evidence.errors)


def test_trace_counts_repo_files_without_bait_cache_or_directories(repo, monkeypatch):
    manifests = iter(
        [
            {
                "README.md": Entry(kind="file", mode=0o666, sha256="0" * 64),
                "build/output": Entry(kind="file", mode=0o666, sha256="0" * 64),
                ".env": Entry(kind="file", mode=0o666, sha256="0" * 64),
                "src": Entry(kind="dir", mode=0o777),
            },
            {},
        ]
    )
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(repo, client_factory=fake_client)
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    assert sandbox.evidence.staged_file_count == 1
    assert [entry.path for entry in sandbox.evidence.file_diffs if entry.is_repo_file] == [
        "README.md"
    ]


@pytest.mark.parametrize("bound", ["bytes", "entries", "file"])
def test_home_writes_share_repository_collection_limits(repo, monkeypatch, bound):
    from run.staging import StagingLimits

    (repo / "README.md").write_text("x")
    limits = StagingLimits(max_bytes=10, max_entries=2, max_file_bytes=8)
    file = Entry(kind="file", mode=0o666, size=6, sha256="0" * 64)
    if bound == "bytes":
        after = {"repo.txt": file, "/home/agent/.cache/data": file}
    elif bound == "entries":
        after = {"/home/agent/.cache/" + str(i): Entry(kind="dir", mode=0o777) for i in range(3)}
    else:
        after = {"/home/agent/data": Entry(kind="file", mode=0o666, size=8, sha256="0" * 64)}
    manifests = iter([{}, after])
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(repo, SandboxConfig(staging=limits), client_factory=fake_client)
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    assert any(error.code == "REPO_WRITE_LIMIT" for error in sandbox.evidence.errors)
    assert sandbox.evidence.status == "error"
    assert any(entry.path.startswith("/home/agent/") for entry in sandbox.evidence.file_diffs)


@pytest.mark.parametrize(
    "changed,total,after_size,expected",
    [(50, 50, 0, "BLOCK"), (1, 50, 0, "FLAG"), (50, 50, 4, "ALLOW")],
)
def test_truncated_repository_files_use_deletion_thresholds(
    repo, monkeypatch, changed, total, after_size, expected
):
    from run.evidence import RunComponents, RunEvidence
    from run.verdict import ReadOutcome, fuse

    before = {
        f"src/{i}.py": Entry(kind="file", mode=0o666, size=10, sha256="0" * 64)
        for i in range(total)
    }
    after = dict(before)
    for i in range(changed):
        after[f"src/{i}.py"] = Entry(kind="file", mode=0o666, size=after_size, sha256="1" * 64)
    manifests = iter([before, after])
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(repo, client_factory=fake_client)
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    run = RunEvidence(
        status="complete",
        components=RunComponents(**{key: State.COMPLETE for key in RunComponents.model_fields}),
        tool_log=[CommandResult(command=["run_cmd", "true"], exit_code=0)],
        file_diffs=sandbox.evidence.file_diffs,
        staged_file_count=sandbox.evidence.staged_file_count,
    )
    assert fuse(ReadOutcome(status=State.COMPLETE, verdict="clean"), run).verdict == expected


@pytest.mark.parametrize("replace", [False, True])
def test_trace_recognizes_empty_file_replacement_and_keeps_exclusions(repo, monkeypatch, replace):
    from run.trace import snapshot

    paths = ["README.md", ".env", "build/output", "node_modules/pkg/a", "empty"]
    for path in paths:
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("" if path == "empty" else "original")
    before = snapshot(repo)
    for path in paths:
        target = repo / path
        if replace:
            target.unlink()
        target.write_text("")
        target.chmod(0o600)
    after = snapshot(repo)
    before["/home/agent/data"] = Entry(kind="file", mode=0o666, size=5, sha256="0" * 64)
    after["/home/agent/data"] = Entry(kind="file", mode=0o666, size=0, sha256="1" * 64)
    manifests = iter([before, after])
    monkeypatch.setattr(Sandbox, "_run_trace_helper", lambda self, role: next(manifests))
    sandbox = Sandbox(repo, client_factory=fake_client)
    with sandbox:
        assert sandbox.trace_before()
        sandbox.trace_after()
    assert [entry.path for entry in sandbox.evidence.file_diffs if entry.is_truncated] == [
        "README.md"
    ]
    assert sandbox.evidence.staged_file_count == 2
