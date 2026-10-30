import contextlib
import ipaddress
import json
import math
import os
import random
import shutil
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import docker
from docker.errors import APIError, DockerException, NotFound
from docker.types import IPAMConfig, IPAMPool, LogConfig, Mount, Ulimit

from run.capture import capture_attached, capture_exec
from run.evidence import (
    CommandResult,
    FileDiff,
    HoneytokenHit,
    RunError,
    RunEvidence,
    State,
    safe_text,
)
from run.honeytokens import (
    Honeytoken,
    generate_tokens,
    plant_tokens,
    scan_sink_log,
    scan_tool_results,
)
from run.llm import LLMBackend
from run.sink_logs import read_sink_log
from run.staging import StagingLimits, is_finite, stage_repository
from run.trace import TraceError, diff, error_paths, manifest_from_json

SCAN_LABEL = "org.baitwatch.scan-id"
DEFAULT_SUBNET = "10.13.37.0/24"
SUBNET_ATTEMPTS = 16
SINKS_DIR = Path(__file__).parent / "sinks"
TRACE_SCRIPT = Path(__file__).parent / "trace.py"
# A 10k-entry manifest is ~1 MiB; past this bound the snapshot is not trustworthy.
TRACE_OUTPUT_BYTES = 8 * 1024 * 1024
# Collection waits this long for a sink to drain in-flight contacts and acknowledge.
SINK_STOP_SECONDS = 5.0
SINK_POLL_SECONDS = 0.05
# Trusted, not model input: busybox timeout kills only its direct child, so a
# tool call can leave forked or background work behind. Everything in the cage
# runs as the same uid, and PID 1 is the cage's own trusted sleep. A live
# process must never be skipped, whatever its cmdline: only a zombie — state Z
# in /proc/<pid>/stat, dead until PID 1 reaps it — is beyond a kill. The state
# sits after the last ')' of comm, which may itself contain parens or a
# newline, so the whole record is read at once; an unreadable or malformed
# record yields no Z and is killed like a live process.
# Busybox's timeout watchdog notices a finished parent on its next 1s tick.
KILL_LINGERING = (
    "poll=0; "
    "while [ $poll -lt 25 ]; do alive=0; "
    "for entry in /proc/[0-9]*; do pid=${entry#/proc/}; "
    'if [ "$pid" != "1" ] && [ "$pid" != "$$" ]; then '
    'stat=$(cat "$entry/stat" 2>/dev/null); '
    "state=${stat##*) }; state=${state%% *}; "
    'if [ "$state" != "Z" ]; then alive=1; fi; fi; '
    "done; "
    'if [ "$alive" -eq 0 ]; then exit 0; fi; '
    "poll=$((poll + 1)); sleep 0.1; done; "
    "round=0; killed=0; "
    "while [ $round -lt 3 ]; do "
    "alive=0; "
    "for entry in /proc/[0-9]*; do pid=${entry#/proc/}; "
    'if [ "$pid" != "1" ] && [ "$pid" != "$$" ]; then '
    'stat=$(cat "$entry/stat" 2>/dev/null); '
    "state=${stat##*) }; state=${state%% *}; "
    'if [ "$state" != "Z" ]; then alive=1; '
    'if kill -KILL "$pid" 2>/dev/null; then killed=2; fi; fi; fi; '
    "done; "
    'if [ "$alive" -eq 0 ]; then exit "$killed"; fi; '
    "round=$((round + 1)); sleep 1; "
    "done; exit 1"
)
KILL_TIMEOUT_SECONDS = 10
# Printed by the in-cage wrapper before the tool starts; its absence means the
# docker exec never reached the cage, so its exit code is not the tool's.
EXEC_START_MARKER = "baitwatch-exec-started"
# A snapshot can carry error markers for thousands of paths; the trace error
# names only a bounded few.
TRACE_PATH_LIMIT = 5
TRACE_PATH_CHARS = 150


def _bounded_paths(paths: Sequence[str]) -> str:
    shown = ", ".join(path[:TRACE_PATH_CHARS] for path in paths[:TRACE_PATH_LIMIT])
    if len(paths) > TRACE_PATH_LIMIT:
        return f"{shown} (+{len(paths) - TRACE_PATH_LIMIT} more)"
    return shown


class SandboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxConfig:
    image: str = "alpine:3.20"
    sink_image: str = "python:3.12-alpine"
    # None tries DEFAULT_SUBNET, then other 10.13.X.0/24 pools on overlap.
    # An explicit subnet never falls back.
    subnet: str | None = None
    # Host offsets within the scan's /24; .1 stays unassigned in isolated mode.
    cage_host: int = 20
    dns_host: int = 53
    http_host: int = 9
    memory_bytes: int = 256 * 1024 * 1024
    nano_cpus: int = 500_000_000
    pids_limit: int = 64
    tmpfs_bytes: int = 32 * 1024 * 1024
    timeout_seconds: float = 20
    sink_ready_seconds: float = 15
    # The decoy cage's overall lifetime and the per-tool-call deadline.
    decoy_seconds: float = 120
    tool_timeout_seconds: float = 10
    max_output_bytes: int = 64 * 1024
    staging: StagingLimits = field(default_factory=StagingLimits)

    def __post_init__(self) -> None:
        hosts = (self.cage_host, self.dns_host, self.http_host)
        if (
            any(type(host) is not int or not 2 <= host <= 254 for host in hosts)
            or len(set(hosts)) != 3
        ):
            raise ValueError("cage and sink host offsets must be distinct integers in 2..254")
        if self.subnet is not None:
            try:
                network = ipaddress.IPv4Network(self.subnet)
            except ValueError as exc:
                raise ValueError("an explicit subnet must be an IPv4 /24 network") from exc
            if network.prefixlen != 24:
                raise ValueError("an explicit subnet must be an IPv4 /24 network")
        if any(
            type(value) is not int
            for value in (
                self.memory_bytes,
                self.nano_cpus,
                self.pids_limit,
                self.tmpfs_bytes,
                self.max_output_bytes,
            )
        ):
            raise ValueError("memory, cpu, pid, tmpfs, and output limits must be integers")
        if type(self.timeout_seconds) not in (int, float) or not is_finite(self.timeout_seconds):
            raise ValueError("timeout_seconds must be a finite int or float")
        if type(self.sink_ready_seconds) not in (int, float) or not is_finite(
            self.sink_ready_seconds
        ):
            raise ValueError("sink_ready_seconds must be a finite int or float")
        for name, value in (
            ("decoy_seconds", self.decoy_seconds),
            ("tool_timeout_seconds", self.tool_timeout_seconds),
        ):
            if type(value) not in (int, float) or not is_finite(value):
                raise ValueError(f"{name} must be a finite int or float")
        if (
            not self.image
            or not self.sink_image
            or any(
                value <= 0
                for value in (
                    self.memory_bytes,
                    self.nano_cpus,
                    self.pids_limit,
                    self.tmpfs_bytes,
                    self.timeout_seconds,
                    self.sink_ready_seconds,
                    self.decoy_seconds,
                    self.tool_timeout_seconds,
                    self.max_output_bytes,
                )
            )
        ):
            raise ValueError("image and positive resource/output/time limits are required")


class Sandbox:
    """One staged copy and one cage use per instance: a single command, or the
    long-lived decoy cage with exec calls.

    Local Linux daemon only. No published ports, no implicit image pulls, and the
    original repository is never mounted.
    """

    def __init__(
        self,
        path: Path | str,
        config: SandboxConfig | None = None,
        *,
        client_factory: Callable | None = None,
    ) -> None:
        self.path = Path(path)
        self.config = config or SandboxConfig()
        self.evidence = RunEvidence()
        self.name = f"bw-{self.evidence.scan_id.hex}"
        self.labels = {SCAN_LABEL: str(self.evidence.scan_id)}
        self._docker_host = os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock")
        self._factory = client_factory or (
            lambda: docker.DockerClient(base_url=self._docker_host, timeout=5)
        )
        self._client = None
        self._network = None
        self._subnet: ipaddress.IPv4Network | None = None
        self._containers: list = []
        self._temporary: Path | None = None
        self._cage = None
        self._open = False
        self._closed = False
        self._command_started = False
        self._service_roles: set[str] = set()
        self._sinks: dict[str, object] = {}
        self._sink_logs: dict[str, Path] = {}
        self._sinks_collected: set[str] = set()
        self._honeytokens: tuple[Honeytoken, ...] = ()
        self._planted_paths: frozenset[str] = frozenset()
        self._honeytoken_scanned = False
        self._trace_before: dict | None = None

    @property
    def network_id(self) -> str | None:
        return self._network.id if self._network is not None else None

    @property
    def container_id(self) -> str | None:
        return self._cage.id if self._cage is not None else None

    @property
    def staged_path(self) -> Path:
        if self._temporary is None:
            raise SandboxError("repository has not been staged")
        return self._temporary / "repo"

    @property
    def honeytokens(self) -> tuple[Honeytoken, ...]:
        """The tokens planted for this scan; memory only, never persisted."""
        return self._honeytokens

    def _network_subnet(self) -> ipaddress.IPv4Network:
        if self._subnet is None:
            raise SandboxError("subnet addresses exist only after the network is created")
        return self._subnet

    @property
    def subnet(self) -> str:
        return str(self._network_subnet())

    @property
    def cage_ip(self) -> str:
        return str(self._network_subnet().network_address + self.config.cage_host)

    @property
    def dns_ip(self) -> str:
        return str(self._network_subnet().network_address + self.config.dns_host)

    @property
    def http_ip(self) -> str:
        return str(self._network_subnet().network_address + self.config.http_host)

    def _error(self, code: str, message: str, component: str | None = "sandbox") -> None:
        # str(exc) can be empty (e.g. TimeoutError()); an empty message would
        # raise ValidationError here and skip the caller's cleanup.
        self.evidence.errors.append(RunError(code=code, message=message[:1000] or code))
        self.evidence.status = "error"
        if component is not None:
            setattr(self.evidence.components, component, State.ERROR)

    def _create_network(self) -> ipaddress.IPv4Network:
        if self.config.subnet is not None:
            subnets = [self.config.subnet]
        else:
            fallbacks = random.SystemRandom().sample(
                [octet for octet in range(256) if octet != 37], SUBNET_ATTEMPTS - 1
            )
            subnets = [DEFAULT_SUBNET, *(f"10.13.{octet}.0/24" for octet in fallbacks)]
        overlap = ""
        for subnet in subnets:
            try:
                self._network = self._client.networks.create(
                    self.name,
                    driver="bridge",
                    internal=True,
                    enable_ipv6=False,
                    ipam=IPAMConfig(pool_configs=[IPAMPool(subnet=subnet)]),
                    labels=self.labels,
                    # Without this the host takes the gateway address and every host
                    # service bound to 0.0.0.0 is reachable from the cage.
                    options={"com.docker.network.bridge.gateway_mode_ipv4": "isolated"},
                )
            except APIError as exc:
                if "overlaps" not in str(exc).lower():
                    raise
                overlap = str(exc)
                continue
            self._network.reload()
            if any(pool.get("Gateway") for pool in self._network.attrs["IPAM"]["Config"]):
                raise SandboxError(
                    "cage network has a host gateway; needs Docker Engine 28+ isolated mode"
                )
            return ipaddress.IPv4Network(subnet)
        if self.config.subnet is not None:
            raise SandboxError(
                f"requested subnet {self.config.subnet} overlaps an existing Docker network"
            )
        raise SandboxError(
            f"all {SUBNET_ATTEMPTS} candidate subnets in 10.13.0.0/16 overlap: {overlap}"
        )

    def __enter__(self) -> "Sandbox":
        if self._closed or self._open:
            raise SandboxError("a sandbox cannot be reopened or nested")
        try:
            if os.name != "posix":
                raise SandboxError("the sandbox requires a local Linux Docker daemon")
            if not self._docker_host.startswith("unix://"):
                raise SandboxError("remote Docker daemons cannot use local staging paths")
            self._client = self._factory()
            self._client.ping()
            if self._client.info().get("OSType") != "linux":
                raise SandboxError("Linux containers are required")
            self._client.images.get(self.config.image)
            self._temporary = Path(tempfile.mkdtemp(prefix="bw-stage-"))
            self.evidence.staging_exclusions = [
                safe_text(path)
                for path in stage_repository(self.path, self.staged_path, self.config.staging)
            ]
            # Planted before the first trace snapshot, so the bait never shows
            # up as one of the repository's own file diffs.
            token_set = generate_tokens()
            planned = {file.path for file in token_set.files}
            planned.update(path.rpartition("/")[0] for path in tuple(planned) if "/" in path)
            existing = {path for path in planned if os.path.lexists(self.staged_path / path)}
            self._honeytokens = plant_tokens(self.staged_path, token_set)
            # Only paths planting actually created are exempt from the write
            # limits; a path the repository already had stays charged.
            self._planted_paths = frozenset(
                path
                for path in planned - existing
                if os.path.lexists(self.staged_path / path)
            )
            self._subnet = self._create_network()
            self._open = True
            return self
        except BaseException as exc:
            # __exit__ never runs when __enter__ raises, so cleanup happens here
            # even for interrupts; those must propagate unchanged.
            self._error("SANDBOX_SETUP", str(exc))
            self.close()
            if not isinstance(exc, Exception):
                raise
            raise SandboxError(str(exc)) from exc

    def _create(
        self,
        image: str,
        command: Sequence[str],
        role: str,
        ip: str | None,
        *,
        mounts: Sequence[Mount] = (),
        sysctls: dict[str, str] | None = None,
        working_dir: str = "/tmp",
        networked: bool = True,
    ):
        if not self._open or self._client is None or (networked and self._network is None):
            raise SandboxError("sandbox is not open")
        self._client.images.get(image)
        config = self.config
        network_kwargs = {}
        if networked:
            endpoint = self._client.api.create_endpoint_config(ipv4_address=ip)
            network_kwargs = {
                "network": self._network.name,
                "networking_config": {self._network.name: endpoint},
                "dns": [self.dns_ip],
                "dns_opt": ["timeout:1", "attempts:1"],
                "dns_search": ["."],
            }
        else:
            network_kwargs = {"network_mode": "none"}
        container = self._client.containers.create(
            image,
            command=list(command),
            entrypoint=[],
            name=f"{self.name}-{role}",
            labels=self.labels,
            user="65532:65532",
            working_dir=working_dir,
            environment={"HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1"},
            mounts=list(mounts),
            read_only=True,
            privileged=False,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            sysctls=sysctls,
            mem_limit=config.memory_bytes,
            memswap_limit=config.memory_bytes,
            nano_cpus=config.nano_cpus,
            pids_limit=config.pids_limit,
            ulimits=[
                Ulimit(
                    name="fsize",
                    soft=config.staging.max_file_bytes,
                    hard=config.staging.max_file_bytes,
                )
            ]
            if role == "cage"
            else None,
            tmpfs={"/tmp": f"rw,noexec,nosuid,nodev,size={config.tmpfs_bytes},mode=1777"},
            log_config=LogConfig(type="json-file", config={"max-size": "1m", "max-file": "1"}),
            restart_policy={"Name": "no"},
            **network_kwargs,
        )
        self._containers.append(container)
        return container

    def start_service(self, role: str, image: str, command: Sequence[str]):
        """Starting a sink container never marks that sink complete."""
        if role not in {"dns", "http"} or role in self._service_roles:
            raise SandboxError("service role must be a unique dns or http sink")
        ip = self.dns_ip if role == "dns" else self.http_ip
        try:
            container = self._create(image, command, role, ip)
            container.start()
            self._service_roles.add(role)
            return container
        except Exception as exc:
            self._error("SERVICE_START", str(exc))
            raise SandboxError(str(exc)) from exc

    def start_sinks(self) -> None:
        """Start the production sinks and wait until both report ready.

        A sink that dies or never reports ready marks only its own components
        error; the scan continues and stays non-ALLOW either way.
        """
        log_dir = self._temporary / "sink-logs"
        log_dir.mkdir(mode=0o700)
        specs = {
            "dns": (
                "dns_sink.py",
                [
                    "python",
                    "-I",
                    "/sink/dns_sink.py",
                    "--log",
                    "/log/dns.jsonl",
                    "--answer",
                    self.http_ip,
                ],
            ),
            "http": (
                "http_sink.py",
                ["python", "-I", "/sink/http_sink.py", "--log", "/log/http.jsonl"],
            ),
        }
        for role, (script, command) in specs.items():
            try:
                log = log_dir / f"{role}.jsonl"
                log.touch()
                # The sink's uid 65532 appends through the bind mount; only the
                # 0700 scan directory shields the file from other host users.
                log.chmod(0o666)
                container = self._create(
                    self.config.sink_image,
                    command,
                    f"sink-{role}",
                    self.dns_ip if role == "dns" else self.http_ip,
                    mounts=[
                        Mount(
                            f"/sink/{script}",
                            str(SINKS_DIR / script),
                            type="bind",
                            read_only=True,
                        ),
                        Mount(f"/log/{role}.jsonl", str(log), type="bind", read_only=False),
                    ],
                    # Low ports without a capability: the sysctl is namespaced
                    # to the sink container's own network namespace.
                    sysctls={"net.ipv4.ip_unprivileged_port_start": "0"},
                )
                container.start()
                self._sinks[role] = container
                self._sink_logs[role] = log
                self._wait_ready(container, log, role)
            except Exception as exc:
                self._sinks.pop(role, None)
                self._sink_error(role, "SERVICE_START", str(exc))

    def _wait_ready(self, container, log: Path, role: str) -> None:
        deadline = time.monotonic() + self.config.sink_ready_seconds
        while time.monotonic() < deadline:
            try:
                text = log.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            for line in text.splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("kind") == "ready":
                    return
            container.reload()
            if container.attrs["State"]["Status"] != "running":
                raise SandboxError(f"{role} sink container exited during startup")
            time.sleep(0.05)
        raise SandboxError(f"{role} sink never wrote its ready record")

    def _sink_components(self, role: str) -> tuple[str, ...]:
        return ("dns_sink",) if role == "dns" else ("http_sink", "tls_sink")

    def _sink_error(self, role: str, code: str, message: str) -> None:
        for component in self._sink_components(role):
            setattr(self.evidence.components, component, State.ERROR)
        self.evidence.errors.append(RunError(code=code, message=message[:1000] or code))
        self.evidence.status = "error"

    def _container_running(self, container) -> bool:
        try:
            container.reload()
            return container.attrs["State"]["Status"] == "running"
        except Exception:
            return False

    def _stop_sink(self, container) -> tuple[bool, int | None]:
        """Ask a sink to drain and exit; (stopped, exit code) within the bound."""
        try:
            container.kill(signal="SIGTERM")
        except NotFound:
            pass
        except Exception:
            pass  # a reload below decides whether it really stopped
        deadline = time.monotonic() + SINK_STOP_SECONDS
        while time.monotonic() < deadline:
            try:
                container.reload()
                state = container.attrs["State"]
            except Exception:
                return False, None
            if state.get("Status") != "running":
                return True, state.get("ExitCode")
            time.sleep(SINK_POLL_SECONDS)
        return False, None

    def _collect_sink(self, role: str) -> tuple[str | None, str | None]:
        """Read one sink's log into evidence, then judge it.

        The hits are extended before any problem is decided: a failed sink
        still captured real contacts, and evidence is never dropped because
        its component errored.
        """
        try:
            sink_log = read_sink_log(self._sink_logs[role])
        except Exception as exc:
            return f"could not read the sink log: {exc}", "SINK_LOG"
        if role == "dns":
            self.evidence.dns_hits.extend(sink_log.dns_hits)
        else:
            self.evidence.http_hits.extend(sink_log.http_hits)
            self.evidence.tls_hits.extend(sink_log.tls_hits)
        if not sink_log.ready:
            return f"{role} sink log has no ready record", "SINK_FAILED"
        if sink_log.problems:
            return "; ".join(sink_log.problems), "SINK_LOG"
        if sink_log.truncated:
            return f"{role} sink log stopped at its size cap", "SINK_LOG"
        if not sink_log.stopped:
            return f"{role} sink log has no stopped record", "SINK_LOG"
        return None, None

    def _scan_honeytokens(self) -> None:
        """After the sinks stop, search every sink record and every tool output
        for planted token values. A bound hit is an error, never a clean pass;
        the hits themselves never change the RUN status."""
        if self._honeytoken_scanned or not self._honeytokens:
            return
        self._honeytoken_scanned = True
        hits: list[HoneytokenHit] = []
        incomplete = False
        for role in ("dns", "http"):
            log = self._sink_logs.get(role)
            if log is None:
                continue  # a sink that never started has already failed closed
            scan = scan_sink_log(log, self._honeytokens)
            hits.extend(scan.hits)
            incomplete = incomplete or scan.incomplete
        tool_scan = scan_tool_results(self.evidence.tool_log, self._honeytokens)
        hits.extend(tool_scan.hits)
        incomplete = incomplete or tool_scan.incomplete
        self.evidence.honeytoken_hits.extend(hits)
        if incomplete:
            self._error(
                "HONEYTOKEN_SCAN_INCOMPLETE",
                "honeytoken detection hit a size bound; records past it were not scanned",
                component=None,
            )

    def collect_sinks(self) -> None:
        """Stop each sink, then read its log. A component is complete only when
        the sink acknowledged the stop after draining everything it accepted;
        the log's hits land in evidence whatever the component's state."""
        for role in ("dns", "http"):
            container = self._sinks.get(role)
            if container is None:
                continue  # never started, or its start already failed closed
            if role in self._sinks_collected:
                continue  # a second collection must not duplicate the hits
            self._sinks_collected.add(role)
            components = self._sink_components(role)
            if not self._container_running(container):
                problem, code = f"{role} sink container is not running at collection", "SINK_FAILED"
            else:
                stopped, exit_code = self._stop_sink(container)
                if not stopped:
                    problem = f"{role} sink did not stop within {SINK_STOP_SECONDS:g}s"
                    code = "SINK_FAILED"
                elif exit_code != 0:
                    problem = f"{role} sink exited with code {exit_code} after stopping"
                    code = "SINK_FAILED"
                else:
                    problem, code = None, None
            log_problem, log_code = self._collect_sink(role)
            problem = problem or log_problem
            code = code or log_code
            if problem is None:
                for component in components:
                    setattr(self.evidence.components, component, State.COMPLETE)
                continue
            for component in components:
                setattr(self.evidence.components, component, State.ERROR)
            self.evidence.errors.append(RunError(code=code, message=f"{role}: {problem}"[:1000]))
            self.evidence.status = "error"
        self._scan_honeytokens()

    def _run_trace_helper(self, role: str) -> dict:
        command = ["python", "-I", "/trace/trace.py", "snapshot", "/repo"]
        container = self._create(
            self.config.sink_image,
            command,
            role,
            None,
            networked=False,
            mounts=[
                Mount("/repo", str(self.staged_path), type="bind", read_only=True),
                Mount("/trace/trace.py", str(TRACE_SCRIPT), type="bind", read_only=True),
            ],
        )
        try:

            def stop() -> None:
                with contextlib.suppress(DockerException):
                    container.kill()

            # Snapshots run in a helper container because the cage's uid can
            # leave files the host user cannot read.
            result = capture_attached(
                ["docker", "--host", self._docker_host, "start", "--attach", container.id],
                command,
                timeout_seconds=self.config.timeout_seconds,
                max_output_bytes=TRACE_OUTPUT_BYTES,
                stop_container=stop,
            )
        finally:
            self._remove_container(container, set())
        if result.timed_out:
            raise SandboxError(f"trace helper exceeded its {self.config.timeout_seconds}s limit")
        if result.output_truncated:
            raise SandboxError(f"trace manifest exceeded {TRACE_OUTPUT_BYTES} bytes")
        if result.exit_code != 0:
            detail = result.stderr.strip() or f"exit code {result.exit_code}"
            raise SandboxError(f"trace helper failed: {detail}")
        try:
            return manifest_from_json(result.stdout)
        except TraceError as exc:
            raise SandboxError(str(exc)) from exc

    def trace_before(self) -> bool:
        if self._trace_before is not None:
            raise SandboxError("the before snapshot can only be taken once")
        try:
            self._trace_before = self._run_trace_helper("trace-before")
        except Exception as exc:
            self._error("TRACE_FAILED", str(exc), component="trace")
            return False
        return True

    def trace_after(self) -> None:
        if self._trace_before is None:
            return  # the failed before snapshot already marked the trace error
        try:
            after = self._run_trace_helper("trace-after")
        except Exception as exc:
            self._error("TRACE_FAILED", str(exc), component="trace")
            return
        self.evidence.file_diffs = [
            FileDiff(path=path, change=change) for path, change in diff(self._trace_before, after)
        ]
        limits = self.config.staging
        planted = self._planted_paths
        if (
            sum(1 for path in after if path not in planted) > limits.max_entries
            or sum(
                entry.size
                for path, entry in after.items()
                if entry.kind == "file" and path not in planted
            )
            > limits.max_bytes
            or any(
                entry.kind == "file"
                and entry.size >= limits.max_file_bytes
                and self._trace_before.get(path) != entry
                for path, entry in after.items()
            )
        ):
            self._error(
                "REPO_WRITE_LIMIT", "staged repository reached a file, total byte or entry limit"
            )
        marked = sorted(set(error_paths(self._trace_before)) | set(error_paths(after)))
        if marked:
            # The diffs are still evidence, but a snapshot that could not read
            # every path cannot promise the diff is whole.
            self._error(
                "TRACE_INCOMPLETE",
                f"a snapshot could not read: {_bounded_paths(marked)}",
                component="trace",
            )
            return
        self.evidence.components.trace = State.COMPLETE

    def open_cage(self) -> None:
        """Start the long-lived cage the decoy's tool calls exec into.

        The trusted idle command self-terminates at the decoy deadline, so a
        crashed host loop can never leave the cage running unbounded. One cage
        per sandbox, mutually exclusive with run_command.
        """
        if self._command_started:
            raise SandboxError("one cage per sandbox; create a new sandbox for another run")
        self._command_started = True
        try:
            # ceil keeps the sleep argument an integer any busybox image accepts.
            self._cage = self._create(
                self.config.image,
                ["sleep", str(max(1, math.ceil(self.config.decoy_seconds)))],
                "cage",
                self.cage_ip,
                mounts=[Mount("/repo", str(self.staged_path), type="bind", read_only=False)],
                working_dir="/repo",
            )
            self._cage.start()
            self._cage.reload()
            if self._cage.attrs["State"]["Status"] != "running":
                raise SandboxError("cage exited during startup")
        except Exception as exc:
            self._error("CAGE_START", str(exc), component="sandbox")
            raise SandboxError(str(exc)) from exc

    def _cage_running(self) -> bool:
        self._cage.reload()
        return self._cage.attrs["State"]["Status"] == "running"

    def cage_running(self) -> bool:
        return self._cage is not None and self._container_running(self._cage)

    def _kill_lingering(self) -> None:
        """Kill every live cage process except PID 1 and the killer itself.

        Only one tool call runs at a time, so anything still alive when an
        exec returns belongs to that call: a fork the `timeout` wrapper could
        not reach, or work backgrounded past a clean exit. Left alive it could
        write or exfiltrate after the sinks and trace were collected. All tool
        processes run under the cage's uid, and only the trusted sleep runs as
        PID 1. A failed cleanup is an error, never a silent straggler.
        """
        try:
            result = capture_attached(
                [
                    "docker",
                    "--host",
                    self._docker_host,
                    "exec",
                    self._cage.id,
                    "sh",
                    "-c",
                    KILL_LINGERING,
                ],
                ["sh", "-c", KILL_LINGERING],
                timeout_seconds=KILL_TIMEOUT_SECONDS,
                max_output_bytes=self.config.max_output_bytes,
                stop_container=lambda: None,
            )
        except Exception as exc:
            self._error("EXEC_KILL_FAILED", str(exc))
            return
        if result.timed_out or result.output_truncated or result.exit_code not in (0, 2):
            self._error("EXEC_KILL_FAILED", "could not kill lingering processes inside the cage")
        elif result.exit_code == 2:
            self._error("EXEC_LINGERING_KILLED", "tool call left live background processes to kill")

    def _confirm_exec(self, exec_id, result: CommandResult, reached: bool, failure) -> None:
        """Docker's own exec record is the only proof a stream end was the exit.

        The stream's end proves nothing — a broken connection can still end
        on a frame boundary, and the marker only proves the call started —
        so the record must show the exec finished, and its ExitCode is the
        code the scan reports. Timeout and output-cap stops are our own
        kills and keep their existing error paths instead.
        """
        if result.timed_out or result.output_truncated:
            return
        try:
            deadline = time.monotonic() + 2.0
            for _ in range(41):
                record = self._client.api.exec_inspect(exec_id)
                if not isinstance(record, dict) or record.get("Running") is not True:
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.05)
        except Exception as exc:
            self._error("EXEC_TRANSPORT_FAILED", f"docker's exec record could not be read: {exc}")
            return
        if not isinstance(record, dict) or record.get("Running") is not False:
            self._error(
                "EXEC_TRANSPORT_FAILED",
                "docker's exec record does not confirm the exec finished",
            )
            return
        exit_code = record.get("ExitCode")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            self._error(
                "EXEC_TRANSPORT_FAILED",
                f"docker's exec record has no exit code ({exit_code!r})",
            )
            return
        result.exit_code = exit_code
        if failure is not None:
            self._error("EXEC_TRANSPORT_FAILED", f"the exec stream broke mid-call: {failure}")
        elif not reached:
            self._error(
                "EXEC_TRANSPORT_FAILED",
                f"docker exec did not reach the cage (exit {exit_code})",
            )

    def exec(self, argv: Sequence[str]) -> CommandResult:
        """Run argv inside the open cage via the SDK exec API; the cage stays up.

        The image's `timeout -s KILL` wrapper is the in-container kill on the
        tool deadline: the cage must survive the call, so the deadline cannot
        stop the container the way run_command's deadline does. That wrapper
        kills only its direct child, so every call then runs a trusted
        kill of every other live cage process (see _kill_lingering). The host
        capture deadline is only a backstop for a hung exec stream, and exit
        137 is the busybox wrapper's KILL result.
        """
        if (
            isinstance(argv, (str, bytes))
            or not argv
            or any(not isinstance(arg, str) or "\0" in arg for arg in argv)
        ):
            raise ValueError("command must be a nonempty argument sequence, never a shell string")
        if not self._open or self._cage is None:
            message = "the cage must be started with open_cage before exec"
            self._error("EXEC_ERROR", message)
            raise SandboxError(message)
        if self._sinks_collected or self._honeytoken_scanned:
            # Output produced after collection would skip the honeytoken search.
            message = "exec is not allowed after the sinks are collected"
            self._error("EXEC_ERROR", message)
            raise SandboxError(message)
        try:
            running = self._cage_running()
        except Exception as exc:
            self._error("EXEC_ERROR", str(exc))
            raise SandboxError(str(exc)) from exc
        if not running:
            message = "the cage is not running"
            self._error("EXEC_ERROR", message)
            raise SandboxError(message)
        seconds = max(1, math.ceil(self.config.tool_timeout_seconds))
        wrapped = [
            "sh",
            "-c",
            f"printf '%s\\n' {EXEC_START_MARKER} >&2; exec timeout -s KILL {seconds} \"$@\"",
            "baitwatch-exec",
            *argv,
        ]
        try:
            exec_id = self._client.api.exec_create(
                self._cage.id,
                wrapped,
                user="65532:65532",
                workdir="/repo",
                privileged=False,
                stdin=False,
                tty=False,
            )["Id"]
        except Exception as exc:
            self._error("EXEC_ERROR", str(exc))
            raise SandboxError(str(exc)) from exc
        try:
            result, stream_failure = capture_exec(
                self._client.api,
                exec_id,
                argv,
                timeout_seconds=self.config.tool_timeout_seconds + 3,
                max_output_bytes=self.config.max_output_bytes,
            )
        except Exception as exc:
            self._error("EXEC_ERROR", str(exc))
            raise SandboxError(str(exc)) from exc
        reached = result.stderr.startswith(EXEC_START_MARKER)
        self._confirm_exec(exec_id, result, reached, stream_failure)
        if result.exit_code == 137 and not result.timed_out:
            result.timed_out = True
        if reached:
            result.stderr = result.stderr[len(EXEC_START_MARKER) :].removeprefix("\n")
        try:
            running = self._cage_running()
        except Exception as exc:
            self._error("EXEC_ERROR", str(exc))
            return result
        if not running:
            # The overall cage deadline fired mid-call; the scan must not
            # become complete as if the decoy had finished.
            self._error("CAGE_EXITED", "the cage stopped during a tool call")
        else:
            self._kill_lingering()
            if result.timed_out:
                self._error(
                    "EXEC_TIMEOUT",
                    f"tool call exceeded its {self.config.tool_timeout_seconds:g}s limit",
                )
            if result.output_truncated:
                self._error(
                    "EXEC_OUTPUT_TRUNCATED",
                    f"tool call exceeded its {self.config.max_output_bytes} byte output limit",
                )
        return result

    def run_command(self, command: Sequence[str]) -> CommandResult:
        if (
            isinstance(command, (str, bytes))
            or not command
            or any(not isinstance(arg, str) or "\0" in arg for arg in command)
        ):
            raise ValueError("command must be a nonempty argument sequence, never a shell string")
        if self._command_started:
            raise SandboxError("one command per sandbox; create a new sandbox for another run")
        self._command_started = True
        result = CommandResult(command=list(command))
        # Sink or trace failures that happened before this command must not
        # decide whether the command itself ran cleanly.
        errors_before = len(self.evidence.errors)
        try:
            # Writable so cage file changes can be traced; the original
            # repository is never mounted, only this disposable copy.
            self._cage = self._create(
                self.config.image,
                command,
                "cage",
                self.cage_ip,
                mounts=[Mount("/repo", str(self.staged_path), type="bind", read_only=False)],
                working_dir="/repo",
            )

            def stop() -> None:
                try:
                    self._cage.kill()
                except NotFound:
                    pass
                except DockerException:
                    self._cage.reload()
                    if self._cage.status == "running":
                        raise

            result = capture_attached(
                ["docker", "--host", self._docker_host, "start", "--attach", self._cage.id],
                command,
                timeout_seconds=self.config.timeout_seconds,
                max_output_bytes=self.config.max_output_bytes,
                stop_container=stop,
            )
            self._cage.reload()
            state = self._cage.attrs["State"]
            if state["Status"] not in {"exited", "dead"}:
                self._error("CONTAINER_STATE", "command did not reach a terminal container state")
            else:
                # Timeouts and truncation already kill the attach client, so only
                # a mismatch on a clean run means its stream failed.
                if (
                    not result.timed_out
                    and not result.output_truncated
                    and result.exit_code != state["ExitCode"]
                ):
                    self._error(
                        "ATTACH_FAILED",
                        f"attach client exited {result.exit_code}, "
                        f"container exited {state['ExitCode']}",
                    )
                result.exit_code = state["ExitCode"]
                if state.get("OOMKilled"):
                    self._error("CONTAINER_OOM", "container exhausted its memory limit")
            if result.timed_out:
                self._error("COMMAND_TIMEOUT", "command exceeded its execution deadline")
            if result.output_truncated:
                self._error("OUTPUT_TRUNCATED", "command exceeded its combined output limit")
            if result.exit_code != 0 and len(self.evidence.errors) == errors_before:
                self._error("COMMAND_FAILED", f"container exited with code {result.exit_code}")
            if len(self.evidence.errors) == errors_before:
                self.evidence.components.sandbox = State.COMPLETE
        except Exception as exc:
            self._error("COMMAND_ERROR", str(exc))
        self.evidence.tool_log.append(result)
        return result

    def _remove_container(self, container, handled: set) -> bool:
        handled.add(container.id)
        try:
            container.remove(force=True, v=True)
        except NotFound:
            pass
        except Exception as exc:
            self._error("CONTAINER_CLEANUP", str(exc))
            return False
        return True

    def _sweep_labelled_containers(self, handled: set) -> bool:
        if self._client is None:
            return True
        try:
            strays = self._client.containers.list(
                all=True,
                filters={"label": f"{SCAN_LABEL}={self.evidence.scan_id}"},
                ignore_removed=True,
            )
        except Exception as exc:
            self._error("CONTAINER_CLEANUP", str(exc))
            return False
        all_removed = True
        for container in strays:
            if container.id in handled:
                continue
            if not self._remove_container(container, handled):
                all_removed = False
        return all_removed

    def _sweep_labelled_networks(self, handled: set) -> None:
        if self._client is None:
            return
        try:
            strays = self._client.networks.list(
                filters={"label": f"{SCAN_LABEL}={self.evidence.scan_id}"}
            )
        except Exception as exc:
            self._error("NETWORK_CLEANUP", str(exc))
            return
        for network in strays:
            if network.id in handled:
                continue
            try:
                network.remove()
            except NotFound:
                pass
            except Exception as exc:
                self._error("NETWORK_CLEANUP", str(exc))

    def _unlock_staging(self) -> tuple[bool, bool]:
        """Let the cage's own uid lift the mode bits it used to lock the staged
        tree against the host user; symlinks are never followed.

        Returns (unlocked, helper removed). A helper whose create reply was lost
        has no handle here, so it counts as not removed and the caller sweeps.
        """
        try:
            container = self._create(
                self.config.sink_image,
                ["python", "-I", "/trace/trace.py", "unlock", "/repo"],
                "unlock-staging",
                None,
                networked=False,
                mounts=[
                    Mount("/repo", str(self.staged_path), type="bind", read_only=False),
                    Mount("/trace/trace.py", str(TRACE_SCRIPT), type="bind", read_only=True),
                ],
            )
        except Exception:
            return False, False
        try:
            container.start()
            status = container.wait(timeout=self.config.timeout_seconds)
            code = status.get("StatusCode") if isinstance(status, dict) else None
            return code == 0, self._remove_container(container, set())
        except Exception:
            return False, self._remove_container(container, set())

    def _remove_staging(self) -> bool:
        """Returns True when an unlock helper was attempted and may need sweeping."""
        try:
            shutil.rmtree(self._temporary)
            return False
        except Exception as first:
            error = str(first)
        if not self._command_started:
            self._error("STAGING_CLEANUP", error)
            return False
        # The cage's uid can lock directories against the host user; only that
        # uid can lift the mode bits. An error is recorded only if the tree
        # still survives, because that is the only leak there is.
        unlocked, removed = self._unlock_staging()
        if not unlocked:
            error = f"{error}; the unlock helper failed"
        if not removed:
            # Retrying against a helper that is still mounted would only hide
            # the leak from the label sweep that follows.
            self._error("STAGING_CLEANUP", f"{error}; the unlock helper was not removed")
            return True
        try:
            shutil.rmtree(self._temporary)
        except Exception as exc:
            self._error("STAGING_CLEANUP", f"{exc}; {error}")
        return True

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        all_removed = True
        handled: set = set()
        for container in reversed(self._containers):
            if not self._remove_container(container, handled):
                all_removed = False
        # A create call can lose its reply while the daemon still makes the
        # resource, so sweep for anything left carrying this scan's label.
        if not self._sweep_labelled_containers(handled):
            all_removed = False
        if self._network is not None:
            handled.add(self._network.id)
            try:
                self._network.remove()
            except NotFound:
                pass
            except Exception as exc:
                self._error("NETWORK_CLEANUP", str(exc))
        self._sweep_labelled_networks(handled)
        staged = self._temporary is not None and all_removed
        helper_used = staged and self._remove_staging()
        # The unlock helper is created after the first sweep, so find one whose
        # create reply was lost before the scan can end.
        if helper_used and not self._sweep_labelled_containers(handled):
            all_removed = False
        if self._client is not None:
            try:
                self._client.close()
            except Exception as exc:
                self._error("CLIENT_CLEANUP", str(exc))
        self._open = False

    def __exit__(self, exc_type, exc, traceback) -> None:
        try:
            if exc is not None:
                self._error("SANDBOX_ABORTED", str(exc))
        finally:
            self.close()


def detonate(
    path: str | Path,
    command: Sequence[str] = ("true",),
    *,
    config: SandboxConfig | None = None,
    backend: LLMBackend | None = None,
    max_steps: int = 20,
) -> RunEvidence:
    """With a backend, run the decoy instead of the plain command.

    The status becomes complete only when every component is complete and no
    errors were recorded; hits never change it (verdict fusion is separate).
    """
    sandbox = Sandbox(path, config)
    try:
        with sandbox:
            try:
                sandbox.start_sinks()
                sandbox.trace_before()
                if backend is None:
                    sandbox.run_command(command)
                else:
                    sandbox.open_cage()
                    # Imported here: run.decoy imports this module for Sandbox.
                    from run.decoy import run_decoy

                    run_decoy(sandbox, backend, max_steps=max_steps)
                    # A failed decoy must never be upgraded: only a clean loop
                    # that left the sandbox component untouched proves the cage ran.
                    if (
                        sandbox.evidence.components.sandbox == State.NOT_RUN
                        and sandbox.evidence.components.decoy == State.COMPLETE
                    ):
                        if sandbox.cage_running():
                            sandbox.evidence.components.sandbox = State.COMPLETE
                        else:
                            sandbox._error(
                                "CAGE_EXITED", "the cage stopped before the decoy completed"
                            )
            finally:
                try:
                    sandbox.collect_sinks()
                finally:
                    sandbox.trace_after()
    except Exception as exc:
        if not sandbox.evidence.errors:
            sandbox._error("DETONATION_ERROR", str(exc))
    if not sandbox.evidence.errors and sandbox.evidence.components.complete():
        sandbox.evidence.status = "complete"
    return sandbox.evidence
