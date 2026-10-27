import ipaddress
import os
import random
import shutil
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import docker
from docker.errors import APIError, DockerException, NotFound
from docker.types import IPAMConfig, IPAMPool, LogConfig, Mount

from run.capture import capture_attached
from run.evidence import CommandResult, RunError, RunEvidence, State
from run.staging import StagingLimits, stage_repository

SCAN_LABEL = "org.baitwatch.scan-id"
DEFAULT_SUBNET = "10.13.37.0/24"
SUBNET_ATTEMPTS = 16


class SandboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxConfig:
    image: str = "alpine:3.20"
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
    max_output_bytes: int = 64 * 1024
    staging: StagingLimits = field(default_factory=StagingLimits)

    def __post_init__(self) -> None:
        hosts = (self.cage_host, self.dns_host, self.http_host)
        if len(set(hosts)) != 3 or any(
            type(host) is not int or not 2 <= host <= 254 for host in hosts
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
        if type(self.timeout_seconds) not in (int, float):
            raise ValueError("timeout_seconds must be an int or float")
        if not self.image or any(
            value <= 0
            for value in (
                self.memory_bytes,
                self.nano_cpus,
                self.pids_limit,
                self.tmpfs_bytes,
                self.timeout_seconds,
                self.max_output_bytes,
            )
        ):
            raise ValueError("image and positive resource/output/time limits are required")


class Sandbox:
    """One staged copy and one command per instance.

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

    def _error(self, code: str, message: str) -> None:
        # str(exc) can be empty (e.g. TimeoutError()); an empty message would
        # raise ValidationError here and skip the caller's cleanup.
        self.evidence.errors.append(RunError(code=code, message=message[:1000] or code))
        self.evidence.status = "error"
        self.evidence.components.sandbox = State.ERROR

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
            self.evidence.staging_exclusions = stage_repository(
                self.path, self.staged_path, self.config.staging
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

    def _create(self, image: str, command: Sequence[str], role: str, ip: str, *, repo: bool):
        if not self._open or self._client is None or self._network is None:
            raise SandboxError("sandbox is not open")
        self._client.images.get(image)
        config = self.config
        endpoint = self._client.api.create_endpoint_config(ipv4_address=ip)
        container = self._client.containers.create(
            image,
            command=list(command),
            entrypoint=[],
            name=f"{self.name}-{role}",
            labels=self.labels,
            network=self._network.name,
            networking_config={self._network.name: endpoint},
            dns=[self.dns_ip],
            dns_opt=["timeout:1", "attempts:1"],
            dns_search=["."],
            user="65532:65532",
            working_dir="/repo" if repo else "/tmp",
            environment={"HOME": "/tmp", "PYTHONDONTWRITEBYTECODE": "1"},
            mounts=[Mount("/repo", str(self.staged_path), type="bind", read_only=True)]
            if repo
            else [],
            read_only=True,
            privileged=False,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            mem_limit=config.memory_bytes,
            memswap_limit=config.memory_bytes,
            nano_cpus=config.nano_cpus,
            pids_limit=config.pids_limit,
            tmpfs={"/tmp": f"rw,noexec,nosuid,nodev,size={config.tmpfs_bytes},mode=1777"},
            log_config=LogConfig(type="json-file", config={"max-size": "1m", "max-file": "1"}),
            restart_policy={"Name": "no"},
        )
        self._containers.append(container)
        return container

    def start_service(self, role: str, image: str, command: Sequence[str]):
        """Starting a sink container never marks that sink complete."""
        if role not in {"dns", "http"} or role in self._service_roles:
            raise SandboxError("service role must be a unique dns or http sink")
        ip = self.dns_ip if role == "dns" else self.http_ip
        try:
            container = self._create(image, command, role, ip, repo=False)
            container.start()
            self._service_roles.add(role)
            return container
        except Exception as exc:
            self._error("SERVICE_START", str(exc))
            raise SandboxError(str(exc)) from exc

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
        try:
            self._cage = self._create(self.config.image, command, "cage", self.cage_ip, repo=True)

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
            if result.exit_code != 0 and not self.evidence.errors:
                self._error("COMMAND_FAILED", f"container exited with code {result.exit_code}")
            if not self.evidence.errors:
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
        if self._temporary is not None and all_removed:
            try:
                shutil.rmtree(self._temporary)
            except Exception as exc:
                self._error("STAGING_CLEANUP", str(exc))
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
) -> RunEvidence:
    """An exit-0 command still leaves the status incomplete until sinks, decoy and tracing run."""
    sandbox = Sandbox(path, config)
    try:
        with sandbox:
            sandbox.run_command(command)
    except Exception as exc:
        if not sandbox.evidence.errors:
            sandbox._error("DETONATION_ERROR", str(exc))
    return sandbox.evidence
