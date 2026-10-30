import hashlib
from pathlib import Path

import docker
import pytest

from run.evidence import RunEvidence
from run.sandbox import SCAN_LABEL, Sandbox, detonate

RUN_TESTS = Path(__file__).parent
IMAGES = ("alpine:3.20", "python:3.12-alpine")


def pytest_collection_modifyitems(config, items):
    # Scoped here so the shared pytest.ini does not put a deadline on READ's suites.
    if not config.pluginmanager.hasplugin("timeout"):
        return
    for item in items:
        if RUN_TESTS in item.path.parents:
            item.add_marker(pytest.mark.timeout(60))


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    (path / "README.md").write_text("A benign fixture.\n")
    return path


# Shared Day 6 chaos helpers. Every chaos case must leave the host repository
# byte-identical and leave behind neither labelled Docker resources nor the
# staging copy, so those checks live here instead of per test file.


class RecordedSandbox(Sandbox):
    """detonate() builds its own Sandbox; this subclass hands the instance back
    for host-side hooks (sink logs, cage container, staged copy) without
    weakening the run."""

    instances: list["RecordedSandbox"] = []

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.sink_log_sizes: dict[str, int] = {}
        type(self).instances.append(self)

    def sink_log_path(self, role: str):
        return self._sink_logs.get(role)

    def kill_sink(self, role: str) -> None:
        self._sinks[role].kill()

    def kill_cage(self) -> None:
        self._cage.kill()

    def close(self) -> None:
        # detonate() removes the staging directory, sink logs included.
        self.sink_log_sizes = {
            role: log.stat().st_size for role, log in self._sink_logs.items() if log.exists()
        }
        super().close()


@pytest.fixture
def recorded_sandbox(monkeypatch):
    RecordedSandbox.instances = []
    monkeypatch.setattr("run.sandbox.Sandbox", RecordedSandbox)
    return RecordedSandbox


@pytest.fixture
def engine():
    client = docker.from_env(timeout=5)
    try:
        client.ping()
        for image in IMAGES:
            client.images.get(image)
        yield client
    finally:
        client.close()


@pytest.fixture
def tree_digest():
    """Digest of paths, link targets and file bytes under the host repository."""

    def digest(root: Path) -> str:
        value = hashlib.sha256()
        for path in sorted(root.rglob("*")):
            value.update(path.relative_to(root).as_posix().encode())
            if path.is_symlink():
                value.update(b"|" + str(path.readlink()).encode())
            elif path.is_file():
                value.update(b"|" + path.read_bytes())
        return value.hexdigest()

    return digest


@pytest.fixture
def assert_no_leftovers(engine):
    def check(evidence) -> None:
        assert not engine.containers.list(
            all=True, filters={"label": f"{SCAN_LABEL}={evidence.scan_id}"}
        )
        assert not engine.networks.list(filters={"label": f"{SCAN_LABEL}={evidence.scan_id}"})

    return check


@pytest.fixture
def assert_staging_gone():
    def check(instance, evidence) -> None:
        staged = instance._temporary
        if staged is None:
            return  # the scan failed before staging created anything
        codes = {error.code for error in evidence.errors}
        assert not staged.exists() or "STAGING_CLEANUP" in codes, staged

    return check


@pytest.fixture
def run_scan(engine, assert_no_leftovers):
    """detonate with one retry when a saturated daemon times out a container
    start; that fails closed as environment noise and is not a scan verdict."""

    def scan(repo, command=("true",), *, config=None, backend_factory=None) -> RunEvidence:
        def attempt() -> RunEvidence:
            backend = backend_factory() if backend_factory is not None else None
            return detonate(repo, command, config=config, backend=backend)

        evidence = attempt()
        if [error.code for error in evidence.errors] == ["SERVICE_START"] and (
            "Read timed out" in evidence.errors[0].message
        ):
            # The retry must not hide the first attempt's leftovers.
            assert_no_leftovers(evidence)
            evidence = attempt()
        return evidence

    return scan
