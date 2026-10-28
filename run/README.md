# RUN

BaitWatch checks a repository for attacks aimed at coding agents before a developer lets an agent work in it. The planned product has two parts. READ runs a detector over the files. RUN executes the repository as a decoy inside an isolated Docker network and records what it tries to reach.

This branch builds the RUN foundation plus the Day 2 layers. It copies the repository with limits, creates an internal Docker network, runs the DNS and HTTP/TLS sinks and a file trace around a restricted cage command, records typed evidence, cleans up, and tests each of these steps. It does not yet include the READ model, the LLM decoy (added in PR #12), honeytoken attribution, the full verdict engine, or agent hooks. The PR #12 decoy trial against repo #1 produced **0/10 bites**; see `docs/DECOY_TRIAL.md`.

## Setup on Linux

Install Python 3.12 or later, uv, Docker Engine 28 or later and the Docker CLI. Your user needs access to a local Linux Docker daemon. Then run:

```bash
uv sync --frozen --extra dev --extra cpu
docker pull alpine:3.20
docker pull python:3.12-alpine
uv run --no-sync ruff check run tests/run
uv run --no-sync ruff format --check run tests/run
uv run --no-sync pytest -m "not gpu" tests/run
```

Plain `uv sync` or pip installs the default torch, which is CUDA-capable on Linux; `--extra cpu` keeps the CPU build for CI and machines without a GPU.

`bash run/check.sh` runs the same steps. `bash run/check.sh unit` runs only the unit tests.

On a machine without Docker, run the unit tests with `uv run --no-sync pytest -m "not docker and not gpu" tests/run`. The full gate needs Docker. If the daemon or an image is missing, the Docker tests fail instead of skipping.

Each scan creates its own network. Automatic selection tries the default subnet `10.13.37.0/24` first and falls back to other subnets under `10.13.0.0/16` when Docker reports the range is taken, so scans can run at the same time. A configured subnet is used as written and never falls back. A scan never deletes another network to free a subnet. If every candidate subnet is taken, the scan records an error.

## Diagnostic command

```bash
uv run --no-sync baitwatch-run sandbox /path/to/repo -- echo hello
uv run --no-sync baitwatch-run sandbox --image python:3.12-alpine /path/to/repo -- python -c 'print("hello")'
```

Only the arguments after `--` run, and they run inside the container. The host shell does not expand them. To use shell syntax, pass a shell command explicitly, for example `sh -c 'echo hello'`.

The command prints RUN evidence. Exit code 2 means the diagnostics are incomplete, and exit code 3 means an operational error. Neither code gives an agent permission to proceed. A container that exits 0 still leaves the scan incomplete, because the other components have not run. This milestone has no `scan` or `install` command.

## Library interface

```python
from run import detonate

evidence = detonate("/path/to/repo", ["echo", "hello"])
assert evidence.status == "incomplete"
```

`Sandbox` is a context manager. `start_sinks()` runs the production DNS and HTTP/TLS sinks, `trace_before()`/`trace_after()` snapshot the staged tree around the command, and `collect_sinks()` reads the sink logs into hits. `start_service()` remains for trusted connectivity fixtures. See [the sandbox boundary](SANDBOX.md), [the sinks](sinks/README.md) and [the proposed team contract](CONTRACT.md).

## What the tests check

- From the cage, public TCP, public DNS and name lookups fail, the host's listening services do not answer, and an HTTP service inside the network does.
- The command runs as a non-root user with restricted mounts and resource limits.
- Staging preserves symlinks, rejects hard links and special files, and never copies a host file when a repository file turns into a symlink during the copy.
- Output floods and deadlines stop the container, and nonzero exit codes are kept.
- The sandbox records setup failures, cleanup failures and subnet conflicts as errors.
- The schema rejects ALLOW when any evidence is incomplete.

These tests cover the boundary built so far. They do not prove that a container cannot escape, they do not measure prompt-injection detection, and they do not run the whole product. Integration still has to pass on the team's demo machine. The interface stays a proposal until Manan and Aditya review it.
