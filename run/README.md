# RUN

BaitWatch checks a repository for attacks aimed at coding agents before a developer lets an agent work in it. The planned product has two parts. READ runs a detector over the files. RUN executes the repository as a decoy inside an isolated Docker network and records what it tries to reach.

This branch builds the RUN foundation, the Day 2 layers, and the Day 3 decoy. It copies the repository with limits, creates an internal Docker network, runs the DNS and HTTP/TLS sinks and a file trace around a restricted cage command, drives a decoy LLM whose tool calls execute inside the cage, records typed evidence, cleans up, and tests each of these steps. It does not yet include the READ model, honeytoken attribution, the full verdict engine, or agent hooks.

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

## Decoy command

```bash
uv run --no-sync baitwatch-run decoy /path/to/repo --llm scripted:steps.json
uv run --no-sync baitwatch-run decoy /path/to/repo --llm ollama:llama3.2:3b --max-steps 30
```

The decoy is a helpful coding agent told to set up and test the repository following its own instructions — which is exactly how an injected instruction gets followed. Its `read_file`, `list_files` and `run_cmd` tools execute only inside the cage; model API calls leave only from the host. Every tool call, reads included, is recorded in `tool_log`. The `--llm` spec selects the backend (`scripted:PATH`, `ollama:MODEL`, `openai:BASE_URL#MODEL[#ENV_VAR]`); a scripted replay is deterministic and needs no network. Exit code 0 means the evidence is complete — never that the repository is safe.

## Library interface

```python
from run import detonate

evidence = detonate("/path/to/repo", ["echo", "hello"])
assert evidence.status == "incomplete"
```

`Sandbox` is a context manager. `start_sinks()` runs the production DNS and HTTP/TLS sinks, `trace_before()`/`trace_after()` snapshot the staged tree around the command, and `collect_sinks()` reads the sink logs into hits. With a backend, `detonate(..., backend=...)` starts the long-lived decoy cage instead of running a command: `open_cage()` starts it with a self-terminating idle process, `exec(argv)` runs arguments inside it under an in-container kill deadline, and `run_decoy()` in `run/decoy.py` drives the loop. `start_service()` remains for trusted connectivity fixtures. See [the sandbox boundary](SANDBOX.md), [the sinks](sinks/README.md) and [the proposed team contract](CONTRACT.md).

## What the tests check

- From the cage, public TCP, public DNS and name lookups fail, the host's listening services do not answer, and an HTTP service inside the network does.
- The command runs as a non-root user with restricted mounts and resource limits.
- Staging preserves symlinks, rejects hard links and special files, and never copies a host file when a repository file turns into a symlink during the copy.
- Output floods and deadlines stop the container, and nonzero exit codes are kept.
- The scripted decoy's tool calls execute inside the cage, land in `tool_log` in order, and its fake exfil reaches the DNS and HTTP sinks attributed to the cage and shows up in `file_diffs`; a decoy run that only finishes cleanly can make the whole evidence `complete`.
- A tool call that outlives its deadline is killed inside the cage and recorded timed out; forked or backgrounded work from any tool call leaves no live process behind, for compound (`sleep 100; echo done`) and backgrounded (`sleep 100 &`) commands alike.
- The sandbox records setup failures, cleanup failures and subnet conflicts as errors, and `exec` fails closed on a cage that was never opened, has closed, or has exited.
- The schema rejects ALLOW when any evidence is incomplete.

These tests cover the boundary built so far. They do not prove that a container cannot escape, they do not measure prompt-injection detection, and they do not run the whole product. Integration still has to pass on the team's demo machine. The interface stays a proposal until Manan and Aditya review it.
