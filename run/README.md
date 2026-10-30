# RUN

BaitWatch checks a repository for attacks aimed at coding agents before a developer lets an agent work in it. The planned product has two parts. READ runs a detector over the files. RUN executes the repository as a decoy inside an isolated Docker network and records what it tries to reach.

This branch builds the RUN foundation, the Day 2 layers, the Day 3 decoy, the Day 4 fused scan, and Day 5 honeytokens. It copies the repository with limits, creates an internal Docker network, runs the DNS and HTTP/TLS sinks and a file trace around a restricted cage command, plants per-scan fake credentials in the staged copy and detects them in sink and tool output, drives a decoy LLM whose tool calls execute inside the cage, records typed evidence, fuses the READ and RUN layers into one verdict, cleans up, and tests each of these steps. It does not yet include model transcript scanning, the agreed verdict thresholds, or agent hooks.

## Setup on Linux

Install Python 3.12 or later, uv, Docker Engine 28 or later and the Docker CLI. Your user needs access to a local Linux Docker daemon. Then run:

```bash
uv sync --frozen --extra dev --extra cpu
docker pull alpine:3.20
docker pull python:3.12-alpine
uv run --no-sync ruff check run tests/run tests/e2e
uv run --no-sync ruff format --check run tests/run tests/e2e
uv run --no-sync pytest -m "not gpu" tests/run tests/e2e
```

Plain `uv sync` or pip installs the default torch, which is CUDA-capable on Linux; `--extra cpu` keeps the CPU build for CI and machines without a GPU.

`bash run/check.sh` runs lint, format and tests against the installed environment; it does not sync dependencies. `bash run/check.sh unit` runs only the unit tests.

On a machine without Docker, run the unit tests with `uv run --no-sync pytest -m "not docker and not gpu" tests/run`. The full gate needs Docker. If the daemon or an image is missing, the Docker tests fail instead of skipping.

Each scan creates its own network. Automatic selection tries the default subnet `10.13.37.0/24` first and falls back to other subnets under `10.13.0.0/16` when Docker reports the range is taken, so scans can run at the same time. A configured subnet is used as written and never falls back. A scan never deletes another network to free a subnet. If every candidate subnet is taken, the scan records an error.

## Diagnostic command

```bash
uv run --no-sync baitwatch-run sandbox /path/to/repo -- echo hello
uv run --no-sync baitwatch-run sandbox --image python:3.12-alpine /path/to/repo -- python -c 'print("hello")'
```

Only the arguments after `--` run, and they run inside the container. The host shell does not expand them. To use shell syntax, pass a shell command explicitly, for example `sh -c 'echo hello'`.

The command prints RUN evidence. Exit code 2 means the diagnostics are incomplete, and exit code 3 means an operational error. Neither code gives an agent permission to proceed. A container that exits 0 still leaves the scan incomplete, because the other components have not run. There is still no `install` command.

## Decoy command

```bash
uv run --no-sync baitwatch-run decoy /path/to/repo --llm scripted:steps.json
uv run --no-sync baitwatch-run decoy /path/to/repo --llm ollama:llama3.2:3b --max-steps 30
```

The decoy is a helpful coding agent told to set up and test the repository following its own instructions — which is exactly how an injected instruction gets followed. Its `read_file`, `list_files` and `run_cmd` tools execute only inside the cage; model API calls leave only from the host. Every tool call, reads included, is recorded in `tool_log`. The `--llm` spec selects the backend (`scripted:PATH`, `ollama:MODEL`, `openai:BASE_URL#MODEL[#ENV_VAR]`); a scripted replay is deterministic and needs no network. Exit code 0 means complete evidence without sink or honeytoken hits — never that the repository is safe. Hits or incomplete evidence exit 2; operational errors exit 3.

## Scan command

```bash
uv run --no-sync baitwatch scan /path/to/repo --llm scripted:steps.json --json verdict.json
uv run --no-sync baitwatch scan /path/to/repo --llm ollama:llama3.2:3b
```

`baitwatch scan` is the fused CLI: it runs the READ detector over the files and
the RUN decoy (same `--llm` spec and cage as `baitwatch-run decoy`) in one pass,
then fuses both into a single `VerdictReport`. `--llm` is required — without a
decoy the scan can never be complete, so use `baitwatch-run sandbox` for
diagnostics instead. The verdict JSON goes to stdout, or to `--json PATH` (the
human report then goes to stdout and the JSON to the file); when the JSON goes
to stdout, the human report goes to stderr. Every report validates against
[docs/verdict.schema.json](../docs/verdict.schema.json).

Exit codes: 0 ALLOW, 4 FLAG, 5 BLOCK, 3 operational error (invalid configuration or repository path, bad `--llm` spec,
unwritable `--json` path; the same code `baitwatch-run` uses). Codes 1 and 2
stay reserved for a crash or a CLI usage error and never mean a verdict. No
exit code permits an agent to proceed on its own. ALLOW means READ is clean
and the RUN decoy completed without verdict-triggering evidence, subject to
the observation limits below; it does not establish that the repository is safe.

The fusion in `run/verdict.py` is provisional until the thresholds are agreed
with the READ owner. Its fixed rules: any exception, timeout, truncated scan,
missing component, incomplete READ, or RUN error is at least FLAG;
step-budget exhaustion and killed background work are errors; a decoy without
an executed `run_cmd`, or staging exclusions beyond the top-level `.git`
directory or regular file, also FLAG. READ runs with strict coverage, and its
partial/truncated statistics prevent ALLOW. READ-skipped directories that RUN copies (including
build, dist and target) also prevent ALLOW; paths staging already omits are
handled by fusion, with only top-level `.git` exempt; any sink
contact or honeytoken hit outside the package registries is BLOCK; package-
registry lookups (the exact hosts listed below) are counted as attempts, not
exfiltration; honeytoken hits are always BLOCK (the generator arrives in a
later milestone, so the field is empty today).

## Library interface

```python
from run import detonate

evidence = detonate("/path/to/repo", ["echo", "hello"])
assert evidence.status == "incomplete"
```

`Sandbox` is a context manager. `start_sinks()` runs the production DNS and HTTP/TLS sinks, `trace_before()`/`trace_after()` snapshot the staged tree around the command, and `collect_sinks()` reads the sink logs into hits. With a backend, `detonate(..., backend=...)` starts the long-lived decoy cage instead of running a command: `open_cage()` starts it with a self-terminating idle process, `exec(argv)` runs arguments inside it under an in-container kill deadline, and `run_decoy()` in `run/decoy.py` drives the loop. `start_service()` remains for trusted connectivity fixtures. See [the sandbox boundary](SANDBOX.md), [the sinks](sinks/README.md) and [the proposed team contract](CONTRACT.md).

## What the tests check

- From the cage, public TCP, public DNS fail; with the DNS sink active, names resolve to the HTTP sink, the host's listening services do not answer, and an HTTP service inside the network does.
- The command runs as a non-root user with restricted mounts and resource limits.
- Staging preserves symlinks, rejects hard links and special files, and never copies a host file when a repository file turns into a symlink during the copy.
- Output floods and deadlines stop the container, and nonzero exit codes are kept.
- The scripted decoy's tool calls execute inside the cage, land in `tool_log` in order, and its fake exfil reaches the DNS and HTTP sinks attributed to the cage and shows up in `file_diffs`; a decoy run that only finishes cleanly can make the whole evidence `complete`.
- Honeytokens are generated per scan in shapes no provider's scanner matches, planted only in the staged copy before the first snapshot, and a leak to a sink or into tool output becomes a `HoneytokenHit` that forbids `ALLOW`; a hit carries only the token id, though the fake value can still appear in quoted tool output and sink detail, and a benign scan records none.
- A tool call that outlives its deadline is killed inside the cage and recorded timed out; forked or backgrounded work from any tool call leaves no live process behind, for compound (`sleep 100; echo done`) and backgrounded (`sleep 100 &`) commands alike.
- The sandbox records setup failures, cleanup failures and subnet conflicts as errors, and `exec` fails closed on a cage that was never opened, has closed, or has exited.
- The fusion flags or blocks on every incomplete READ or RUN, blocks on sink contacts outside the package registries, and only allows a clean READ plus a complete, contact-free decoy run — the local attack fixtures block, the benign fixture allows, and every report validates against the schema.
- The schema rejects ALLOW when any evidence is incomplete.

These tests cover the boundary built so far. They do not prove that a container cannot escape, they do not measure prompt-injection detection, and they do not run the whole product. Integration still has to pass on the team's demo machine. The interface stays a proposal until Manan and Aditya review it.

Literal-IP connections and unlisted ports are a known observation gap: blocked
network access does not necessarily create a sink hit, so otherwise clean
scans can still ALLOW them. See [the uncovered channels](SANDBOX.md#known-limits).

Registry downgrades apply only to exact pypi.org, files.pythonhosted.org,
registry.npmjs.org, registry.yarnpkg.com, proxy.golang.org, sum.golang.org,
index.crates.io, static.crates.io, rubygems.org and index.rubygems.org names:
DNS questions, TLS SNI, or HTTP GET/HEAD with no body, query or incomplete
capture. Subdomains and uploads BLOCK. Registry-attempt reasons are bounded.

Cage file writes have an 8 MiB per-file hard limit by default. Post-run
size/entry checks record errors, but aggregate disk use during execution is
not quota-bound; see [repository write limits](SANDBOX.md#repository-write-limits).

JSON output escapes all non-ASCII characters. Human reports escape terminal,
bidi and zero-width controls. The decoy checks its lifetime before each tool
call; model turns and total tool calls each share the configured max-steps cap.
A reply with many calls cannot multiply that budget. API keys require HTTPS
except for exact localhost or 127.0.0.1 endpoints.

File changes are a known verdict gap: fusion currently ignores `file_diffs`,
including edits to `.claude/`, `AGENTS.md`, `.vscode/` and `.mcp.json`.
`HOME=/tmp` writes, including dotfiles, are not traced. These actions can still
ALLOW when the remaining evidence is clean. File-change verdict rules and
tracing HOME writes are planned work; see [known limits](SANDBOX.md#known-limits).
