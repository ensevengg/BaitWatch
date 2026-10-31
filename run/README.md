# RUN

BaitWatch checks a repository for attacks aimed at coding agents before a developer lets an agent work in it. The planned product has two parts. READ runs a detector over the files. RUN executes the repository as a decoy inside an isolated Docker network and records what it tries to reach.

This branch builds the RUN foundation, the Day 2 layers, the Day 3 decoy, the Day 4 fused scan, and Day 5 honeytokens. It copies the repository with limits, creates an internal Docker network, runs the DNS and HTTP/TLS sinks and a file trace around a restricted cage command, plants per-scan fake credentials in the staged copy and detects them in sink and tool output, drives a decoy LLM whose tool calls execute inside the cage, records typed evidence, fuses the READ and RUN layers into one verdict, cleans up, and tests each of these steps. It does not yet include model transcript scanning, the agreed verdict thresholds, or agent hooks.

## Setup on Linux

Install Python 3.12 or later, uv, Docker Engine 28 or later and the Docker CLI. Your user needs access to a local Linux Docker daemon. Then run:

```bash
uv sync --frozen --extra dev --extra cpu
docker pull alpine:3.20
docker pull python:3.12-alpine
uv run --no-sync python -m run.cage build
uv run --no-sync ruff check run tests/run tests/e2e
uv run --no-sync ruff format --check run tests/run tests/e2e
uv run --no-sync pytest -m "not gpu" tests/run tests/e2e
```

The default cage is `baitwatch-cage:1`, built only from the trusted
`run/cage/Dockerfile`. Build from a trusted BaitWatch checkout, never from a
repository being scanned. The build context contains only `run/cage`; it copies
no repository files into the image. The Python 3.12 Alpine base is pinned by
digest. APK resolves bash, ca-certificates, curl, git, make, nodejs and npm at
build time; Python and pip come from the base. Rebuild deliberately to update
APK packages. The build needs host network access; scans never build or pull
images and the cage keeps its existing network and resource restrictions.
A missing cage image fails closed with a build instruction. Explicit trusted
`--image` overrides still work, including the smaller test images above.

Plain `uv sync` or pip installs the default torch, which is CUDA-capable on Linux; `--extra cpu` keeps the CPU build for CI and machines without a GPU.

`bash run/check.sh` runs `uv sync --frozen --extra dev --extra cpu`, then lint, format and tests with `uv run --no-sync`. `bash run/check.sh unit` runs only the unit tests.

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
contact outside the package registries is BLOCK; package-registry lookups (the
exact hosts listed below) are exempt only for validated plain DNS and
hello-only TLS; other registry contacts are counted as attempts, not
exfiltration. A
honeytoken sent over DNS, HTTP or TLS is BLOCK; a decoy that only read one
(`tool_log`) is FLAG.

## Measuring the decoy pwn rate

On the demo machine (Manan's laptop), with Docker and the cage image ready:

```bash
export BAITWATCH_DECOY_BASE_URL="https://<primary-endpoint>/v1"   # e.g. Muse Spark endpoint
export BAITWATCH_DECOY_MODEL="<primary-model>"
export BAITWATCH_DECOY_API_KEY_ENV="BAITWATCH_DECOY_API_KEY"      # NAME of the env var holding the key
export BAITWATCH_DECOY_API_KEY="..."                              # value lives only in the environment
export BAITWATCH_DECOY_FALLBACK_BASE_URL="http://127.0.0.1:11434/v1"  # local llama-server/Ollama
export BAITWATCH_DECOY_FALLBACK_MODEL="llama3.1:8b"
uv run --no-sync python -m run.pwnrate --repo attacks/repos/readme-bait-curl --runs 10 \
  --llm "openai:${BAITWATCH_DECOY_BASE_URL}#${BAITWATCH_DECOY_MODEL}#${BAITWATCH_DECOY_API_KEY_ENV}" \
  --llm-fallback "ollama:${BAITWATCH_DECOY_FALLBACK_MODEL}" \
  --max-steps 20 --max-tokens 100000 --max-seconds 120 \
  --out pwnrate.json --markdown pwnrate.md
uv run --no-sync pytest -m gpu tests/run/test_pwnrate_gpu.py -q   # same env; skips when unset
```

Env var names: `BAITWATCH_DECOY_BASE_URL`, `BAITWATCH_DECOY_MODEL`,
`BAITWATCH_DECOY_API_KEY_ENV` (a variable *name*, never a key value in specs,
logs or reports), `BAITWATCH_DECOY_FALLBACK_BASE_URL`,
`BAITWATCH_DECOY_FALLBACK_MODEL`, and `BAITWATCH_PWNRATE_RUNS` (default 10).
The report JSON and markdown table give, per repo: runs, runs with a counted
sink hit, runs with honeytoken hits, verdict counts, pwn rate, p50/p95 latency,
tokens used and fallback count. A counted sink hit is a contact verdict fusion
counts (exfiltration or a registry attempt): validated plain registry DNS and
hello-only registry TLS do not count, while registry HTTP and non-plain
registry contacts do. A run is marked `suspect` when the fallback
answered every turn, so its numbers belong to the fallback model. Repository code only runs inside the cage;
model calls leave only from the host.

Spend caps (per scan, configurable on `baitwatch scan`, `baitwatch-run decoy`
and `run.pwnrate`): `--max-steps` (turns and total tool calls, default 20),
`--max-tokens` (prompt+completion, from the API `usage` field when present,
else a conservative character estimate; default 100000; each request asks for
at most the remaining budget, capped at 4096 completion tokens) and `--max-seconds`
(decoy wall time, default 120). Hitting any cap records
`DECOY_STEP_BUDGET`, `DECOY_TOKEN_BUDGET` or `DECOY_TIME_BUDGET`, marks the
decoy component `error`, and can never ALLOW — matching step-budget
exhaustion. Evidence records `decoy_total_tokens`, `decoy_backend` and
`decoy_fallback_count`.

Fallback: `--llm-fallback SPEC` wraps the primary backend. On connection
error, HTTP 5xx, HTTP 429, timeout or a missing key it retries the same turn
on the fallback (temperature 0, fixed seed 0 for the local Llama backend via
`ollama:`/`openai:` specs). A fallback answer is recorded in
`decoy_backend`/`decoy_fallback_count` and is not by itself an error; if both
backends fail the decoy records `DECOY_FAILED` and the scan stays non-ALLOW.

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
- The fusion flags or blocks on every incomplete READ or RUN, blocks on sink contacts outside the package registries, and only allows a clean READ plus a complete decoy run without disallowed evidence — the local attack fixtures block, the benign fixture allows, and every report validates against the schema.
- The schema rejects ALLOW when any evidence is incomplete.

These tests cover the boundary built so far. They do not prove that a container cannot escape, they do not measure prompt-injection detection, and they do not run the whole product. Integration still has to pass on the team's demo machine. The interface stays a proposal until Manan and Aditya review it.

Literal-IP connections and unlisted ports are a known observation gap: blocked
network access does not necessarily create a sink hit, so otherwise clean
scans can still ALLOW them. See [the uncovered channels](SANDBOX.md#known-limits).

Plain DNS contacts to exact pypi.org, files.pythonhosted.org,
registry.npmjs.org, registry.yarnpkg.com, proxy.golang.org, sum.golang.org,
index.crates.io, static.crates.io, rubygems.org and index.rubygems.org names
remain in evidence but do not affect the verdict. Matching ignores case and a
trailing dot. The query type must be a standard type named by the DNS sink;
unknown types and unclassified evidence remain FLAG. Existing DNS validation
still requires a single question and no extra sections except one valid EDNS0
OPT with empty data or one 8-byte client cookie. Odd EDNS and incomplete
captures still BLOCK, including on a registry host.

Plaintext registry HTTP remains an attempt (FLAG for the existing complete
GET/HEAD shape; uploads, queries and incomplete captures still BLOCK).
A registry TLS contact is likewise exempt only with an exact registry SNI, a
complete capture, and trusted hello-only evidence. The TLS sink records the
first record length (`hello_record_length`), the total bytes received before
it closed the connection (`total_bytes`, after the sink answers a validated
hello with a fatal alert and then drains for at most one second and 16 KiB
past the hello, until the peer closes or the window expires), the count and a
bounded hex prefix of any bytes after that record, and `hello_only`.
`hello_only` is true only when the received bytes are exactly one TLS record
holding a single complete ClientHello and the peer reached EOF or reset
inside that window; extra records, coalesced or trailing bytes, a hello split
across records, unparseable, truncated or oversize captures, and a peer still
connected when the window expires are all false. TLS hits carry this as
`NetworkHit.hello_only` (also in the JSON schema); records without it are
never exempt. Registry TLS without that proof remains an attempt (FLAG);
missing/mismatched SNI and incomplete captures still BLOCK.
Known limit: a validated hello-only ClientHello can still carry up to about
2 KB of client-chosen bytes to an exact registry host, across its random,
session id, cipher and compression lists and extension bytes. The honeytoken
search finds those bytes in plain, URL-encoded, base64, base32 and hex forms;
XOR or other custom encodings and a token split across two separate
connections are not detected. In a real environment those bytes reach only
the registry host.

Non-registry contacts and network honeytoken hits always BLOCK. A honeytoken
hit over DNS, HTTP or TLS takes precedence over any registry exemption.
Registry-attempt reasons remain bounded.

Cage file writes have an 8 MiB per-file hard limit by default. Post-run
size/entry checks record errors, but aggregate disk use during execution is
not quota-bound; see [repository write limits](SANDBOX.md#repository-write-limits).

JSON output escapes all non-ASCII characters. Human reports escape terminal,
bidi and zero-width controls. The decoy checks its lifetime before each tool
call; model turns and total tool calls each share the configured max-steps cap.
A reply with many calls cannot multiply that budget. API keys require HTTPS
except for exact localhost or 127.0.0.1 endpoints.

File-change fusion BLOCKs agent-control and persistence edits, including nested
agent instructions, settings, MCP configuration and Git hooks. HOME is a fresh
traced directory at `/cage/home`; shell startup and configuration changes there
BLOCK, while cache writes alone remain eligible for ALLOW. Repository deletions
FLAG, or BLOCK at 50% of staged regular files or more than 200 files, excluding
build/cache trees and planted bait. See [file-change rules](CONTRACT.md#file-change-rules).

Before the first trace snapshot, a trusted, network-disabled helper creates an
empty Git repository in the staged copy with templates disabled. The original
`.git` stays excluded from staging. Unchanged synthetic metadata is baseline,
not a repository file or growth; subsequent `.git/hooks` and `.git/config`
changes remain traced and BLOCK. The image trusts only `/repo` for Git ownership
checks because the staging owner differs from the cage uid. A failed initialization keeps the scan non-ALLOW.
A `run_cmd` that exits 126/127 or emits a shell command-not-found diagnostic does
not establish execution coverage. If no setup program ran, fusion FLAGs; ordinary
program failures (such as failing tests) still count as executed.

Common executables do not imply installed project dependencies. For example,
`python -m pytest` can start Python and fail because pytest is absent; this
still counts as a program execution. A missing or non-executable setup command
followed by such a real program failure can therefore remain eligible for
ALLOW. Source executable bits are preserved. To exercise a readable shell
script without its executable bit, the decoy can invoke `sh script.sh` inside
the cage.

The runner sets pip and npm retries to zero and fetch timeouts to three seconds,
with update checks, npm audit/funding requests, and interactive pip/Git prompts
disabled. Git HTTP transfers abort after three seconds below one byte per second.
The trusted image precompiles Python modules so pip startup does not spend the
tool budget compiling imports on the read-only filesystem. These are overridable
defaults, not security controls. Curl uses its normal behavior: the sinks answer
HTTP and terminate TLS promptly; there is no curl timeout environment variable.
Network isolation, sinks, and execution limits remain enforced independently.
An ordinary install failure is recorded as a nonzero program exit; a real
deadline kill still yields at least FLAG. Registry contacts without a plain
DNS or hello-only TLS exemption remain FLAG under the current verdict policy,
and other sink contacts remain BLOCK. Neither
an install failure nor a registry lookup proves an install lifecycle payload ran.
