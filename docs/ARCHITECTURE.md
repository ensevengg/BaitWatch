# Architecture

BaitWatch checks a repository for prompt-injection attacks aimed at AI coding agents. This page explains how the parts fit together, what each one trusts, and what it does not catch. The component docs linked at the end have the full detail.

## Two ways to run it

| | Agent hook | `baitwatch scan` |
|---|---|---|
| When | Every prompt, and every `Bash`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `WebFetch`, `Read` or `Grep` call in Claude Code | On demand, before you trust a repo |
| Layers | READ | READ and RUN |
| Verdicts | allow, ask, block | ALLOW, FLAG, BLOCK |
| Needs | the detector checkpoint, optional `META_API_KEY` | the same, plus Linux, Docker Engine 28 or later, and a decoy model |
| Code | `hooks/` | `run/scan_cli.py`, `run/verdict.py` |

```
Everyday use
  prompt ──► Gate A: READ scans the repo ──► allow / ask / block
  matched tool call ──► Gate B: repo verdict + tool policy + scan-on-open ──► allow / ask / block

Deeper scan
  repo ──► READ (files) ─┐
                         ├──► fusion ──► ALLOW / FLAG / BLOCK
  repo ──► RUN (decoy) ──┘
```

The hook does not run RUN. Starting a Docker sandbox and a decoy model on every prompt would be too slow, so RUN is a separate, deeper check.

## Components

| Component | What it does |
|---|---|
| `read/` | Reads the files: decodes hidden text, scores it with a fine-tuned detector, and asks the Muse Spark judge about suspicious parts |
| `run/` | Runs the repo in a Docker sandbox with a decoy agent, watches the network and files, and fuses READ and RUN into one verdict |
| `hooks/` | Claude Code hook: Gate A on prompts, Gate B on tool calls, the verdict cache and approvals |
| `attacks/` | 17 attack repos and 5 harmless twins, the obfuscation transforms and decoders, and the harness that scores them |
| `tests/` | One suite per component, plus end-to-end tests |
| `docs/` | The verdict schema, hook docs, results and reports |

## READ: reading the files

```
walk ──► decode ──► chunk ──► detector ──► judge ──► findings
```

1. **Walk** (`read/walk.py`). Lists files without following links out of the repo, and sorts them into priority tiers (`read/tiers.py`). Tier 0 and 1 are the files an agent is most likely to load: agent instruction files such as `AGENTS.md` and `CLAUDE.md`, configs, shallow READMEs, manifests and workflows. Tier 2 is other docs and scripts, and tier 3 is source code. The first scan skips generated files such as lockfiles and bundles, and the hook checks them when an agent opens them.
2. **Decode** (`read/decoders.py`, plus `attacks/decoders.py`). Turns each file into extra views: base64 blobs, HTML comments, invisible Unicode and the other channels the attack transforms use. Each view is scored alongside the original text, so a payload hidden in one of them is still read.
3. **Chunk** (`read/chunking.py`). Splits each view into windows of up to 512 tokens.
4. **Detector** (`read/detector.py`). A fine-tuned Llama Prompt Guard 2 (86M) scores each window. The checkpoint lives outside the repo. `read/model_config.json` pins it by SHA-256 and holds its thresholds.
5. **Judge** (`read/judge.py`). Muse Spark reads flagged windows, windows in the uncertain band, a bounded number of low-score windows, and every agent instruction file in full. It answers three questions: is there harm, who is it addressed to, and is it active or quoted. Code turns those answers into attack, mention or benign. The judge's reply must be exactly one JSON object, and anything else counts as no answer.

An attack or mention answer from the judge adds a flagged finding. A benign answer clears a detector flag only if it came from the primary endpoint, or from the judge's cache of earlier primary answers, and the judge read the window in full. A benign answer from the local fallback model, a window cut short, or no answer at all leaves the detector's flag in place. `ReadConfig.judge_clears_flags = False` turns clearing off. A cleared flag stays as a finding marked `cleared_by_judge`, and in the hook an agent has to ask before it opens that file.

`read/batches.py` runs the scan in tier order and saves each batch, so a scan that runs out of time can resume. `read/scan.py` returns findings plus a verdict of clean, attack or incomplete.

Details: [`read/README.md`](../read/README.md), [`read/docs/JUDGE.md`](../read/docs/JUDGE.md), [`read/docs/MODEL_CARD.md`](../read/docs/MODEL_CARD.md).

## The hook: Gate A and Gate B

The installer (`python -m hooks install`) adds two Claude Code hooks to `settings.json`. Both run Python with `-I`, so a repo cannot replace BaitWatch's code with its own `hooks/` package. The installer sets both to block if the hook process fails to run.

**Gate A** runs on each prompt (`hooks/guard.py`):

1. It runs READ over the repo, tier 0 and 1 first. If it can't fully scan those, Gate A stops the prompt with an ask.
2. It checks the prompt itself for encoded instructions.
3. It decides from the findings:
   - **block:** the judge confirms text aimed at the agent, in a window the detector flagged by itself, in a tier 0 or 1 file. A BaitWatch failure also blocks.
   - **ask:** other findings where the detector and judge agree, the judge alone in a tier 0 or 1 file, or a detector flag with no judge to confirm it.
   - **allow, with a notice:** the judge alone in a lower-tier file, or attack text the judge reads as quoted in a file that is not an agent instruction file. Gate B checks that file again if the agent later opens it. For source code (tier 3), it does so only when the file looks agent-directed.
4. It caches the verdict, keyed by the repo path, Git HEAD, a fingerprint of the file contents, and the scanner settings. An edit to an agent-facing file always triggers a new scan, because those files are compared by content. An edit to a large other file that keeps its size and modification time can reuse the old verdict.

**Gate B** runs before each tool call that matches the installed list: `Bash`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `WebFetch`, `Read` and `Grep` (`TOOL_MATCHER` in `hooks/install.py`). Other tools do not trigger it.

- A **static policy** blocks or asks about dangerous actions, such as piping `curl` into `sh`, sending `.env` or SSH keys over the network, `rm -rf /`, editing agent instruction files, or contacting the test attacker hosts.
- If the repo verdict is attack, every matched tool call is blocked.
- **Scan on open:** when the agent opens a file Gate A did not fully cover (with `Read`, `Grep` on that file, `cat`, `head` and similar), Gate B checks it first. For a file the judge cleared, Gate B asks without scanning again. It always scans tier 0 to 2 files and generated files such as lockfiles, snapshots and vendored code. For source code (tier 3), including files in directories the first scan skips, such as `dist/` and `node_modules/`, Gate B scans only files that look agent-directed: text addressed to an agent, a rule hit, or imperative prose, in the file or its decoded views (`_worth_scanning_on_read`). That check sees about 91% of real attack windows. Other source files open without a scan. Scan on open needs the real READ scanner: with `BAITWATCH_HOOK_SCANNER=keyword`, Gate B does not check opened files.

**Approvals.** `python -m hooks approve` lets the person continue past an ask, and `--allow-block` past a block. Approvals live in the user's own cache folder, so a repo cannot add to them. An accepted file stays accepted until its content changes. Other approvals, such as for a scan that ran out of time, cover only the exact tree and expire after 15 minutes by default. An agent cannot approve for itself. The hook refuses any tool call that runs `hooks approve`.

Details: [`docs/HOOKS.md`](HOOKS.md).

## RUN: running the repo in a sandbox

`baitwatch scan <repo> --llm <spec>` runs READ, then RUN, then fuses the two. RUN follows these steps for each scan (`run/sandbox.py`):

1. **Stage a copy.** The runner copies the repo into a private temporary directory, without following symlinks and within size, count, depth and time limits. The copy leaves out Git metadata, dependency folders, credential folders and real `.env` files, and lists what it left out. The runner never mounts or writes to the original repo.
2. **Plant honeytokens** (`run/honeytokens.py`). The runner writes fake credentials into the copy: `.env`, `.env.local` and `config/credentials`, only where the repo has none. The values are new for each scan and match no real provider's format.
3. **Create the network.** The runner creates a new internal Docker bridge with no route out and no host address. Two sink containers listen on it: one for DNS, one for HTTP and TLS (`run/sinks/`). They log every request they receive.
4. **Start the cage.** The cage is a container built only from the trusted `run/cage/Dockerfile`. It runs as an unprivileged user with a read-only root, no capabilities, CPU, memory, process and output limits, and an empty home directory. It has no host home, credentials or Docker socket.
5. **Run the decoy** (`run/decoy.py`). A decoy LLM, running on the host, is told to set up and test the repo by following its own instructions. Its `read_file`, `list_files` and `run_cmd` tools run only inside the cage. The runner logs every call. After each call, the runner kills any process the call left running in the background.
6. **Trace files** (`run/trace.py`). The runner snapshots the staged copy and the cage home before and after, then compares the snapshots to find every file added, changed or deleted.
7. **Search for honeytokens.** The runner looks for the planted values in sink traffic, tool output, tool arguments, the decoy's reply text and files the cage wrote. It checks plain, URL, base64, base32 and hex forms.
8. **Clean up.** It removes only this scan's containers, network and staging folder, found by the scan's label. It never runs a global Docker prune.

**Fusion** (`run/verdict.py`) turns READ findings and RUN evidence into one verdict:

| Evidence | Verdict |
|---|---|
| A honeytoken sent over DNS, HTTP or TLS | BLOCK |
| Any network contact outside the package registries | BLOCK |
| A write to agent config, editor settings, Git hooks or CI workflows in the copy or the cage home, outside build and cache folders such as `dist`, `node_modules`, `vendor` and `.venv`. `.git/hooks` and `.git/config` block wherever they are | BLOCK |
| A write to shell startup files, `.ssh`, `.gitconfig`, package-manager config or cron files in the cage home, outside build and cache folders | BLOCK |
| Half or more of the repo's own files deleted or emptied, or more than 200, not counting build and cache folders or planted honeytokens | BLOCK |
| A READ attack at or above the pinned `hard_high` score (0.9965 for v1.7) | BLOCK |
| A honeytoken moved into a command, the decoy's reply or a file | FLAG |
| A lower-scoring READ attack, a package-registry contact other than a plain lookup, or a deleted or emptied file | FLAG |
| Any error, timeout, limit hit, incomplete READ, or a decoy that ran no command | FLAG |
| Any path left out of the copy, other than the top-level `.git` | FLAG |
| READ clean and RUN complete with none of the above | ALLOW |

ALLOW needs complete evidence from every part. The verdict schema (`docs/verdict.schema.json`) rejects an ALLOW that has errors or honeytoken hits other than a plain read. A decoy reading `.env` is normal setup behaviour and does not change the verdict by itself.

Details: [`run/README.md`](../run/README.md), [`run/SANDBOX.md`](../run/SANDBOX.md), [`run/CONTRACT.md`](../run/CONTRACT.md).

## Security model

**Untrusted:** everything in the scanned repo, including file names, contents, symlinks and project settings. Also untrusted: text the judge or the decoy model writes back, since an attacker can influence it.

**Trusted:** BaitWatch's own code, the user's `~/.claude/settings.json`, the detector checkpoint (checked against its pinned hash), and Docker images built from a trusted BaitWatch checkout.

How BaitWatch keeps that line:

- **Repo commands never run on the host.** In RUN they run only in the cage. The hook never runs them.
- **A repo cannot change BaitWatch's settings.** The hook takes its security settings, such as the judge endpoint and the error mode, only from the user's own `settings.json`, and ignores values inherited from the environment.
- **The judge treats the repo text it reads as data.** BaitWatch fences each window with a random tag and sends the file name as a quoted string. An attempt to steer the judge counts as an attack. Only a reply that is exactly one JSON object counts as an answer.
- **Errors never allow.** In the hook, a crash, a bad payload or a missed deadline becomes block, or ask if `BAITWATCH_ON_ERROR=ask` is set. In fusion, any error or missing evidence is at least FLAG.
- **BaitWatch caps spending.** The judge has per-scan call and token budgets, and the decoy has step, token and time budgets.

**What leaves your machine.** With `META_API_KEY` set, the judge sends suspicious windows from any file, and agent instruction files in full, to its primary endpoint. That is Meta's API unless `BAITWATCH_JUDGE_BASE_URL` points elsewhere. When the primary is unavailable, the judge uses its fallback, a local `llama-server` unless `BAITWATCH_FALLBACK_BASE_URL` points elsewhere. The decoy sends what it reads from the repo to its model backend. With no key, the default local fallback and a local decoy model (for example `ollama:`), nothing leaves the machine. Do not use model tiers that let the provider train on what you send, such as Muse Spark's Contributor tier, on private code.

## Known limits

- **An allow is not proof.** BaitWatch still misses about 29% of real malicious skills ([`docs/HOOKS.md`](HOOKS.md#coverage)).
- **Hook coverage has gaps.** Gate B runs only for the tools in its matcher, so other tools, such as `Glob` or `WebSearch`, are not checked. Gate B does not check a file on open when the agent reads it with `grep -r`, `python -c` or a build script. The hook does not scan tool output or fetched web pages. Hosts that load instruction files from excluded folders without a tool call are not covered.
- **One incomplete case can still allow.** If a scan does not finish, and every finding it made only matters when a file is opened, Gate A allows the prompt instead of asking.
- **The judge can be fooled.** A fooled judge clears a flag, and the only remaining check is the ask when the agent opens that file.
- **The sandbox does not see everything.** The network blocks traffic to raw IP addresses or unlisted ports but does not log it. The trace cannot see writes undone before the after-snapshot. The sandbox makes no claim against kernel or container escapes. See [`run/SANDBOX.md`](../run/SANDBOX.md#known-limits).
- **The decoy is not a reliable trigger.** In our trial, Muse Spark did not try to exfiltrate in any of 10 runs on repo #1 ([`docs/DECOY_TRIAL.md`](DECOY_TRIAL.md)). RUN catches what the decoy does, not what a determined agent might do.
- **Honeytoken search is text-based.** It misses values that are compressed, reversed, or split across two files or requests.

## Project structure

```
read/            READ scanner
  walk.py          file listing and symlink handling
  tiers.py         file priority tiers
  decoders.py      hidden-text views
  chunking.py      token windows
  detector.py      Prompt Guard 2 detector
  judge.py         Muse Spark judge, endpoints, budgets, cache
  batches.py       tiered, resumable scanning
  scan.py          findings and the READ verdict
  model_config.json  pinned checkpoint hash and thresholds
  data/, training/   dataset and training pipeline
run/             RUN sandbox and fusion
  staging.py       bounded copy of the repo
  honeytokens.py   plant and search for fake credentials
  sandbox.py       network, cage, sinks, trace and cleanup
  sinks/           DNS and HTTP/TLS sink containers
  cage/            the cage image
  trace.py         before and after file snapshots
  decoy.py, llm.py decoy loop and model backends
  verdict.py       fusion rules
  scan_cli.py      `baitwatch scan`
  cli.py           `baitwatch-run sandbox` and `decoy`
  schemas.py       generates docs/verdict.schema.json
hooks/           Claude Code hook
  guard.py         Gate A and Gate B decisions
  cache.py         verdict cache and accepted files
  cli.py           entry points, deadline, approvals, selftest
  install.py       settings.json installer
attacks/         attack repos and tooling
  repos/           17 attack repos and 5 harmless twins
  synth/           transforms, seeds and templates
  decoders.py      decoder plugin for READ
  harness.py       per-repo detection table
tests/           read/, run/, attacks/ and e2e/ suites
demo/            three-minute demo script
docs/            schema, hook docs, results and reports
```

## Further reading

| Topic | Doc |
|---|---|
| Hook install, verdict rules, coverage, approvals, cache | [`docs/HOOKS.md`](HOOKS.md) |
| READ API and detector | [`read/README.md`](../read/README.md) |
| Judge design and failure handling | [`read/docs/JUDGE.md`](../read/docs/JUDGE.md) |
| Detector numbers and known misses | [`read/docs/MODEL_CARD.md`](../read/docs/MODEL_CARD.md) |
| RUN commands and fusion rules | [`run/README.md`](../run/README.md) |
| Sandbox boundary and limits | [`run/SANDBOX.md`](../run/SANDBOX.md) |
| Evidence and verdict contract | [`run/CONTRACT.md`](../run/CONTRACT.md) |
| Attack repos and safety rails | [`attacks/README.md`](../attacks/README.md) |
| Builds, dates and methods behind the results | [`docs/RESULTS.md`](RESULTS.md) |
