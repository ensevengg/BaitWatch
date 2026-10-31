# Proposed team interface, schema version 1.0

This is RUN's first proposal for the shared interface. The team has not reviewed or frozen it.

`run.detonate(path, command=("true",), config=None, *, backend=None, max_steps=20) -> RunEvidence`

The default command only checks that the sandbox works. With a `backend` (any object with `chat(messages, tools) -> LLMReply`, OpenAI chat-completions shapes; see `run/llm.py`), the decoy loop `run_decoy(sandbox, backend, max_steps=..., task=...)` replaces the plain command: the model runs on the host, and every tool call executes inside the cage through `Sandbox.exec`. Command arguments run inside the cage, never on the host.

## RunEvidence

`RunEvidence` always has these lists: `dns_hits`, `http_hits`, `tls_hits`, `honeytoken_hits`, `file_diffs`, `tool_log` and `errors`. It also has a scan UUID, a UTC start time, a version, a status and a state for each component. `staging_exclusions` lists the paths left out of the copy on purpose: dependency and cache directories, Git metadata, credential directories and real environment files.

An empty list means nothing was recorded. It does not mean the component ran. Evidence that was parsed is never dropped when its component errors: sink hits stay in the hit lists and file diffs stay in `file_diffs` whatever the component's state.

- A component's state is `not_run`, `complete` or `error`.
- The RUN status is `incomplete`, `complete` or `error`. It becomes `complete` only when every component is `complete` and `errors` is empty; hits never change it, and the verdict fusion is a separate later step.
- A command that exits 0 marks only the sandbox component complete. `dns_sink`, `http_sink` and `tls_sink` become complete only when the sink reported ready, its container is still running when evidence is collected, stopped cleanly, and its whole log parses without problems or truncation; otherwise they are error (`SINK_FAILED`, `SINK_LOG`) while every hit the log did produce is kept. A `refused` record — a contact dropped at the sink's connection limit — is such a problem, so suppressed evidence cannot look like a clean log; so are incomplete captures flagged by the sinks themselves: a DNS datagram the kernel truncated at the receive bound, a TLS ClientHello cut at the read limit, or an HTTP request whose head or body was cut at a capture limit (a chunked body always counts as cut, since it is never decoded). The TLS component shares the HTTP sink's container and log. `trace` is complete only when both repository and HOME snapshots parsed strictly and neither carries an error marker; a snapshot that could not read some path is an error (`TRACE_INCOMPLETE`, naming a bounded set of paths) while the diffs it did produce are kept, and any snapshot failure is `TRACE_FAILED`. Without a backend the decoy stays `not_run`, so a plain command scan can never become `complete`. With a backend, `decoy` is complete when the loop ended without a model or cage error — the model must finish within the step budget — and error otherwise. Step-budget exhaustion records `DECOY_STEP_BUDGET`. A loop failure is `DECOY_FAILED`, except a host-side decoy deadline that expires during inference or tool calls (`DECOY_DEADLINE`) and a cage found stopped before completion (`CAGE_EXITED`). A provider reply whose `finish_reason` is anything but a plain finish or a tool-call step — cut at the length limit, blocked by a content filter, or an unknown value — is a model error, never a finished reply.
- `tool_log` holds one `CommandResult` per executed entry. The plain command records its argv. A decoy tool call records the tool name and arguments as its `command` (for example `["run_cmd", "sh setup.sh"]`) plus the outcome; the underlying cage argv is not repeated there. A call that could not dispatch — unknown tool or malformed arguments — is logged with the model-facing error in `stderr` and no `exit_code`, because nothing executed. Each exec's exit code comes from Docker's own exec record, never from the streaming client: a stream that ends can be a broken connection wearing a clean end, so after the stream closes the record must show the exec finished and its `ExitCode` is the reported one. After each exec, a bounded poll (up to 2.5 seconds, every 0.1 seconds) lets the trusted Busybox timeout watchdog exit while sinks remain active; then every other live cage process except the cage's PID 1 is killed, so forked or backgrounded work cannot outlive its tool call; a sweep that kills live work records `EXEC_LINGERING_KILLED`, and one that cannot confirm the cage is clear records `EXEC_KILL_FAILED`. Both prevent ALLOW. A tool call killed at its deadline is an error (`EXEC_TIMEOUT`) and one whose output passed the byte budget is an error (`EXEC_OUTPUT_TRUNCATED`), though its `tool_log` entry is kept; ordinary nonzero tool exits are results, not errors. A record that cannot be read, still shows the exec running, has no exit code, or disagrees with a stream that broke or with the in-cage start marker (the exec never reached the cage) is an error (`EXEC_TRANSPORT_FAILED`) and the entry is kept.
- `dns_hits`, `http_hits` and `tls_hits` carry the peer source IP (the cage), the destination (DNS qname, HTTP host+path or TLS SNI) and a bounded detail line: query type and label-decoded secrets, method and body preview, or a raw preview for unparseable TCP contact.
- `file_diffs` lists added, modified and deleted paths in the disposable staged copy and HOME. Repository paths are relative; HOME paths start with `/cage/home/`. Each diff has `is_repo_file`, true only for a pre-run regular repository file outside build/cache trees and planted bait. `staged_file_count` counts those files for deletion thresholds. Changes to the original repository are impossible to record this way because the original is never mounted.
- Each scan generates a small set of honeytokens from `secrets`, in obviously fake shapes (`BAITWATCH_FAKE_<lowercase base32>`, canary URLs only under the reserved `.example` TLD) that match no provider's secret format. They are planted only in the staged copy — a fake `.env`, a fake `.env.local`, and a fake `config/credentials` where the repository provides no such file — before the first trace snapshot, so planted files are never the repository's own `file_diffs` and the original repository is never written. After the sinks stop, the DNS names, the HTTP method, host, path (also percent-decoded), header names and values and body, the TLS SNI and the full bounded TLS capture (logged as `capture_hex`, searched as hex and as decoded bytes, covering the ClientHello and every drained byte after it), the decoded DNS labels and every `tool_log` output are searched for those values in plain, URL-encoded, base64, base64url, base32 and hex forms, including values split across DNS labels, across adjacent queries to one domain, or across wrapped lines, under per-record and total byte bounds. Each match appends `HoneytokenHit(token_id, source, source_ip)` to `honeytoken_hits`. A hit record carries only the token id, never the value; the fake value can still appear in `tool_log` output and sink detail because evidence quotes what the cage emitted, which is harmless because the values are fake and unique to the scan. A `tool_log` hit means the decoy handled a planted value, not that anything left the cage. A detection bound hit records `HONEYTOKEN_SCAN_INCOMPLETE`, so an unscanned remainder can never look clean, and truncated sink records stay incomplete through their own log problems whether or not a token was found. A planted token reaching a sink is the strongest exfil signal: fusion BLOCKs on a `dns`, `http` or `tls` hit and FLAGs a hit that only came from `tool_log` or a transcript, and never ALLOWs while `honeytoken_hits` is non-empty.
- Setup, timeout, truncation, command and cleanup errors stay in `errors`. A component that is not built yet is `not_run`.
- If Docker drops whole output frames at a frame boundary while reporting a clean exit, capture cannot detect the loss; this requires a Docker transport fault rather than cage control, and a per-stream end-of-output record is the planned fix.
- `stdout` and `stderr` share one byte budget. `timed_out` and `output_truncated` are separate fields.

## VerdictReport

The proposed `VerdictReport` has three verdicts, `ALLOW`, `FLAG` and `BLOCK`, and defaults to `FLAG`. The Python model and the generated JSON Schema both reject `ALLOW` unless READ and every RUN component are complete and there are no errors or honeytoken hits. This guard only checks structure. A provisional fusion truth table lives in `run/verdict.py` (`baitwatch scan` uses it); its thresholds are not agreed yet.

The READ finding fields are left out on purpose. Manan owns that part of the contract. The team should agree on the finding format and on what counts as complete before any component depends on this proposal.

Regenerate `docs/verdict.schema.json` with `uv run --no-sync python -m run.schemas`. A test fails if the committed schema differs from the generator's output.

Fusion requires an executed `run_cmd` entry with an exit code before ALLOW;
empty logs, read/list-only runs and rejected command arguments are FLAG.
Exclusions other than the top-level `.git` directory or regular file cause FLAG, with a bounded
reason. A regular top-level `.git` file is excluded without being read; a symlink fails staging.
Nested `.git` exclusions still FLAG.
READ is requested with `strict_coverage=True`; partial-file, truncated-file,
file-cap and dropped-view/chunk statistics independently prevent a clean outcome.
READ-skipped directories that staging copies also prevent a clean outcome;
the coverage check uses the READ walker configuration and staging entry, depth
and time bounds without following directory symlinks. Already excluded staging
paths are handled by fusion. Attack scores survive incomplete coverage.

Network evidence covers the DNS listener and HTTP/TLS listeners, not all failed
connections. TCP or UDP to literal IPs outside those listeners, and contacts on
unlisted ports, can fail without a sink hit. A clean READ and otherwise complete
RUN can still yield ALLOW in that case. See [SANDBOX.md](SANDBOX.md).

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
hello with a fatal `handshake_failure` alert and then drains for at most one
second and 16 KiB past the hello, until the peer closes or the window
expires), the count and a bounded hex prefix of any bytes after that record,
a hex copy of every received byte (`capture_hex`, bounded by the 64 KiB read
limit and the drain limit, and marked `capture_incomplete` when either limit
is hit), and `hello_only`. `hello_only` is true only when the received bytes
are exactly one TLS record holding a single complete ClientHello, the record
version is `0x0301` or `0x0303`, the record payload is at most 2^14 bytes,
the whole record is at most 2048 bytes, the ClientHello body validates:
legacy version `0x0301`–`0x0303`, a session id of at most 32 bytes, a
non-empty even-length cipher-suite list, a compression list containing the
null method, and an extensions block whose lengths exactly consume the body
with zero-filled padding, and the peer reached EOF or reset inside that
window. Extra records, coalesced or trailing bytes, a hello split across
records, unparseable, truncated or oversize captures, and a peer still
connected when the window expires are all false. TLS hits carry this as
`NetworkHit.hello_only` (also in the JSON schema); records without it are
never exempt. Registry TLS without that proof remains an attempt (FLAG);
missing/mismatched SNI and incomplete captures still BLOCK.
Known limit: a validated hello-only ClientHello can still carry up to about
2 KB of client-chosen bytes to an exact registry host, spread across its
32-byte random, a session id of up to 32 bytes, the cipher and compression
lists and the extension bytes (including unknown or GREASE extensions and key
shares); all of those fields together are bounded by that cap. The capture is
searched for honeytokens in plain, URL-encoded, base64, base32 and hex forms;
XOR or other custom encodings and a token split across two separate
connections are not detected. In a real environment those bytes reach only
the registry host.

Non-registry contacts and network honeytoken hits always BLOCK. A honeytoken
hit over DNS, HTTP or TLS takes precedence over any registry exemption.
Registry-attempt reasons remain bounded.

DNS labels escape every non-LDH byte as `\DDD` (decimal), including embedded
dots. Names are bounded by DNS wire length and never cut in presentation.
Up to 128 questions per packet are logged; multiple questions, malformed names,
budget overflow or extra sections other than exactly one well-formed root-name
EDNS0 OPT record mark capture incomplete. Only empty OPT RDATA or exactly one
COOKIE option (code 10) with an 8-byte client cookie counts as a plain lookup.
Go's pure resolver sends an empty OPT; c-ares defaults tested here send a
client-only COOKIE, which is also dig's default shape.
All other options, longer or shorter cookies, and multiple options stay incomplete
and BLOCK even for exact registry hosts. Extra-section bytes are retained in a
bounded, escaped `raw` preview (200 characters) for evidence and honeytoken searches;
bytes beyond that preview are not retained. Multiple OPT records, unsupported
versions and malformed options stay incomplete. TLS SNI is escaped and retained within the bounded ClientHello capture, without a silent name cut.

Evidence fields replace lone Unicode surrogates with literal backslash escapes
before validation, so byte filenames, tool text and error paths cannot suppress
JSON reports. Raw trace keys remain unchanged for comparing snapshots.

READ system findings are operational failures, with ERROR coverage and a
truthful note, never detector scores. Genuine flagged model/judge scores still
block at the threshold even alongside system failures. Attack verdict reasons
retain coverage gaps.

An added or modified file reaching the per-file cap, or a snapshot exceeding
total-byte/entry limits, records `REPO_WRITE_LIMIT` and prevents ALLOW. RLIMIT_FSIZE is a hard
per-file bound, not an aggregate disk quota; see SANDBOX.md for the residual gap.

The decoy checks its deadline between calls within a reply, and counts each
call (including rejected arguments) toward max_steps as well as bounding model
turns. Docker exec completion tolerates up to two seconds of delayed exit-event
publication; a still-running or malformed record remains a transport error.
Sink and after-trace collection run in finally blocks before sandbox cleanup.

Keyed plain-HTTP model requests are allowed only to exact `localhost` or
`127.0.0.1` and bypass all environment proxies, regardless of `no_proxy`.
HTTPS model requests retain urllib's environment proxy behavior: HTTP proxies
use CONNECT and the request, including Authorization, stays inside the verified
TLS connection to the endpoint. Keyless HTTP requests retain proxy behavior.
Redirects remain disabled for all model requests.

## File-change rules

Any added, modified or deleted path at or below `.claude`, `.cursor`, `.windsurf`,
`.codex`, `.gemini`, `.continue`, `.vscode`, `.idea` or `.husky` BLOCKs. Whole editor
directories are covered because extensions and workspace settings can execute
commands. The named files `.mcp.json`, `mcp.json`, `AGENTS.md`, `CLAUDE.md`,
`GEMINI.md`, `.claude.json`, `.claude.json.backup`, `.clinerules`,
`.aider.conf.yml`, `.cursorrules`, `.windsurfrules`, `.pre-commit-config.yaml`,
`.github/copilot-instructions.md`, `.github/workflows`, `.envrc`, `.git/config`
and `.git/hooks` also BLOCK, including descendants of these names. Workflow changes can persist code into CI;
`.envrc` can execute through direnv on directory entry. Matching uses casefold
conservatively on all platforms and applies at any component depth within the bounded snapshot
(default 64 levels, 10,000 entries). Creating new Git metadata counts even though
original Git metadata was excluded during staging. Reasons show at most three
paths, at most 100 characters each, within a 400-character rule reason.

HOME starts empty at `/cage/home` and is separately mounted from a disposable
scan directory. Its writes use the same per-file hard RLIMIT and snapshot
limits, with combined post-run entry/byte checks. Shell startup files (`.bashrc`,
`.profile`, `.bash_profile`, `.bash_login`, `.bash_logout`, `.zshrc`, `.zshenv`,
`.zprofile`, `.zlogin`, `.zlogout`, `.kshrc`, `.cshrc`, `.tcshrc`, `.login`),
`.config`, `.ssh`, `.gitconfig`, `.npmrc`, `.pypirc`, `.crontab`, `crontab`, `cron`
and `cron.*`, plus the agent-control names above (including the single-file
agent configs at HOME root), BLOCK at any HOME depth outside dependency/cache
trees. Other HOME writes, including `.cache`, `.npm` and `.local`, remain recorded and
alone do not prevent ALLOW. No real credentials or host HOME are copied.

Deleting or truncating a counted staged repository file from nonempty to zero
bytes FLAGs, including delete-and-recreate as an empty regular file. Destroying
at least 50% of counted files or more than 200 files BLOCKs: the ratio catches small-tree wipes,
while the absolute cap catches substantial destruction in large trees. Both the
denominator and destroyed-file count exclude planted honeytoken files, directories,
symlinks, HOME and files under any `build`, `dist`, `target`, `node_modules`,
`__pycache__`, `.pytest_cache`, `.cache`, `.venv`, `venv`, `site-packages`,
`vendor`, `.npm`, `.yarn` or `.pnpm-store` component. A pre-existing repository
`config/credentials` still counts if no bait was planted there. Sensitive-path
matching only considers components before the first dependency/cache
directory component, so installing packages containing agent files does not
BLOCK, while a control path above such a directory (for example
`.claude/skills/build/SKILL.md`) still BLOCKs. `.git/config` and `.git/hooks`
remain protected even inside those trees. Ordinary setup writes (build output, dependencies, environments, lockfiles and source files) alone
remain eligible for ALLOW with clean READ and a complete executed decoy.

`FileDiff.is_truncated` defaults to false and is set by the runner from the
trusted before/after manifests for counted repository files; it does not change
the `modified` change type. The JSON schema includes this evidence field.

These rules compare final snapshots, not a write journal: restored writes,
transient files and `/tmp` writes remain unobserved. Partial content loss that
leaves a nonempty regular file does not trigger destruction rules. Alternate
agent configuration names and environment overrides remain outside the path
catalog. Matching is lexical: writes through pre-existing symlink or hardlink
aliases can change an ordinary target without changing its sensitive alias.
Aggregate disk/inode use during execution remains without a hard quota;
any snapshot failure or exceeded collection bound still prevents ALLOW.
