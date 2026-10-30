# Proposed team interface, schema version 1.0

This is RUN's first proposal for the shared interface. The team has not reviewed or frozen it.

`run.detonate(path, command=("true",), config=None, *, backend=None, max_steps=20) -> RunEvidence`

The default command only checks that the sandbox works. With a `backend` (any object with `chat(messages, tools) -> LLMReply`, OpenAI chat-completions shapes; see `run/llm.py`), the decoy loop `run_decoy(sandbox, backend, max_steps=..., task=...)` replaces the plain command: the model runs on the host, and every tool call executes inside the cage through `Sandbox.exec`. Command arguments run inside the cage, never on the host.

## RunEvidence

`RunEvidence` always has these lists: `dns_hits`, `http_hits`, `tls_hits`, `honeytoken_hits`, `file_diffs`, `tool_log` and `errors`. It also has a scan UUID, a UTC start time, a version, a status and a state for each component. `staging_exclusions` lists the paths left out of the copy on purpose: dependency and cache directories, Git metadata, credential directories and real environment files.

An empty list means nothing was recorded. It does not mean the component ran. Evidence that was parsed is never dropped when its component errors: sink hits stay in the hit lists and file diffs stay in `file_diffs` whatever the component's state.

- A component's state is `not_run`, `complete` or `error`.
- The RUN status is `incomplete`, `complete` or `error`. It becomes `complete` only when every component is `complete` and `errors` is empty; hits never change it, and the verdict fusion is a separate later step.
- A command that exits 0 marks only the sandbox component complete. `dns_sink`, `http_sink` and `tls_sink` become complete only when the sink reported ready, its container is still running when evidence is collected, stopped cleanly, and its whole log parses without problems or truncation; otherwise they are error (`SINK_FAILED`, `SINK_LOG`) while every hit the log did produce is kept. A `refused` record — a contact dropped at the sink's connection limit — is such a problem, so suppressed evidence cannot look like a clean log; so are incomplete captures flagged by the sinks themselves: a DNS datagram the kernel truncated at the receive bound, a TLS ClientHello cut at the read limit, or an HTTP request whose head or body was cut at a capture limit (a chunked body always counts as cut, since it is never decoded). The TLS component shares the HTTP sink's container and log. `trace` is complete only when both staged-tree snapshots parsed strictly and neither carries an error marker; a snapshot that could not read some path is an error (`TRACE_INCOMPLETE`, naming a bounded set of paths) while the diffs it did produce are kept, and any snapshot failure is `TRACE_FAILED`. Without a backend the decoy stays `not_run`, so a plain command scan can never become `complete`. With a backend, `decoy` is complete when the loop ended without a model or cage error — the model must finish within the step budget — and error otherwise. Step-budget exhaustion records `DECOY_STEP_BUDGET`. A loop failure is `DECOY_FAILED`, except a host-side decoy deadline that expires during inference or tool calls (`DECOY_DEADLINE`) and a cage found stopped before completion (`CAGE_EXITED`). A provider reply whose `finish_reason` is anything but a plain finish or a tool-call step — cut at the length limit, blocked by a content filter, or an unknown value — is a model error, never a finished reply.
- `tool_log` holds one `CommandResult` per executed entry. The plain command records its argv. A decoy tool call records the tool name and arguments as its `command` (for example `["run_cmd", "sh setup.sh"]`) plus the outcome; the underlying cage argv is not repeated there. A call that could not dispatch — unknown tool or malformed arguments — is logged with the model-facing error in `stderr` and no `exit_code`, because nothing executed. Each exec's exit code comes from Docker's own exec record, never from the streaming client: a stream that ends can be a broken connection wearing a clean end, so after the stream closes the record must show the exec finished and its `ExitCode` is the reported one. After each exec, a one-second grace lets the trusted Busybox timeout watchdog exit while sinks remain active; then every other live cage process except the cage's PID 1 is killed, so forked or backgrounded work cannot outlive its tool call; a sweep that kills live work records `EXEC_LINGERING_KILLED`, and one that cannot confirm the cage is clear records `EXEC_KILL_FAILED`. Both prevent ALLOW. A tool call killed at its deadline is an error (`EXEC_TIMEOUT`) and one whose output passed the byte budget is an error (`EXEC_OUTPUT_TRUNCATED`), though its `tool_log` entry is kept; ordinary nonzero tool exits are results, not errors. A record that cannot be read, still shows the exec running, has no exit code, or disagrees with a stream that broke or with the in-cage start marker (the exec never reached the cage) is an error (`EXEC_TRANSPORT_FAILED`) and the entry is kept.
- `dns_hits`, `http_hits` and `tls_hits` carry the peer source IP (the cage), the destination (DNS qname, HTTP host+path or TLS SNI) and a bounded detail line: query type and label-decoded secrets, method and body preview, or a raw preview for unparseable TCP contact.
- `file_diffs` lists added, modified and deleted paths in the disposable staged copy. Changes to the original repository are impossible to record this way because the original is never mounted.
- Setup, timeout, truncation, command and cleanup errors stay in `errors`. A component that is not built yet is `not_run`.
- If Docker drops whole output frames at a frame boundary while reporting a clean exit, capture cannot detect the loss; this requires a Docker transport fault rather than cage control, and a per-stream end-of-output record is the planned fix.
- `stdout` and `stderr` share one byte budget. `timed_out` and `output_truncated` are separate fields.

## VerdictReport

The proposed `VerdictReport` has three verdicts, `ALLOW`, `FLAG` and `BLOCK`, and defaults to `FLAG`. The Python model and the generated JSON Schema both reject `ALLOW` unless READ and every RUN component are complete and there are no errors or honeytoken hits. This guard only checks structure. A provisional fusion truth table lives in `run/verdict.py` (`baitwatch scan` uses it); its thresholds are not agreed, and sink attribution and judge behavior do not exist yet.

The READ finding fields are left out on purpose. Manan owns that part of the contract. The team should agree on the finding format and on what counts as complete before any component depends on this proposal.

Regenerate `docs/verdict.schema.json` with `uv run --no-sync python -m run.schemas`. A test fails if the committed schema differs from the generator's output.

Fusion requires an executed `run_cmd` entry with an exit code before ALLOW;
empty logs, read/list-only runs and rejected command arguments are FLAG.
Exclusions other than the top-level `.git` directory cause FLAG, with a bounded
reason. A top-level `.git` file or symlink fails staging; it is never copied.
READ is requested with `strict_coverage=True`; partial-file, truncated-file,
file-cap and dropped-view/chunk statistics independently prevent a clean outcome.
Attack findings retain their score even when coverage is incomplete.

Network evidence covers the DNS listener and HTTP/TLS listeners, not all failed
connections. TCP or UDP to literal IPs outside those listeners, and contacts on
unlisted ports, can fail without a sink hit. A clean READ and otherwise complete
RUN can still yield ALLOW in that case. See [SANDBOX.md](SANDBOX.md).

Registry downgrades apply only to exact pypi.org, files.pythonhosted.org,
registry.npmjs.org and registry.yarnpkg.com names: DNS questions, TLS SNI,
or HTTP GET/HEAD with no body, query or incomplete capture. Subdomains and
uploads BLOCK. Registry-attempt reasons are bounded.

DNS labels escape every non-LDH byte as `\DDD` (decimal), including embedded
dots. Names are bounded by DNS wire length and never cut in presentation.
Up to 128 questions per packet are logged; multiple questions, extra sections,
malformed names or budget overflow mark capture incomplete. TLS SNI is escaped
and retained within the bounded ClientHello capture, without a silent name cut.

Evidence fields replace lone Unicode surrogates with literal backslash escapes
before validation, so byte filenames, tool text and error paths cannot suppress
JSON reports. Raw trace keys remain unchanged for comparing snapshots.
