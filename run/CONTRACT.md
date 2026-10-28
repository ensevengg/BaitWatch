# Proposed team interface, schema version 1.0

This is RUN's first proposal for the shared interface. The team has not reviewed or frozen it.

`run.detonate(path, command=("true",), config=None) -> RunEvidence`

The default command only checks that the sandbox works. The decoy loop (PR #12) extends it with a model-driven `tool_log`; its trial against repo #1 produced 0/10 bites (`docs/DECOY_TRIAL.md`). Command arguments run inside the cage, never on the host.

## RunEvidence

`RunEvidence` always has these lists: `dns_hits`, `http_hits`, `tls_hits`, `honeytoken_hits`, `file_diffs`, `tool_log` and `errors`. It also has a scan UUID, a UTC start time, a version, a status and a state for each component. `staging_exclusions` lists the paths left out of the copy on purpose: dependency and cache directories, Git metadata, credential directories and real environment files.

An empty list means nothing was recorded. It does not mean the component ran.

- A component's state is `not_run`, `complete` or `error`.
- The RUN status is `incomplete`, `complete` or `error`.
- A command that exits 0 marks only the sandbox component complete. `dns_sink`, `http_sink` and `tls_sink` become complete only when the sink reported ready, its container is still running when evidence is collected, and its whole log parses without problems or truncation; otherwise they are error (`SINK_FAILED`, `SINK_LOG`). A `refused` record — a contact dropped at the sink's connection limit — is such a problem, so suppressed evidence cannot look like a clean log. The TLS component shares the HTTP sink's container and log. `trace` is complete only when both staged-tree snapshots parsed strictly and their diff produced `file_diffs`. This branch has no decoy, so a real `detonate` scan stays `incomplete`; with the PR #12 loop the decoy component is set from the model run.
- `dns_hits`, `http_hits` and `tls_hits` carry the peer source IP (the cage), the destination (DNS qname, HTTP host+path or TLS SNI) and a bounded detail line: query type and label-decoded secrets, method and body preview, or a raw preview for unparseable TCP contact.
- `file_diffs` lists added, modified and deleted paths in the disposable staged copy. Changes to the original repository are impossible to record this way because the original is never mounted.
- Setup, timeout, truncation, command and cleanup errors stay in `errors`. A component that is not built yet is `not_run`.
- `stdout` and `stderr` share one byte budget. `timed_out` and `output_truncated` are separate fields.

## VerdictReport

The proposed `VerdictReport` has three verdicts, `ALLOW`, `FLAG` and `BLOCK`, and defaults to `FLAG`. The Python model and the generated JSON Schema both reject `ALLOW` unless READ and every RUN component are complete and there are no errors or honeytoken hits. This guard only checks structure. It is not the planned fusion truth table, and sink attribution, model thresholds and judge behavior do not exist yet.

The READ finding fields are left out on purpose. Manan owns that part of the contract. The team should agree on the finding format and on what counts as complete before any component depends on this proposal.

Regenerate `docs/verdict.schema.json` with `uv run --no-sync python -m run.schemas`. A test fails if the committed schema differs from the generator's output.
