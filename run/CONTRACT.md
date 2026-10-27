# Proposed team interface, schema version 1.0

This is RUN's first proposal for the shared interface. The team has not reviewed or frozen it.

`run.detonate(path, command=("true",), config=None) -> RunEvidence`

The default command only checks that the sandbox works. The decoy loop will replace or extend it later. Command arguments run inside the cage, never on the host.

## RunEvidence

`RunEvidence` always has these lists: `dns_hits`, `http_hits`, `tls_hits`, `honeytoken_hits`, `file_diffs`, `tool_log` and `errors`. It also has a scan UUID, a UTC start time, a version, a status and a state for each component. `staging_exclusions` lists the paths left out of the copy on purpose: dependency and cache directories, Git metadata, credential directories and real environment files.

An empty list means nothing was recorded. It does not mean the component ran.

- A component's state is `not_run`, `complete` or `error`.
- The RUN status is `incomplete`, `complete` or `error`.
- A command that exits 0 marks only the sandbox component complete. Sinks, the decoy and tracing keep their own states.
- Setup, timeout, truncation, command and cleanup errors stay in `errors`. A component that is not built yet is `not_run`.
- `stdout` and `stderr` share one byte budget. `timed_out` and `output_truncated` are separate fields.

## VerdictReport

The proposed `VerdictReport` has three verdicts, `ALLOW`, `FLAG` and `BLOCK`, and defaults to `FLAG`. The Python model and the generated JSON Schema both reject `ALLOW` unless READ and every RUN component are complete and there are no errors or honeytoken hits. This guard only checks structure. It is not the planned fusion truth table, and sink attribution, model thresholds and judge behavior do not exist yet.

The READ finding fields are left out on purpose. Manan owns that part of the contract. The team should agree on the finding format and on what counts as complete before any component depends on this proposal.

Regenerate `docs/verdict.schema.json` with `uv run --no-sync python -m run.schemas`. A test fails if the committed schema differs from the generator's output.
