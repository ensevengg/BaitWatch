# BaitWatch

Catches prompt-injection attacks aimed at AI coding agents before the agent is
allowed to run in a repository.

## How it works

```
untrusted repo
  ├─ READ  fine-tuned Llama Prompt Guard 2 reads every file, including decoded
  │        hidden payloads; Muse Spark judges uncertain chunks (escalate-only)
  └─ RUN   a decoy agent runs the repo in an offline Docker cage rigged with
           DNS/HTTP(S) sinks and honeytokens
        ↓
  verdict (ALLOW / ASK / BLOCK, fail-closed) → agent hook stops the coding agent
```

## Layout

| Path | What | Owner |
|---|---|---|
| `read/` | READ scanner: walker, decoders, chunker, detector, judge | [ensevengg](https://github.com/ensevengg) |
| `run/` | sandbox, sinks, honeytokens, decoy runner, verdict engine, CLI | [pixelash459](https://github.com/pixelash459) |
| `attacks/` | attack repos, obfuscation synthesizer, decoders, per-repo harness | [Shellghostt](https://github.com/Shellghostt) |
| `hooks/` | Gate A / Gate B agent hook, verdict cache, Claude Code installer | [Shellghostt](https://github.com/Shellghostt) |
| `tests/` | per-component test suites (`read/`, `run/`, `attacks/`) | all |
| `demo/` | three-minute beat sheet (`demo/run_demo.sh`) | all |
| `docs/` | shared contracts (`verdict.schema.json`) and `HOOKS.md` | all |

Status: READ and RUN in progress; the ATTACK side, decoder plugin and agent
hook are implemented and tested on CPU.

**Known result — decoy trial failed.** On 2026-10-28, Muse Spark was run ten
times against repo #1 (`readme-bait-curl`) through the decoy loop in PR #12. It
did not attempt exfiltration in any run: **0/10 bites** against a required
`>= 8/10`. All ten runs were complete and error-free, so this is a real miss,
not a broken harness. Repo #1 is a negative control for this model. Raw
evidence: [`docs/decoy-trial/`](docs/decoy-trial/); protocol and analysis:
[`docs/DECOY_TRIAL.md`](docs/DECOY_TRIAL.md).

## Quick start (ATTACK side)

No GPU and no model download are needed for the attack package:

```bash
python -m attacks build --check       # generated repos/manifests are current
python -m attacks lint                # safety rails: *.example + 10.13.37.0/24 only
python -m attacks harness             # all attack repos, READ gate, CPU stand-in
python -m attacks check               # lint + drift + gate
python -m hooks selftest              # 11 gate decisions
python -m hooks install --scope user --dry-run
bash demo/run_demo.sh                 # three-minute demo
```

Manifest contract, transform table, repo catalogue and safety rails:
[`attacks/README.md`](attacks/README.md). Gate A/B, output schemas, cache and
fail-closed matrix: [`docs/HOOKS.md`](docs/HOOKS.md).

## Quick start (READ side)

```bash
pip install -e ".[test]"             # add ".[train]" for the training pipeline
git clone https://github.com/uiuc-kang-lab/InjecAgent injectionagent/InjecAgent   # frozen eval set
baitwatch-read scan <repo>           # human-readable findings
baitwatch-read scan <repo> --json    # input for the verdict engine
pytest -m "not gpu" tests/read       # CPU test suite
```

Detector checkpoint, thresholds and the full API: [`read/README.md`](read/README.md).

## Quick start (RUN side)

Needs Linux, Docker Engine 28 or later, and uv.

```bash
uv sync --frozen --extra dev --extra cpu
docker pull alpine:3.20
docker pull python:3.12-alpine
bash run/check.sh                    # lint, format and RUN tests, including Docker isolation
baitwatch-run sandbox <repo> -- echo hello
```

Plain `uv sync` or pip installs the default torch, which is CUDA-capable on Linux; `--extra cpu` keeps the CPU build for CI and machines without a GPU.

Sandbox boundary, evidence contract and known limits: [`run/README.md`](run/README.md).

## Meta models

- **Llama Prompt Guard 2 (22M), fine-tuned:** local detector
- **Muse Spark (Meta Model API):** judge and plain-English explanations

## Hackathon

Built for the Meta Global AI Developer Hackathon (Indie track, "Push the
Frontier"). Any reused prior work is credited in this section.

The hidden-instruction taxonomy and the "decaffeinate the payload" framing in
the ATTACK slice build on De-Caffeinator (Camel-AI); credit is by name only in
payload-bearing directories, where the safety lint forbids real URLs.

## License

MIT, see [LICENSE](LICENSE). Datasets are not vendored; sources and licenses
are listed in [`read/docs/DATA.md`](read/docs/DATA.md).
