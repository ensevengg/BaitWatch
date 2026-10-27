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
| `attacks/` | attack repos, obfuscation synthesizer, decoders, agent hook | [Shellghostt](https://github.com/Shellghostt) |
| `tests/` | per-component test suites | all |
| `docs/` | shared contracts (`verdict.schema.json`) | all |

Status: READ side in progress; RUN and ATTACK sides land in their folders.

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

## License

MIT, see [LICENSE](LICENSE). Datasets are not vendored; sources and licenses
are listed in [`read/docs/DATA.md`](read/docs/DATA.md).
