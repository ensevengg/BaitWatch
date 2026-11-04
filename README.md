# BaitWatch

Stops prompt-injection attacks hidden in a repository before your AI coding agent acts on them.

![BaitWatch stopping a prompt on a poisoned test repo](docs/assets/hook-blocked.gif)

*A test repo we built, with hidden instructions in its docs. Waits are shortened and local paths trimmed.*

## What it does

- Installs as a Claude Code hook, so your normal workflow stays the same.
- Scans the repo when you send a prompt.
- Checks files again before each tool call.
- Decodes hidden text first, including invisible Unicode.
- Answers with allow, ask or block, and explains why in plain English.

## What a block looks like

![A blocked prompt with the reason for each flagged file](docs/assets/hook-blocked.png)

## How it works

```
untrusted repo
  ├─ READ  fine-tuned Llama Prompt Guard 2 reads every file, including decoded
  │        hidden payloads; Muse Spark judges flagged and suspicious chunks
  └─ RUN   a decoy agent runs the repo in an offline Docker cage rigged with
           DNS/HTTP(S) sinks and honeytokens
        ↓
  verdict (ALLOW / ASK / BLOCK, fail-closed) → agent hook stops the coding agent
```

## Results

| Test | Result |
|---|---|
| Our attack repos | 17 of 17 stopped (15 block, 2 ask) |
| Harmless twins of those repos | 5 of 5 allowed |
| 100 popular repos it had not seen | 77 allow, 17 ask, 6 block |
| Detector alone, held-out attacks | 128 of 150 caught |
| Detector alone, held-out harmless files | 39 of 7,989 flagged |

Full numbers and known misses: [model card](read/docs/MODEL_CARD.md) and [attack report](docs/ATTACKS_REPORT.md).

## Install the hook

```bash
pip install -e ".[dev]"
python -m hooks install --scope user --dry-run   # preview the change
python -m hooks install --scope user
python -m hooks install --scope user --uninstall # remove it
```

- Restart the agent after installing.
- Set `META_API_KEY` to turn on the Muse Spark judge.
- The judge sends suspicious repo text to Meta's API.
- The trained detector is not in this repo. Set `BAITWATCH_MODEL_PATH` to your copy.

Details: [`docs/HOOKS.md`](docs/HOOKS.md).

## Run each part

**Attacks** (no GPU or model download needed):

```bash
python -m attacks check     # lint, drift check and READ gate
python -m hooks selftest    # 11 gate decisions
bash demo/run_demo.sh       # three-minute demo
```

**READ scanner:**

```bash
pip install -e ".[test]"             # add ".[train]" for training
baitwatch-read scan <repo>           # readable findings
baitwatch-read scan <repo> --json    # input for the verdict engine
pytest -m "not gpu" tests/read       # CPU tests
```

**RUN sandbox** (needs Linux, Docker Engine 28 or later, and uv):

```bash
bash run/setup.sh                    # deps, images, cage build, smoke scan
bash run/setup.sh --tests            # same, plus lint, format and tests
baitwatch-run sandbox <repo> -- echo hello
```

## Repository layout

| Path | What |
|---|---|
| [`read/`](read/README.md) | Scanner: walker, decoders, chunker, detector, judge |
| [`run/`](run/README.md) | Sandbox, sinks, honeytokens, decoy runner, verdict engine, CLI |
| [`attacks/`](attacks/README.md) | Attack repos, obfuscation synthesizer, per-repo harness |
| `hooks/` | Prompt and tool-call gates, verdict cache, installer |
| `tests/` | Test suites for each component |
| `demo/` | Demo script |
| `docs/` | Shared contracts and hook docs |

## Known limits

- No scanner is a guarantee. An allow lowers the risk; it does not prove a repo is safe.
- The decoy agent is not a reliable trigger. Muse Spark took the bait 0 of 10 times on repo #1. See the [trial write-up](docs/DECOY_TRIAL.md).

## Meta models

- **Llama Prompt Guard 2 (86M), fine-tuned:** local detector
- **Muse Spark (Meta Model API):** judge and plain-English explanations

## Hackathon and credits

- Built for the Meta Global AI Developer Hackathon (Indie track, "Push the Frontier").
- Team: [ensevengg](https://github.com/ensevengg), [pixelash459](https://github.com/pixelash459), [Shellghostt](https://github.com/Shellghostt).
- The hidden-instruction taxonomy and "decaffeinate the payload" framing build on De-Caffeinator (Camel-AI).

## License

MIT, see [LICENSE](LICENSE). Datasets are not vendored; sources and licenses are in [`read/docs/DATA.md`](read/docs/DATA.md).
