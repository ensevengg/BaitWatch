# Model card — Llama-Prompt-Guard-2-22M · BaitWatch READ detector v1.5

If published, the Llama 4 license requires the model name to start with
"Llama" and the card to carry "Built with Llama" + the license file, plus a
complete data-source list — `read/docs/DATA.md` is that list.

## Model

- **Base:** meta-llama/Llama-Prompt-Guard-2-22M (DeBERTa-v3-xsmall
  architecture, 512-token context). Local copy checksum-verified against the
  Hub on Oct 25.
- **Fine-tune (pinned `v1.5`):** full fine-tune of the 22M — 2 epochs, batch
  16 × 2 grad-accum, AdamW lr 1e-5, linear warmup 5%, bf16 autocast, class
  weights inverse-frequency, seed 42. Trained in 2,020 steps / ~17 min on the
  RTX 5060. (The roadmap's v1 was head-only; it underfit badly — AP 0.86 vs
  0.98 — so the operating checkpoint is a full FT of the same 22M base. v2's
  86M run on D4 uses the same recipe.)
- **Task:** binary — text chunk is a prompt-injection attempt against an AI
  coding agent (1) or not (0). Label map pinned in code: index 0 = benign,
  1 = injection (the base config ships no names).
- **Intended use:** scoring file chunks of software repositories inside the
  BaitWatch READ scan, behind a threshold tuned on validation data, with a
  fail-closed wrapper and an escalate-only LLM judge. **Not** a general
  prompt-injection classifier for chat traffic, and not a defense on its own.

## Training data (seed set v1.5)

See `read/docs/DATA.md` for sources/licenses and the manifest hash. Summary:
19,188 train rows (frozen v1 splits) + 1,051 synthetic patch rows merged
train-only: dependency-changelog voice, tiny dotfile/glob voice, security-doc
voice, overt + covert short attacks. ~35% malicious. val/test splits are
byte-identical across v1/v1.5/v2 (enforced by `--merge-mode` + a test).

## Evaluation (generated JSONs in read/results/, summary in results/README.md)

- **InjecAgent (frozen, 2,108 cases, never trained on):** injected-response
  recall 0.693 @0.84 (overt enhanced variants 0.93+, covert base variants
  0.36–0.52); raw attacker-instruction recall 0.32. Base-model zero-shot was
  0.036 — the fine-tune is what detects covert payloads.
- **Benign corpus (10 real repos, held out):** file FPR 0.089, chunk FPR
  0.034 — above the D4 2% bar; dominated by machine-generated artifacts and
  the deliberately scary security-doc repos (see results/README.md).
- **Val/test:** test precision 0.947 / recall 0.848 / F1 0.885 at 0.84.
- **Fixtures:** benign 0/8 flagged, attack 4/4 flagged (0.90–0.99).
- Threshold chosen on the validation split only (F2 subject to ≤2% chunk FPR).

## Performance (RTX 5060 8 GB, bf16)

- Model load ~1.5 s; warm scan of a 216-file repo / 653 chunks: **3.07 s**;
  peak VRAM during scan **1.60 GB** — leaves room for the 8B decoy under the
  7.5 GB budget (roadmap D5 gate).

## Limitations

- Only ~2.9k of the malicious seed rows are repo-file voice; llmail is
  email/chat voice, so per-source metrics matter more than the average.
- English-centric (inherited from the base model).
- Encoded payloads (base64, zero-width) are only caught after decoding — the
  decoder layer is part of the pipeline, not the model.
- Chunks longer than 512 tokens are split; an attack split across many chunks
  with heavy benign padding may score low on every chunk (overlap mitigates,
  does not eliminate).
- Real-corpus file FPR (8.9%) is the headline number to improve on D4 with
  v2 (86M) + scary-benign negatives; the pinned gates in model_config.json
  are the regression guard meanwhile.

## Reproduction

```
python -m read.data.prepare && python -m read.data.leakage
python -m read.training.train --out-dir ~/.local/share/baitwatch/models/v1_22m
python -m read.training.tune_threshold ~/.local/share/baitwatch/models/v1_22m
python -m read.training.evaluate ~/.local/share/baitwatch/models/v1_22m
```

Checkpoint integrity: SHA-256 pinned in `read/model_config.json`, verified by
`tests/read/test_metrics.py::test_pinned_checkpoint_sha256` on every GPU run.

## "Built with Llama"

Fine-tuned from Llama Prompt Guard 2 under the Llama license; the license
file ships with any published checkpoint.
