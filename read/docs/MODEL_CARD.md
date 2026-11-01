# Model card — Llama-Prompt-Guard-2-86M · BaitWatch READ detector v1.7

If published, the Llama 4 license requires the model name to start with
"Llama" and the card to carry "Built with Llama" + the license file, plus a
complete data-source list — `read/docs/DATA.md` is that list.

## Model (pinned `v1.7`)

- **Base:** meta-llama/Llama-Prompt-Guard-2-86M (mDeBERTa-v3-base
  architecture, 512-token context, 279M parameters of which 193M are the
  multilingual embeddings).
- **Fine-tune:** the average of three full fine-tunes (seeds 42, 7, 1337),
  each 2 epochs on data v1.7: batch 16 × 2 grad-accum, AdamW lr 2e-5,
  layer-wise LR decay 0.9, frozen embeddings, linear warmup 5%, bf16
  autocast, gradient checkpointing, inverse-frequency class weights. Averaged
  in float32 with `read.training.soup`. About 70 min per seed on the RTX 5060.
- **Thresholds** (`read/model_config.json`): flag at **0.9965**, the lowest
  cutoff that keeps held-out harmless files at ≤0.5% flagged. Scores from
  0.85 up to the flag go to the judge.
- **Task and intended use:** unchanged from v1.5 (below): file windows of
  software repositories, inside the READ scan, behind a fail-closed wrapper
  and an escalate-only judge.

## Training data (v1.7)

41,196 train / 5,716 val rows (28% attacks), built by `read.data.v17.build`
(details and licenses in `read/docs/DATA.md`, "Data v1.7"): scanner-shaped
448/64-token windows of 42 real repos with generated attack and harmless
snippets planted at recorded spans, real agent files (AGENTS.md, CLAUDE.md,
cursor rules, SKILL.md…) as harmless rows, and the earlier sources.

## Evaluation (v1.7 gate, `read.training.eval_v17`, judge off)

| | v1.7 | v1.5f |
|---|---|---|
| Held-out attack files caught at ≤0.5% harmless flagged | **85.3%** (128/150) | 14.0% |
| — hand-written gold attacks planted in held-out repos | 83.3% (110/132) | |
| — Aditya's attack-slice repos | 100% (18/18) | |
| Harmless files flagged (corpus, held-out repos and agent files, lookalikes) | 0.49% (39/7,989) | |
| — held-out agent files | 0.75% (3/400) | |
| Real-world suite (dev set) | 14/15 attacks, 0/32 harmless files | |
| InjecAgent injected-response recall | 0.796 @0.9965 | 0.611 @0.85 |
| InjecAgent raw attacker-instruction recall | 0.169 | 0.355 |

- The target was 96% caught at ≤0.5% flagged; v1.7 does not meet it.
- The single seeds scored 84.0%, 86.0% and 80.7%; their average is pinned.
- The flag threshold is chosen on the harmless pool itself, so 0.49% is a fit,
  not an independent measurement. The held-out attacks were used to compare
  several training variants, so 85.3% is somewhat optimistic.

## Known misses

- **22 of 132 gold attacks**: safety_off 5, supply_chain 5, concealment 4,
  destructive 4, backdoor_code 3, secret_exfil 1. 17 of them score ≤0.07 in
  their file, and several of those score ≥0.99 when the attack text is scored
  alone: a short instruction inside a 448-token window of real docs is read
  as harmless in context.
- **Suite case `fake-install-phish`** (a README telling agents to run
  `curl … | sh` and paste a GitHub token): 0.011, while v1.5f scored 0.97.
  `tests/read/test_realworld_suite.py` lists it as a known miss for `v1.7`.
- Tried and rejected, all at or below 85.3% on the same gate: 1,044 more
  targeted rows for the weak goals, scoring paragraphs on top of windows,
  scoring each window by its top token, and OR-ing in a second model.

## Performance (RTX 5060 8 GB, bf16, batch 16)

- Model load 1.6 s. Full scan of a 216-file repo (621 chunks), model loaded,
  score cache off: **5.6 s** (v1.5's 22M: 3.1 s). The inline-hook preset on a
  231-file repo: 6.5 s; repeat scans hit the chunk-score cache.
- Peak VRAM **1.1 GiB** at batch 16 (2.9 GiB at 64, 5.2 GiB at 128, same
  speed), so the scan batch defaults to 16.
- Scores sit close to 1.0 (harmless files reach 0.9997), so small numeric
  changes move them: re-run the gate after any change to inference (dtype,
  quantization, padding).

## Reproduction (v1.7)

```
python -m read.data.v17.sources && python -m read.data.v17.agentfiles
python -m read.data.v17.build --out <data> --tokenizer <86M base>
python -m read.training.train --base-model <86M base> --data-dir <data> \
  --out-dir <ckpt_seed> --mode full --freeze-embeddings --llrd 0.9 --lr 2e-5 \
  --epochs 2 --batch-size 16 --grad-accum 2 --grad-checkpointing --seed <seed>
python -m read.training.soup --out <soup> <ckpt_42>/epoch2 <ckpt_7>/epoch2 <ckpt_1337>/epoch2
python -m read.training.eval_v17 --model <soup> --out gate.json
# thresholds.json (flag = gate threshold, review_low 0.85) and
# checkpoint_meta.json go next to the soup, then:
python -m read.training.pin <soup> --tag v1.7
```

Checkpoint integrity: SHA-256 pinned in `read/model_config.json`, verified by
`tests/read/test_metrics.py::test_pinned_checkpoint_sha256` on every GPU run.

## Previous pin: v1.5 (22M)

### Model

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

### Training data (seed set v1.5)

See `read/docs/DATA.md` for sources/licenses and the manifest hash. Summary:
19,188 train rows (frozen v1 splits) + 1,051 synthetic patch rows merged
train-only: dependency-changelog voice, tiny dotfile/glob voice, security-doc
voice, overt + covert short attacks. ~35% malicious. val/test splits are
byte-identical across v1/v1.5/v2 (enforced by `--merge-mode` + a test).

### Evaluation (generated JSONs in read/results/, summary in results/README.md)

- **InjecAgent (frozen, 2,108 cases, never trained on):** injected-response
  recall 0.693 @0.84 (overt enhanced variants 0.93+, covert base variants
  0.36–0.52); raw attacker-instruction recall 0.32. Base-model zero-shot was
  0.036 — the fine-tune is what detects covert payloads.
- **Benign corpus (10 real repos, held out):** file FPR 0.0391, chunk FPR
  0.0121 — above the D4 2% bar; dominated by machine-generated artifacts and
  the deliberately scary security-doc repos (see results/README.md).
- **Val/test:** test precision 0.947 / recall 0.848 / F1 0.885 at 0.84.
- **Fixtures:** benign 0/8 flagged, attack 4/4 flagged (0.90–0.99).
- Threshold chosen on the validation split only (F2 subject to ≤2% chunk FPR).

### Performance (RTX 5060 8 GB, bf16)

- Model load ~1.5 s; warm scan of a 216-file repo / 653 chunks: **3.07 s**;
  peak VRAM during scan **1.60 GB** — leaves room for the 8B decoy under the
  7.5 GB budget (roadmap D5 gate).

### Limitations

- Only ~2.9k of the malicious seed rows are repo-file voice; llmail is
  email/chat voice, so per-source metrics matter more than the average.
- English-centric (inherited from the base model).
- Encoded payloads (base64, zero-width) are only caught after decoding — the
  decoder layer is part of the pipeline, not the model.
- Chunks longer than 512 tokens are split; an attack split across many chunks
  with heavy benign padding may score low on every chunk (overlap mitigates,
  does not eliminate).
- Real-corpus file FPR (3.9%) is the headline number to improve on D4 with
  v2 (86M) + scary-benign negatives; the pinned gates in model_config.json
  are the regression guard meanwhile.

### Reproduction

```
python -m read.data.prepare && python -m read.data.leakage
python -m read.training.train --out-dir ~/.local/share/baitwatch/models/v1_22m
python -m read.training.tune_threshold ~/.local/share/baitwatch/models/v1_22m
python -m read.training.evaluate ~/.local/share/baitwatch/models/v1_22m
```

## "Built with Llama"

Fine-tuned from Llama Prompt Guard 2 under the Llama license; the license
file ships with any published checkpoint.
