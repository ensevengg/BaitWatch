# DATA — sources and licenses

The BaitWatch repo is public, so **no raw dataset rows, gated data, or repo
copies are ever committed**. Everything below is downloaded to
`~/.local/share/baitwatch/` (or `$BAITWATCH_DATA_ROOT`, read-only) by pinned
scripts; only download code and this document live in the repo.

Every number we publish traces back to the input hashes recorded in
`~/.local/share/baitwatch/data/manifest.json`.

## Training / validation data

| Source | HF id / URL | License | Used for | Rows (raw) |
|---|---|---|---|---|
| prodnull | `prompt-injection-repo-dataset` (train.jsonl) | Apache-2.0 | repo-file voice, both labels | 5,671 |
| llmail-inject | `microsoft/llmail-inject-challenge`, labelled_unique_submissions_phase{1,2}.json | MIT | email/chat voice: attacks + benign; "Unclear" dropped | 198,044 entries |
| OpenCodeInstruct | `nvidia/OpenCodeInstruct` train shards (CC-BY-4.0) | CC-BY-4.0 | benign code voice (`output` column) | sampled 4,000 |

Seed set composition and dedupe stats are in the manifest (current run:
31,620 raw → 23,980 kept; 1,846 exact + 5,794 near-duplicates removed;
80/10/10 stratified by source+label, seed 42).

Planned additions (roadmap D2/D3):
- **HackAPrompt** (gated on HF — Manan accepts terms before use; download
  script lands here once terms are accepted; never committed).
- **Muse Spark pilot rows** (~100, later ~3k): repo-file-voice rewrites +
  scary-benign negatives, tagged `source=muse_spark`, ingested with
  `read.data.prepare --extra-train rows.jsonl`. Schema rule enforced in code:
  muse_spark rows never enter the test split.
- **Aditya's obfuscation rows** (+5k, `source=attack_obfuscation`).

## Data v1.7 (`read/data/v17/`)

v1.6 trained on emails and one-line prompts: under 5% of its attack rows looked
like a repo file, and 15% of its attack rows were cut off at 512 tokens. v1.7
trains on what the scanner actually scores: 448/64-token windows of real repo
files, cut by the scanner's own `Chunker` after the scanner's blob masking.

| Part | Where it comes from | Label |
|---|---|---|
| Snippets | 18 generated batches (Muse Wonder): 12 attacker goals × 120 rows, 6 harmless lookalike voices × 150 rows; ~30% non-English in both labels | 1 / 0 |
| Carriers | shallow clones of 42 permissively licensed repos (`sources.TRAIN_REPOS`) | 0 |
| Agent files | real AGENTS.md / CLAUDE.md / cursor rules / copilot instructions / SKILL.md from permissively licensed repos (GitHub code search, ≥10 stars), screened by hand | 0 |
| Old sources | prodnull, llmail (≤448 tokens, capped), OpenCodeInstruct, patch_v16, harmless short snippets | as before |
| Noise | reversed / ROT13 / base32 / hex / identifier soup / minified JS | 0 |

Rules the builder enforces:
- **Exact labels.** A snippet is planted at a recorded character span. A
  window is label 1 only if it holds the whole span (or 80%+ of a long one);
  windows that cut it are dropped; windows that miss it are label 0.
- **Minimal pairs.** Each planted attack window also yields the same window
  from the clean file, and one other window of the same file.
- **No label shortcuts.** Snippets use `{host}`/`{ip}`/`{project}`/`{pkg}`
  placeholders filled from one shared pool of reserved names (RFC 2606/6761),
  so hostnames carry no signal; attack rows that name themselves (evil,
  malicious, payload, inject…) are dropped; both labels share one markup
  distribution (HTML comment, blockquote, `<details>`, JSON key, comment
  prefixes) and harmless snippets are planted more often so planted windows
  split evenly. Old attack rows have loaded hostnames (`evil.example`…)
  rewritten from the same pool.
- **Disjoint test.** 20% of snippets (by id) are held out and planted only
  into `sources.TEST_REPOS` carriers → `test_planted.parquet`, reported apart
  from `test.parquet` because it is generated text. `test.parquet` is the
  v1.6 test split, byte-identical.
- **Leakage.** Train, val and test_planted are checked against the suite
  fixtures, InjecAgent and Aditya's attack-slice payloads; leaked rows are
  dropped and counted in the manifest.

Build: `python -m read.data.v17.sources` (clones + license lock),
`python -m read.data.v17.agentfiles`, then
`python -m read.data.v17.build --tokenizer <base model>` (windows depend on
the tokenizer, so build once per base model).

### v1.7 gate (`read.training.eval_v17`)

Target: **≥96% of held-out attack files caught at ≤0.5% of held-out harmless
files flagged**, detector + decoders, judge off, every set run through
`read.scan`.
- Attacks: the hand-written gold set (`read.data.v17.gold`: 120 attacks over
  12 goals plus 12 encoded variants, different author and host pool from the
  training snippets, planted into TEST_REPOS files) and Aditya's five
  attack-slice repos (answer keys removed). The suite is reported but is a
  dev set.
- Harmless: the FPR corpus (10 repos) + TEST_REPOS files + the held-out 20%
  of fetched agent files (repos never trained on; `agentfiles.split_for_repo`)
  + gold lookalikes + suite benign files. The gate threshold is the lowest one
  that keeps the pooled set at ≤0.5%; per-set rates (agent files, for example)
  can be higher and are reported separately.

Agent files are screened before use (`read.data.v17.screen`): pattern hits
and the highest-scoring files are read by hand and anything hostile goes into
`agentfiles_exclude.json`. The 2026-10-29 screen of 1,836 files excluded none
(notes in `v17_raw/agentfiles_review.md`).

## Frozen evaluation sets (never trained on)

| Set | Source | License | Role |
|---|---|---|---|
| InjecAgent | `uiuc-kang-lab/InjecAgent` (cloned at `injectionagent/InjecAgent`) | MIT | recall: 2,108 attacker instructions + injected tool responses (dh/ds × base/enhanced) |
| Aditya's attack seeds | (D3) | — | leakage check input via `read.data.leakage --extra-frozen` |

Leakage rule: before any number is reported,
`python -m read.data.leakage --report <file>` must pass on all splits (exact,
embedded-substring, and word-3-gram Jaccard ≥ 0.8 checks).

## Benign corpus (false-positive measuring stick)

Cloned on demand by `python -m read.data.benign_corpus <target>`; the script
records the resolved commit of every clone in `corpus_lock.json` next to the
clones, so any FPR number names the exact commits it measured. Starter list
(D2, grow to 30 with Aditya on D4): microsoft/llmail-inject-challenge,
OWASP/CheatSheetSeries, laravel/laravel (.env.example), jquery/jquery
(minified JS), expressjs/express, psf/requests, pallets/flask,
sindresorhus/awesome, github/gitignore, httpie/cli. Verify each repo's
license file at clone time and note it in the lock entry before quoting FPR.

Scary-benign coverage the corpus must include (test matrix): security docs
*about* prompt injection, base64 data-URIs, minified JS, Hindi/Persian text
with legitimate zero-width joiners, `.env.example` files, and lots of
AGENTS.md/CLAUDE.md/.cursorrules agent-config files.

## Base models

- `meta-llama/Llama-Prompt-Guard-2-22M` and `-86M` — local copies verified
  under `$HOME/hf_models/` (checksums matched the Hub on Oct 25). Llama 4 license
  applies to published fine-tunes (name must start with "Llama", plus
  "Built with Llama" and the license file — see MODEL_CARD.md).
- `meta-llama/Llama-3.2-3B-Instruct` (Q6_K GGUF) — local judge fallback,
  served with `llama-server`.
