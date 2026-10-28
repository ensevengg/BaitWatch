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
