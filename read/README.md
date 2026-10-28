# BaitWatch READ side (Manan)

The brain of BaitWatch: everything that *reads* a repo before an agent is
allowed to run in it.

```
walk (symlink-safe) → decode hidden payloads → chunk (≤512 tokens)
   → fine-tuned Llama Prompt Guard 2 detector → Muse Spark judge (escalate-only)
   → Finding[] for the verdict engine
```

Owner: Manan.
Contract: `read.scan(path) → [Finding{file, chunk_id, score, layer, evidence}]`.

## Quick start

```bash
python -m read scan <repo>            # human output (also: baitwatch-read scan <repo>)
python -m read scan <repo> -v         # + every finding and the uncertain band
python -m read scan <repo> --json     # verdict-engine input
python -m read.scan <repo>            # same, module form
python -m read selftest               # detector sanity scores
```

Exit codes: `0` clean · `1` flagged findings · `2` scan error · `3`
incomplete evidence (nothing flagged, but the scan could not cover
everything — see `stats.incomplete_reasons`). Callers must treat 2 and 3 as
*not clean* (fail closed).

## Public API

```python
from read import scan, ReadConfig

result = scan("path/to/repo")              # ScanResult — iterable of Finding
for finding in result.flagged:             # only status == "flagged"
    print(finding.file, finding.chunk_id, finding.score, finding.layer)
print(result.to_dict())                    # JSON for the verdict engine
```

- `scan()` keeps the model warm in a module cache: a daemon/hook process pays
  the model load once, then every scan is inference-only (READ target < 3 s).
- Pass `detector=`/`judge=`/`decoders=` to inject doubles in tests.
- Single files and directories both work; everything is repo-relative.

## Finding JSON contract (for Ashutosh's verdict engine)

```json
{
  "file": "AGENTS.md",
  "chunk_id": 1,
  "score": 0.9742,
  "layer": "model",            // "model" | "judge" | "system"
  "evidence": {"text": "…≤200 chars…", "line": 14, "model_score": 0.9742},
  "status": "flagged",         // "flagged" | "reviewed"
  "explanation": null,          // judge plain-English when available
  "decoded": true,              // chunk came from a decoded hidden payload
  "decoder": "html_comment"
}
```

Wrapped by `ScanResult.to_dict()` as `{"findings": [...], "stats": {...},
"read_verdict": "attack"|"incomplete"|"clean"}`. `read_verdict` is the READ
layer's opinion only — the fused ALLOW/ASK/BLOCK decision is Ashutosh's
verdict engine.

Fail-closed semantics the engine can rely on:

- Unreadable files and detector failures produce a **flagged** finding —
  layer `"system"` when BaitWatch itself is the problem — or a raised
  exception for "couldn't scan at all". An error is never clean.
- A review-band chunk (`review_low..flag_threshold`) that no judge cleared —
  judge disabled (`--no-judge` / `ReadConfig.quick()`), judge unavailable
  (down/timeout/garbage/spend cap), or judge budget exhausted — is **not**
  flagged and **not** clean: it stays `status="reviewed"` with
  `evidence["note"]` saying why it was not judged, and the verdict is
  `"incomplete"` (CLI exit 3). Judge-unavailable in the band no longer makes
  a benign repo read as `"attack"`.
- Evidence the scan could not cover makes `read_verdict` `"incomplete"`,
  never `"clean"`; `stats.incomplete_reasons` says why (with a count of
  unjudged review-band chunks): walker file cap, decoded content past its
  cap, decoded views the per-file chunk budget could not cover
  (`stats.decoded_views_uncovered`), review-band chunks the per-scan judge
  budget did not reach (`stats.judge_skipped`, status `"reviewed"` with a
  note), decoder crashes, and — with `ReadConfig.strict_coverage` —
  oversized files.
- `max_chunks_per_file` is one budget per file across head/tail segments and
  decoded views. Decoded views are measured first and get what they need, up
  to about half the budget, shared fairly between views; the original view
  gets the rest. A small comment or blob can no longer starve the original,
  and a large file can no longer starve a hidden payload.
- In-repo directory symlinks are followed under the link path, even into
  excluded dirs (`.cursor/rules -> ../dist/rules`); outside-repo links and
  links back to an ancestor are not. Each real directory is listed at most
  once per priority tier, so link fan-out stays linear.
- Oversized files are scanned head + tail (`tail_bytes`, `tail_windows`);
  the unscanned middle is reported in `stats.files_truncated` /
  `stats.partial_files` / `stats.chunks_dropped`.
- Base64/hex blobs and PEM blocks are masked before scoring (including any
  intermediate nested views); their readable content is scored through the
  decoder views (base64 incl. `KEY=`/unpadded/URL-safe/wrapped, base32, hex,
  HTML comments, HTML entities, URL percent-encoding, rot13, reversed text,
  zero-width, variation selectors, Unicode tags; nested three levels deep).
  HTML-entity / URL decoders are gated (decoded runs, multi-escape lines, or
  materially encoded text only) and rot13/reversed keep an English-likeness
  gate, so ordinary files containing `&amp;` or `%20` gain no decoded view.
- The judge can **escalate** (flag an uncertain chunk, raise a score) but can
  **never clear** a chunk the model flagged — at most it records its dissent
  in `explanation`. Inside the uncertain band (`review_low..flag_threshold`)
  a "benign" verdict downgrades the chunk to `status="reviewed"`.

## Detector

Fine-tuned Llama Prompt Guard 2 (22M v1; 86M is the D4 v2 candidate). The
base model ships no label names, so index→name mapping is pinned in code:
**0 = benign, 1 = injection** (`read/detector.py`, asserted in tests).

- The trained checkpoint lives outside the repo
  (`~/.local/share/baitwatch/models/`), pinned by SHA-256 in
  `read/model_config.json` together with the operating thresholds — that file
  is what `scan()` reads, and what `tests/read/test_metrics.py` guards.
- Thresholds are chosen on the **validation** split only
  (`python -m read.training.tune_threshold`), never on test.
- Model path resolution: explicit arg → `BAITWATCH_MODEL_PATH` → pinned
  config → `/mnt/d/hf_models/Llama-Prompt-Guard-2-22M|86M`.

## Judge (Muse Spark)

`read/judge.py` speaks the OpenAI chat-completions dialect on stdlib urllib
to keep the READ side dependency-free. Endpoints (first live one wins):
Meta Model API (key in `META_API_KEY`) → local `llama-server` with the
Llama-3.2-3B GGUF. Design rules: 10 s timeout, only suspicious chunks are
sent, escalate-only, per-scan call/token budgets, and a persistent USD ledger
capped at $120 per key in code (a spend-limit notice does not stop billing).
Details: `read/docs/JUDGE.md`.

## Decoders (integration point for Aditya)

`read/decoders.py` turns a file's text into decoded *views* (base64 blobs,
HTML comments, zero-width smuggles) that get chunked and scored alongside the
original; findings report which decoder surfaced them. Aditya's transform
table plugs in via a `baitwatch_decoders` module (or `attacks/decoders.py`)
defining `register(registry)`. His contract stays: `decode(encode(seed)) == seed`.

## Data & training (D2 pipeline)

```bash
python -m read.data.prepare          # raw datasets → deduped stratified parquet
python -m read.data.leakage          # splits vs frozen eval sets (InjecAgent + seeds)
python -m read.training.train --out-dir ~/.local/share/baitwatch/models/v1_22m
python -m read.training.tune_threshold ~/.local/share/baitwatch/models/v1_22m
python -m read.training.evaluate ~/.local/share/baitwatch/models/v1_22m \
    --out read/results/v1_metrics.json
python -m read.training.pin ~/.local/share/baitwatch/models/v1_22m --tag v1
```

Raw data is never committed (public-repo rule): download scripts with pinned
sources live in `read/data/`, licenses are documented in `read/docs/DATA.md`.
The benign corpus is cloned on demand (`python -m read.data.benign_corpus
~/corpus`) and locked to commit SHAs in `corpus_lock.json`.

## Tests

```
pytest -m "not gpu"     # CI suite: walker safety, chunking, decoders, judge
                        # (mock HTTP), scan fail-closed paths, data pipeline
pytest -m gpu           # demo machine: pinned-checkpoint SHA, label map +
                        # sanity scores, InjecAgent recall gate, benign FPR gate
```

Chunking/model tests skip automatically where no Prompt Guard 2 model dir
exists (CI) — they run here. Test fixtures double as the scary-benign corpus
seed: benign_repo quotes an injection in its security docs on purpose.
