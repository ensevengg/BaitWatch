# Three-minute demo

The ATTACK slice in one run: obfuscation, detection, the agent hook, and the
safety rails. No network, no GPU, no model download.

```bash
bash demo/run_demo.sh          # Linux / macOS / WSL / Git Bash
PYTHON=python3 bash demo/run_demo.sh
```

On Windows PowerShell, run it through Git Bash or WSL:

```powershell
bash demo/run_demo.sh
```

If `python` is not the interpreter with `pytest`, set `PYTHON`:

```bash
PYTHON=/usr/bin/python3 bash demo/run_demo.sh
```

## Beat sheet (target: 2:50)

| Time | Beat | What the audience sees |
|---|---|---|
| 0:00 | Cold open | `attacks check`: lint clean, generated tree clean, five repos pass the READ gate |
| 0:15 | D2: obfuscation | One payload encoded nine ways; every channel recovers the seed |
| 1:00 | D3: repo #1 | Harness table: READ flags the README, zero extra files; Gate B refuses the `.env` POST |
| 1:45 | Gates | Hook selftest (11/11), Gate A catches invisible instructions, installer refuses an old host and dry-runs a merge for 2.1.295 |
| 2:30 | Close | Safety lint clean, leakage check skips without a corpus, one-line summary |

## What it proves

- **D2:** `decode(encode(seed)) == seed` for base64, hex, rot13, zero-width
  bits, Unicode tags, variation selectors, markdown-image alt text,
  `eval(atob(...))`, and bidi Trojan Source.
- **D3:** the manifest is ground truth. The harness stages a copy without
  `MANIFEST.json`, flags every `READ`/`both` file, and fails on any extra file.
- **Hook:** Gate A screens the prompt and repo; Gate B denies exfiltration,
  remote pipe-to-shell, and credential reads. A crash is a deny.
- **Safety:** every URL is `*.example`, every IP is in `10.13.37.0/24`, and
  the lint rejects real keys and committed `.env` files.

## Expected output

The exact wording tracks the generator, but the shape is stable:

```
lint: clean
generated tree: clean
gate READ readme-bait-curl: ok (3/3 payloads recovered)
...
recovered 9/9 channels from one seed
...
readme-bait-curl  READ  yes  1  1  0  0  3/3  keyword
...
{"gate":"B","verdict":"block","reason":"repository is blocked: ...","source":"repo",...}
...
selftest: 11/11
...
PASS
```

`python -m attacks check` ends with `PASS: lint, generated tree, and READ
gate`; `python -m hooks selftest` ends with `selftest: 11/11`.

## Notes

- The demo uses `BAITWATCH_HOOK_SCANNER=keyword`, the deterministic CPU
  stand-in. The product default is the real `read.scan` model; on a machine
  with torch and a Prompt Guard checkpoint, run
  `python -m attacks.harness --scanner read`.
- The hook cache is written under `TMPDIR` and deleted at the start of the
  run, so the first gate is a cold scan.
- The demo writes nothing into the repository: the installer runs with
  `--dry-run` and the generated trees are only read.
- The leakage beat intentionally uses a nonexistent corpus directory and
  reports "skipped". On Manan's machine, pass the real one:
  `python -m attacks leakage --data-dir <path>`.
