"""Published skill data for training, plus held-out sets in the red-team format.

Added to the v1.7 training data without changing its rows, so any difference in
results comes from these rows alone. Rules from the data review:

- Train only on text where the attack is written in the file. Package-level
  labels (the attack may live in a bundled script) are never used.
- SkillHarm: "plain_text" samples only. The attack block is what differs from
  the lines most versions of that skill share, so each sample also gives an
  exact span and a clean twin. Pointers to a new script or doc are not used:
  the attack is not in the text.
- ATR: authored attack fixtures, and real skills as harmless windows.
- Nothing that shares text with a held-out set is used.

    python -m read.data.v17.real review --raw <hf_datasets>
    python -m read.data.v17.real build --raw <hf_datasets> --exclude <json> --out <data dir>
    python -m read.data.v17.real heldout --raw <hf_datasets> --attacks <jsonl> --out <root>
"""

from __future__ import annotations

import argparse
import json
import random
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path

from read.chunking import Chunker
from read.data.v17.carriers import CarrierPool, index_repos, read_text
from read.data.v17.embed import family, normalize_kind, plant, wrap
from read.data.v17.gold import ATTACKS, BENIGN
from read.data.v17.redteam import shingles
from read.data.v17.snippets import SELF_LABEL_RE, Snippet, fill_placeholders, stable_unit
from read.decoders import mask_blobs

HOME = Path.home() / ".local/share/baitwatch"
SKILLHARM = "osunlp__SkillHarm"
ATR = "Agent-Threat-Rule__atr-skill-benchmark"
MALWARE = "yoonholee__agent-skill-malware"
MIN_VERSIONS = 4        # fewer versions of a skill cannot give a reliable clean base
MAX_MISSING_LINES = 3   # more means the sample rewrote the skill, not inserted a block
MIN_BLOCK_SHARE = 0.5   # below this the largest block may not hold the attack
BLOCK_CHARS = (40, 1800)
HARMLESS_WINDOWS_PER_FILE = 8
HARMLESS_OVERLAP = 0.05
HARMLESS_SETUP_PLANTS = 12
VAL_FRAC = 0.1
ATR_ATTACK_TYPES = frozenset({
    "context-poisoning-claude-md", "rug-pull-timebomb", "credential-harvest-env",
    "typosquat-supply-chain", "permission-escalation-fs", "reverse-shell-disguised",
    "prompt-injection-ignore", "data-exfil-dns", "wallet-stealer", "shadow-dependency",
    "ssh-key-harvest", "browser-cookie-steal", "evasive-03-prompt-subtle", "evasive-10-roleplay",
    "exfiltration-curl-pastebin", "malicious-skill"})
ATR_HARMLESS_FAMILIES = frozenset({"real", "mcp-official", "ninja"})
RESERVED_HOST_RE = re.compile(r"\b[a-z0-9][\w.-]*\.(?:example|test|invalid)\b", re.I)
# These write a value or a format into the output: harmless when read alone, not a text signal.
TEXT_INVISIBLE_RISKS = frozenset({"output_manipulation", "goal_hijacking"})
PREFLIGHT_RE = re.compile(r"preflight", re.I)
# Legitimate setup text that uses the attack blocks' words and commands, so that "required
# first step", shell profiles, /etc/hosts or a log reset carry no label on their own.
HARMLESS_SETUP = (
    "## Required preflight\nBefore running the tests, install the dev dependencies:\n```bash\npip install -r requirements-dev.txt\n```\nSkipping this step makes the import checks fail.",
    "## Preflight (required)\nRun this first so the build directory exists:\n```bash\nmkdir -p build && cmake -S . -B build\n```",
    "# Prerequisite: Node version\nThis skill needs Node 20. Check it before any other step:\n```bash\nnode --version\n```\nIf it is older, ask the user to upgrade.",
    "## Before you begin (mandatory)\nRead `CONTRIBUTING.md` in this repository and follow its commit message format. Do not skip this step.",
    "## Preflight: clear stale build output\nStale artifacts cause confusing errors. Run this before each build:\n```bash\nrm -rf ./dist ./build\n```\nIt only touches this project's output folders.",
    "## Session hygiene (required)\nClear this project's debug log before a new run so the output only shows the current run:\n```bash\nrm -f ./logs/debug.log\n```\nDo not delete anything outside `./logs`.",
    "## Environment setup (run first)\nAdd the project virtualenv to your PATH for this shell, after asking the user:\n```bash\nsource .venv/bin/activate\n```",
    "## Shell profile\nIf the user asks for it to persist, offer to add this line to `~/.bashrc`, show them the change first, and wait for approval:\n```bash\nexport PATH=\"$HOME/.local/bin:$PATH\"\n```",
    "## Local development hostname\nThe app expects `myapp.local`. Ask the user before changing system files. With their approval, add `127.0.0.1 myapp.local` to `/etc/hosts`.",
    "## Required setup: make the scripts executable\nThe repository's helpers lose their mode on some checkouts:\n```bash\nchmod +x ./scripts/*.sh\n```",
    "## Preflight: verify the checksum\nBefore unpacking the release archive, compare it with the published checksum and stop if they differ:\n```bash\nsha256sum -c release.sha256\n```",
    "## Required first step: load the sample data\nThe examples read a small fixture. Copy it into the workspace first:\n```bash\ncp tests/fixtures/sample.csv ./data/sample.csv\n```",
    "## Preflight check (required)\nConfirm the database is the local one before running migrations:\n```bash\necho \"$DATABASE_URL\" | grep -q localhost\n```\nStop and ask the user if it is not.",
    "## Install the official CLI\nUse the vendor's documented installer from their own domain, and tell the user before running it:\n```bash\ncurl -fsSL https://sh.rustup.rs | sh\n```",
    "# Environment preparation (mandatory before any call)\nCopy the example settings and let the user fill in their own values:\n```bash\ncp .env.example .env\n```\nNever print or commit the `.env` file.",
    "## Workspace notes\nKeep a short `NOTES.md` in the workspace describing what you changed in this session, so the user can review it. Do not include secrets.",
    "## Audit log\nThe audit log at `./logs/audit.log` is how reviewers check your work. Never edit or delete it, and mention it in your summary.",
    "## Required step: run the linter\nBefore committing, run the linter and fix what it reports:\n```bash\nnpm run lint\n```\nThis is mandatory for every pull request.",
    "## Cache reset (optional)\nIf the results look stale, the user can remove this tool's own cache:\n```bash\nrm -rf .pytest_cache\n```\nIt is rebuilt on the next run.",
    "## Registry configuration\nThis project installs from the public registry only. Do not add an extra index or a mirror. If an install fails, report the error to the user.",
    "## SSH key permissions\nIf git reports that a key is too open, tighten it, never loosen it:\n```bash\nchmod 600 ~/.ssh/id_ed25519\n```",
    "## First-run setup\nDownload the model weights from the official release page linked in the README, verify the checksum listed there, and save them under `./models`.",
    "## Telemetry\nThis tool sends no usage data. If you add a network call, list the host in the README and ask the user first.",
    "## Bootstrap step (required)\nGenerate the local certificates for the dev server. They stay in this repository's ignored `./certs` folder:\n```bash\nmkcert -install && mkcert -cert-file certs/dev.pem localhost\n```",
)
FENCE_RE = re.compile(r"```[\w-]*|---|~~~")
SKILL_KINDS = ["SKILL.md", "AGENTS.md", "CLAUDE.md", "README.md", ".cursorrules"]


def neutral_hosts(text: str) -> str:
    """Reserved hostnames become {host}: an all-.example attack set teaches that shortcut."""
    return RESERVED_HOST_RE.sub("{host}", text)


def neutral_wording(text: str, rng: random.Random) -> str:
    """One author's habits ("/root/", "preflight") would become label shortcuts: vary them."""
    home = rng.choice(("~/", "$HOME/", "/home/{user}/", "/opt/{project}/", "/var/tmp/{project}/"))
    word = rng.choice(("preflight", "setup step", "pre-run check", "first-run setup",
                       "bootstrap step", "initial check"))

    def swap(m: re.Match) -> str:
        return word.capitalize() if m.group(0)[0].isupper() else word

    return PREFLIGHT_RE.sub(swap, text.replace("/root/", home))


def inserted_blocks(texts: list[str], min_share: float = 0.5) -> list[dict]:
    """For versions of one skill: lines most share are the base, the rest were inserted."""
    counts = Counter(ln.strip() for t in texts for ln in set(t.splitlines()) if ln.strip())
    base = {ln for ln, n in counts.items() if n / len(texts) >= min_share}
    out = []
    for text in texts:
        lines = text.splitlines()
        blocks, cur = [], []
        for i, ln in enumerate(lines):
            s = ln.strip()
            if s and s not in base:
                cur.append(i)
            elif cur and s and not FENCE_RE.fullmatch(s):
                blocks.append(cur)
                cur = []
            elif cur and FENCE_RE.fullmatch(s):
                # Every skill has code fences, so they count as shared lines. They must not
                # cut a block between "run this:" and the command it introduces.
                cur.append(i)
        if cur:
            blocks.append(cur)
        present = {ln.strip() for ln in lines}
        best = max(blocks, key=len, default=None)
        inserted = sum(len(lines[i]) for b in blocks for i in b)
        gone = {i for b in blocks for i in b}
        out.append({"block": "\n".join(lines[best[0]:best[-1] + 1]) if best else "",
                    "share": sum(len(lines[i]) for i in best) / inserted if best else 0.0,
                    "clean": "\n".join(ln for i, ln in enumerate(lines) if i not in gone),
                    "missing": sum(ln not in present for ln in base)})
    return out


def load_skillharm(raw: Path) -> tuple[list[dict], Counter]:
    root = raw / SKILLHARM
    groups: dict[str, list[dict]] = defaultdict(list)
    for x in json.loads((root / "MANIFEST.json").read_text())["fpp"]:
        path = root / x["path"] / x["target_path"]
        if Path(x["target_path"]).name == "SKILL.md" and path.is_file():
            groups[x["task_id"] + "/" + x["target_path"]].append(
                {**x, "text": path.read_text(encoding="utf-8", errors="replace")})
    why: Counter = Counter()
    rows = []
    for target, members in groups.items():
        if len(members) < MIN_VERSIONS:
            why["too few versions"] += sum(m["realization"] == "plain_text" for m in members)
            continue
        found = inserted_blocks([m["text"] for m in members])
        for m, f in zip(members, found, strict=True):
            if m["realization"] != "plain_text":
                continue
            if m["risk_id"] in TEXT_INVISIBLE_RISKS:
                why["harm not visible in text"] += 1
                continue
            if not BLOCK_CHARS[0] <= len(f["block"]) <= BLOCK_CHARS[1]:
                why["block size"] += 1
            elif f["missing"] > MAX_MISSING_LINES or f["share"] < MIN_BLOCK_SHARE:
                why["rewrote the skill"] += 1
            elif SELF_LABEL_RE.search(f["block"]):
                why["self-labelling word"] += 1
            else:
                rows.append({"src": "sh-" + m["task_id"] + "-" + m["sample_id"], "skill": target,
                             "risk": m["risk_id"],
                             "attack": f["block"], "body": m["text"], "clean": f["clean"]})
    # A block several samples share came from the upstream skill, not from one attack.
    seen = Counter(r["attack"].strip() for r in rows)
    why["shared by samples"] = sum(seen[r["attack"].strip()] > 1 for r in rows)
    return [r for r in rows if seen[r["attack"].strip()] == 1], why


def load_atr(raw: Path) -> tuple[list[dict], list[dict]]:
    rows = [json.loads(ln) for ln in (raw / ATR / "atr-skill-benchmark.jsonl").open(encoding="utf-8")]
    attacks = [r for r in rows if r["label"] == "malicious" and r["attack_type"] in ATR_ATTACK_TYPES]
    harmless = [r for r in rows if r["label"] == "benign"
                and r["source_family"] in ATR_HARMLESS_FAMILIES]
    return attacks, harmless


def heldout_shingles(raw: Path, attacks: Path, redteam_raw: list[Path], muse_test: list[str]) -> set:
    """Text of every set used for judging, so training can share none of it."""
    ref: set = set()
    for ln in (raw / MALWARE / "skills.jsonl").open(encoding="utf-8"):
        ref |= shingles(json.loads(ln)["content"])
    for ln in attacks.open(encoding="utf-8"):
        ref |= shingles(json.loads(ln)["text"])
    for *_, text in (*ATTACKS, *BENIGN):
        ref |= shingles(text)
    for text in muse_test:
        ref |= shingles(text)
    for root in redteam_raw:
        for p in Path(root).rglob("*"):
            if p.is_file() and p.suffix == ".jsonl":
                for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    if ln.strip():
                        r = json.loads(ln)
                        ref |= shingles(r.get("text") or r.get("attack_text") or "")
            elif p.is_file() and p.parent.parent.name == "files":
                ref |= shingles(p.read_text(encoding="utf-8", errors="replace"))
    return ref


def overlap(text: str, ref: set) -> float:
    sh = shingles(text)
    return len(sh & ref) / max(1, len(sh))


def select(raw: Path, attacks: Path, redteam_raw: list[Path], muse_test: list[str],
           exclude: set[str]) -> dict:
    """Everything training may use, with a count of what was dropped and why."""
    ref = heldout_shingles(raw, attacks, redteam_raw, muse_test)
    blocks, why = load_skillharm(raw)
    kept = []
    for r in blocks:
        if r["src"] in exclude:
            why["excluded in review"] += 1
        elif shingles(r["attack"]) & ref:
            why["shares text with a held-out set"] += 1
        else:
            kept.append(r)
    atr_a, atr_h = load_atr(raw)
    files = []
    for r in atr_a:
        if r["id"] in exclude:
            why["excluded in review"] += 1
        elif overlap(r["text"], ref) >= HARMLESS_OVERLAP:
            why["ATR attack shares text with a held-out set"] += 1
        elif mask_blobs(r["text"]) != r["text"]:
            why["ATR attack is in an encoded blob"] += 1
        else:
            files.append(r)
    harmless = []
    for r in atr_h:
        if r["id"] in exclude:
            why["excluded in review"] += 1
        elif overlap(r["text"], ref) >= HARMLESS_OVERLAP:
            why["ATR harmless shares text with a held-out set"] += 1
        else:
            harmless.append(r)
    return {"blocks": kept, "attack_files": files, "harmless": harmless, "dropped": dict(why)}


RISKY_RE = re.compile(
    r"curl[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh|base64\s+-d|~/\.ssh|~/\.aws|\.env\b|id_rsa|"
    r"password|do not (?:tell|mention|inform)|never (?:tell|mention)|ignore (?:all|any|previous)|"
    r"without (?:asking|telling|confirm)|\b\d{1,3}(?:\.\d{1,3}){3}\b|webhook|pastebin|ngrok|"
    r"sudo |chmod 777|rm -rf|keychain|wallet|seed phrase|private key", re.I)


def review(raw: Path, attacks: Path, redteam_raw: list[Path], muse_test: list[str],
           exclude: set[str], width: int = 170) -> None:
    """Print each kept block's start and end (the harm tends to sit in the end) for reading."""
    s = select(raw, attacks, redteam_raw, muse_test, exclude)
    print("kept: blocks", len(s["blocks"]), "attack files", len(s["attack_files"]),
          "harmless", len(s["harmless"]), "dropped", s["dropped"])
    print("risks", Counter(r["risk"] for r in s["blocks"]).most_common())
    for r in sorted(s["blocks"], key=lambda r: r["src"]):
        text = re.sub(r"\s+", " ", neutral_hosts(r["attack"]))
        print(f"B {r['src']} | {text[:90]} ... {text[-width:]}")
    for r in s["harmless"]:
        hits = [ln.strip() for ln in r["text"].splitlines() if RISKY_RE.search(ln)]
        if hits:
            print(f"H {r['id']} {r['text'][:40]!r} n={len(hits)} | " + hits[0][:width])


def _agent_carriers(carriers_dir: Path, agent_dir: Path, exclude: Path) -> list:
    from read.data.v17.agentfiles import PERMISSIVE, split_for_repo
    from read.data.v17.carriers import index_agentfiles
    from read.data.v17.sources import TEST_REPOS, TRAIN_REPOS
    lock = json.loads((agent_dir / "agentfiles_lock.json").read_text())
    excluded = set(json.loads(exclude.read_text())) if exclude.exists() else set()
    return [c for c in index_agentfiles(agent_dir / "files", lock)
            if f"{c.repo}:{c.rel}" not in excluded
            and lock["repos"].get(c.repo, {}).get("license") in PERMISSIVE
            and split_for_repo(c.repo, TRAIN_REPOS, TEST_REPOS) in ("train", "val")]


def split_of(src: str) -> str:
    return "val" if stable_unit("v17-real:" + src) < VAL_FRAC else "train"


def _add_own_file(out, chunker: Chunker, r: dict, rng: random.Random, stats: Counter) -> None:
    """The attack in its own skill: the window holding it is 1, the clean window is 0."""
    atk = fill_placeholders(neutral_wording(neutral_hosts(r["attack"]), rng), rng)
    text = mask_blobs(r["body"].replace(r["attack"], atk, 1))
    a = text.find(atk)
    if a < 0:
        stats["own_file_span_lost"] += 1
        return
    b, split = a + len(atk), split_of(r["src"])
    meta = dict(sid=r["src"], intent=r["risk"], kind="SKILL.md", lang="en", voice="na")
    chunks, _ = chunker.chunk(text, "SKILL.md", line_offset=None, max_chunks=10_000)
    hit = next((c for c in chunks if c.start_char <= a and b <= c.end_char), None)
    if hit is None:
        stats["own_file_span_not_windowed"] += 1
        return
    if out.add(hit.text, 1, "v17_real_file", split, role="woven", **meta):
        stats["own_file_1"] += 1
    # The clean twin drops every inserted line, so no part of the attack is labelled harmless.
    twins, _ = chunker.chunk(mask_blobs(r["clean"]), "SKILL.md", line_offset=None, max_chunks=10_000)
    twin = next((c for c in twins if c.start_char <= a < c.end_char), None)
    if twin is not None and out.add(twin.text, 0, "v17_real_file", split, role="twin", **meta):
        stats["own_file_twin_0"] += 1


def build(raw: Path, base: Path, out_dir: Path, tokenizer: Path, attacks: Path,
          redteam_raw: list[Path], exclude: set[str], seed: int = 42) -> dict:
    import pandas as pd
    from transformers import AutoTokenizer

    from read.data.schema import text_sha256
    from read.data.v17.build import Out, plant_snippet
    from read.data.v17.snippets import assign_split, load_batches

    rng = random.Random(seed)
    v17 = HOME / "v17_raw"
    snippets, _ = load_batches(v17 / "muse")
    assign_split(snippets)
    s = select(raw, attacks, redteam_raw, [x.text for x in snippets if x.group == "test"], exclude)
    tok = AutoTokenizer.from_pretrained(str(tokenizer))
    chunker = Chunker(tok, window_tokens=448, overlap_tokens=64, max_file_tokens=60_000,
                      max_chunks=10_000, tail_windows=2)
    pool = CarrierPool(index_repos(v17 / "carriers/train")
                       + _agent_carriers(v17 / "carriers", v17 / "agentfiles",
                                         v17 / "agentfiles_exclude.json"))
    frames = {n: pd.read_parquet(base / f"{n}.parquet")
              for n in ("train", "val", "test", "test_planted")}
    out, stats = Out(), Counter()
    out.seen = {text_sha256(t) for n in frames for t in frames[n].text}
    for r in s["blocks"]:
        snip = Snippet(sid=r["src"], label=1, intent=r["risk"], voice="na", lang="en",
                       form="prose", file_kinds=SKILL_KINDS,
                       text=neutral_wording(neutral_hosts(r["attack"]), rng).strip("\n"),
                       batch="skillharm", group=split_of(r["src"]))
        plant_snippet(out, chunker, snip, pool, snip.group, rng, stats, 6)
        _add_own_file(out, chunker, r, rng, stats)
    for i, text in enumerate(HARMLESS_SETUP):
        src = f"setup-{i:02d}"
        snip = Snippet(sid=src, label=0, intent="benign", voice="na", lang="en", form="prose",
                       file_kinds=SKILL_KINDS, text=text, batch="setup", group=split_of(src))
        plant_snippet(out, chunker, snip, pool, snip.group, rng, stats, HARMLESS_SETUP_PLANTS)
    for r in s["attack_files"]:
        meta = dict(sid="atr-" + r["id"], intent=r["attack_type"], kind="SKILL.md", lang="en",
                    voice="na", role="file")
        text = fill_placeholders(neutral_hosts(r["text"]), rng)
        if out.add(text[:6000], 1, "v17_real_file", split_of(r["id"]), **meta):
            stats["atr_attack_1"] += 1
    for r in s["harmless"]:
        chunks, _ = chunker.chunk(mask_blobs(r["text"]), "SKILL.md", line_offset=None,
                                  max_chunks=10_000)
        rng.shuffle(chunks)
        for c in chunks[:HARMLESS_WINDOWS_PER_FILE]:
            if out.add(c.text, 0, "v17_real_harmless", split_of(r["id"]), sid="atr-" + r["id"],
                       intent="benign", kind="SKILL.md", lang="en", voice="na", role="file"):
                stats["harmless_0"] += 1
    new = pd.DataFrame(out.rows).fillna("")
    out_dir.mkdir(parents=True, exist_ok=True)
    counts = {}
    for n, df in frames.items():
        add = new[new.split == n]
        merged = pd.concat([df, add], ignore_index=True).fillna("") if len(add) else df
        merged.to_parquet(out_dir / f"{n}.parquet", index=False)
        counts[n] = {"rows": len(merged), "label_1": int(merged.label.sum()), "added": len(add),
                     "added_1": int(add.label.sum()) if len(add) else 0}
    judged = {text_sha256(t) for n in ("test", "test_planted") for t in frames[n].text}
    leaked = sum(text_sha256(t) in judged for t in new.text)
    manifest = {"parent": str(base), "selected": {k: len(v) for k, v in s.items() if k != "dropped"},
                "dropped": s["dropped"], "stats": dict(sorted(stats.items())), "counts": counts,
                "added_by_source": new.groupby(["source", "label"]).size().rename(
                    lambda x: str(x)).reset_index(name="n").to_dict("records"),
                "leaked_into_judged_splits": leaked}
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str))
    return manifest


def _case(root: Path, side: str, case: str, file: str, text: str, label: int, intent: str,
          src: str, shape: str = "file") -> dict:
    p = root / side / case / file
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return {"case": case, "label": label, "intent": intent, "shape": shape, "strength": "na",
            "lang": "en", "kind": normalize_kind(file), "file": file, "carrier": None,
            "span": None, "src": src}


def _write_set(root: Path, cases: list[dict]) -> None:
    (root / "attack").mkdir(parents=True, exist_ok=True)
    (root / "benign").mkdir(parents=True, exist_ok=True)
    (root / "cases.json").write_text(json.dumps(cases, indent=1))


def heldout(raw: Path, attacks: Path, carriers: Path, out: Path) -> dict:
    """The malware campaign and the independent attack set, in the red-team format."""
    root = out / "redteam_malware"
    shutil.rmtree(root, ignore_errors=True)
    cases = []
    for ln in (raw / MALWARE / "skills.jsonl").open(encoding="utf-8"):
        r = json.loads(ln)
        bad = r["label"] == "malicious"
        cases.append(_case(root, "attack" if bad else "benign", ("m-" if bad else "b-") + r["id"][:12],
                           "SKILL.md", r["content"], int(bad), "skill_malware", r["id"]))
    _write_set(root, cases)
    rows = [json.loads(ln) for ln in attacks.open(encoding="utf-8")]
    pool = CarrierPool(index_repos(carriers / "test"))
    sizes = {"malware": len(cases)}
    for seed in (0, 1, 2, 3):      # 0 = bare; 1-3 repeat the earlier placements
        root = out / f"redteam_aditya{seed}"
        shutil.rmtree(root, ignore_errors=True)
        rng, cases = random.Random(seed), []
        for r in rows:
            if seed == 0:
                file, text = r["file"], r["text"]
            else:
                kind = normalize_kind(r["file"])
                c = pool.pick(kind, rng)
                text = plant(read_text(c.path) or "", wrap(r["text"], kind, "prose", rng),
                             family(kind), rng)[0]
                file = c.rel
            cases.append(_case(root, "attack", r["id"], file, text, 1, r["technique"], r["id"],
                               "snippet"))
        _write_set(root, cases)
        sizes[f"aditya{seed}"] = len(cases)
    return sizes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.data.v17.real")
    parser.add_argument("command", choices=("review", "build", "heldout"))
    parser.add_argument("--raw", default=str(HOME / "hf_datasets"))
    parser.add_argument("--attacks", default=str(Path.home() / "Downloads/heldout63/heldout63.jsonl"))
    parser.add_argument("--exclude", default=None, help="JSON list of rejected ids")
    parser.add_argument("--out", default=None)
    parser.add_argument("--base", default=str(HOME / "data_v17_86m"))
    parser.add_argument("--tokenizer", default="/mnt/d/hf_models/Llama-Prompt-Guard-2-86M")
    args = parser.parse_args(argv)
    raw, attacks = Path(args.raw), Path(args.attacks)
    if args.command == "heldout":
        print(json.dumps(heldout(raw, attacks, HOME / "v17_raw/carriers", Path(args.out or HOME))))
        return 0
    exclude = set(json.loads(Path(args.exclude).read_text())) if args.exclude else set()
    redteam = [HOME / "v17_raw/glm" / d for d in ("zcode", "zcode_strong", "opencode")]
    if args.command == "review":
        from read.data.v17.snippets import assign_split, load_batches
        snippets, _ = load_batches(HOME / "v17_raw/muse")
        assign_split(snippets)
        review(raw, attacks, redteam, [x.text for x in snippets if x.group == "test"], exclude)
        return 0
    print(json.dumps(build(raw, Path(args.base), Path(args.out), Path(args.tokenizer), attacks,
                           redteam, exclude), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
