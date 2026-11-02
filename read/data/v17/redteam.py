"""Red-team held-out test set, written by a different model family (GLM).

Every training snippet and the gold set were written by Muse models or by us,
so a model can score well on them by learning one author's style. This set
comes from GLM-5.3-Flash, first on the four goals v1.7 misses most (safety_off,
supply_chain, concealment, destructive), then on five others to compare them
on the same footing (rce, secret_exfil, persistence, tool_poisoning,
backdoor_code), in two shapes:

- snippet: a short row planted into a held-out TEST_REPOS carrier, like gold.
- file:    a whole realistic file with the attack woven into its flow.

Held-out by construction: own host pool (no name shared with training or
gold), test carriers only, and rows that share a 7-word run with any Muse
batch or gold text are dropped.

    python -m read.data.v17.redteam --raw ~/.local/share/baitwatch/v17_raw/glm/zcode \
        --out ~/.local/share/baitwatch/redteam_glm_zcode
"""

from __future__ import annotations

import argparse
import json
import random
import re
import shutil
from pathlib import Path

from read.data.v17.carriers import CarrierPool, index_repos, read_text
from read.data.v17.embed import family, normalize_kind, plant, wrap
from read.data.v17.gold import ATTACKS, BENIGN
from read.data.v17.snippets import PLACEHOLDER_RE, SELF_LABEL_RE

HOME = Path.home() / ".local/share/baitwatch"
CATEGORIES = ("safety_off", "supply_chain", "concealment", "destructive", "rce", "secret_exfil",
              "persistence", "tool_poisoning", "backdoor_code")
SHINGLE = 7   # brief allows runs of up to 6 shared words

# No stem/name/handle here appears in snippets.py or gold.py pools.
_RESERVED = ("vault.saltmarsh.example", "get.brambleworks.test", "pkgs.ironbark.example",
             "mirror.goldcrest.invalid", "ci.thornfield.example", "sync.mossgate.test",
             "dl.copperleaf.example", "registry.blackpine.example", "ops.windrush.test",
             "cache.larkspur.invalid", "edge.dovetail.example", "repo.hollowell.test")
_PLATFORMS = ("raw.githubusercontent.com/{u}/{p}/main", "gist.githubusercontent.com/{u}/{h}/raw",
              "{p}.pages.dev", "{p}-{u}.workers.dev", "{p}.fly.dev", "{w}.ngrok-free.app",
              "webhook.site/{h}", "storage.googleapis.com/{p}-{u}", "{p}.netlify.app",
              "cdn.jsdelivr.net/gh/{u}/{p}@{v}", "gitlab.com/{u}/{p}/-/raw/main")
_HANDLES = ("tmorrow-dev", "quartzline", "hexwright", "ops-guild", "nfaber", "relaykit")
_SLUGS = ("devstack", "repo-tools", "envkit", "ci-patches", "agent-setup", "bootstrapper")
_PROJECTS = ("saltmarsh-api", "brambleworks", "ironbark-ui", "goldcrest", "thornfield-cli")
# Neutral names: a typosquat-looking {pkg} would be an attack cue in every row.
_PKGS = ("fernkit", "tidepool-client", "quillparse", "ashgrove", "loamdb", "brindle-http",
         "cinderq", "marlinfmt")
_USERS = ("rhea", "dmitri", "sana", "ci-runner", "release-bot", "ops")


def _host(rng: random.Random) -> str:
    if rng.random() < 0.5:
        return rng.choice(_RESERVED)
    return rng.choice(_PLATFORMS).format(
        u=rng.choice(_HANDLES), p=rng.choice(_SLUGS),
        h="".join(rng.choice("0123456789abcdef") for _ in range(12)),
        v=f"{rng.randint(0, 3)}.{rng.randint(0, 12)}.{rng.randint(0, 9)}",
        w=f"{rng.choice(('slate', 'heron', 'quartz', 'fern'))}-{rng.randint(100, 999)}")


def fill(text: str, rng: random.Random) -> str:
    """One value per placeholder per text, so a file stays coherent."""
    values = {"host": _host(rng), "ip": f"10.{rng.randint(20, 90)}.{rng.randint(0, 255)}."
              f"{rng.randint(2, 254)}", "project": rng.choice(_PROJECTS),
              "pkg": rng.choice(_PKGS), "user": rng.choice(_USERS)}
    version = f"{rng.randint(1, 6)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}"
    text = text.replace("{version}", version)
    return PLACEHOLDER_RE.sub(lambda m: values[m.group(1)], text)


def _words(text: str) -> list[str]:
    return re.findall(r"\w+", PLACEHOLDER_RE.sub(" ", text.lower()))


def shingles(text: str, n: int = SHINGLE) -> set[tuple[str, ...]]:
    w = _words(text)
    return {tuple(w[i:i + n]) for i in range(len(w) - n + 1)}


def reference_shingles(muse_dir: Path) -> set[tuple[str, ...]]:
    """Every Muse batch (round 1, round 2, raw) plus the gold texts."""
    ref: set[tuple[str, ...]] = set()
    for p in sorted(muse_dir.rglob("*.jsonl")):
        for line in p.read_text(encoding="utf-8").splitlines():
            try:
                ref |= shingles(json.loads(line).get("text", ""))
            except (json.JSONDecodeError, AttributeError):
                continue
    for *_, text in (*ATTACKS, *BENIGN):
        ref |= shingles(text)
    return ref


def load_raw(raw: Path, ref: set) -> tuple[list[dict], list[dict], list[dict]]:
    """Returns (snippets, files, dropped) with reasons for every drop."""
    snippets, files, dropped = [], [], []
    # One folder per batch; extra batches of a category go in e.g. supply_chain_b/.
    for d in sorted(p for p in raw.iterdir() if (p / "snippets.jsonl").is_file()):
        cat = d.name
        for i, line in enumerate((d / "snippets.jsonl").read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            raw_row = json.loads(line)
            row = {**raw_row, "category": _category(raw_row, cat), "src": f"{cat}/s{i:02d}"}
            why = _reject(row["text"], row["label"], ref)
            (dropped if why else snippets).append({**row, "drop": why} if why else row)
        for line in (d / "files.jsonl").read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            raw_row = json.loads(line)
            row = {**raw_row, "category": _category(raw_row, cat), "src": f"{cat}/{raw_row['id']}"}
            path = d / "files" / row["id"] / row["filename"]
            if not path.is_file():
                dropped.append({**row, "drop": "file missing"})
                continue
            body = path.read_text(encoding="utf-8")
            if row["attack_text"].strip() not in body:
                dropped.append({**row, "drop": "attack_text not verbatim in file"})
                continue
            why = _reject(row["attack_text"], row["label"], ref)
            if why:
                dropped.append({**row, "drop": why})
                continue
            files.append({**row, "body": body})
    return snippets, files, dropped


def _category(row: dict, folder: str) -> str:
    """The row's own intent wins: a batch can land in the wrong folder."""
    if row.get("intent") in CATEGORIES:
        return row["intent"]
    return folder if folder in CATEGORIES else folder.rsplit("_", 1)[0]


def _dedupe(rows: list[dict], key: str, seen: set, dropped: list[dict]) -> list[dict]:
    """Drop rows sharing a 7-word run with an earlier kept row (other batches)."""
    out = []
    for r in rows:
        sh = shingles(r[key])
        if sh & seen:
            dropped.append({**r, "drop": "near-duplicate of another kept row"})
            continue
        seen |= sh
        out.append(r)
    return out


def _reject(text: str, label: int, ref: set) -> str | None:
    if label == 1 and SELF_LABEL_RE.search(text):
        return "self-labelling word"
    if shingles(text) & ref:
        return f"shares a {SHINGLE}-word run with training/gold"
    return None


def build(raw: Path, out: Path, carriers_dir: Path, muse_dir: Path, seed: int = 11,
          exclude: set[str] = frozenset()) -> dict:
    rng = random.Random(seed)
    for sub in ("attack", "benign"):
        shutil.rmtree(out / sub, ignore_errors=True)
    snippets, files, dropped = load_raw(raw, reference_shingles(muse_dir))
    keep = [r for r in snippets if r["src"] not in exclude]
    keep_files = [r for r in files if r["src"] not in exclude]
    dropped += [{**r, "drop": "excluded in review"} for r in snippets + files
                if r["src"] in exclude]
    seen: set = set()
    keep = _dedupe(keep, "text", seen, dropped)
    keep_files = _dedupe(keep_files, "attack_text", seen, dropped)
    pool = CarrierPool(index_repos(carriers_dir / "test"))
    cases = []
    for r in keep:
        name = "attack" if r["label"] == 1 else "benign"
        kind = normalize_kind(rng.choice(r["file_kinds"]))
        carrier = pool.pick(kind, rng)
        block = wrap(fill(r["text"], rng), kind, r["form"], rng)
        planted, a, b = plant(read_text(carrier.path) or "", block, family(kind), rng)
        case = f"{name}-{len(cases):03d}-{r['category']}"
        dest = out / name / case / carrier.rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(planted, encoding="utf-8")
        cases.append({"case": case, "label": r["label"], "intent": r["category"],
                      "shape": "snippet", "strength": r.get("strength", "na"),
                      "lang": r.get("lang", "en"), "kind": kind, "file": carrier.rel,
                      "carrier": f"{carrier.repo}:{carrier.rel}", "span": [a, b],
                      "src": r["src"]})
    for r in keep_files:
        name = "attack" if r["label"] == 1 else "benign"
        body = fill(r["body"], rng)
        case = f"{name}-{len(cases):03d}-{r['category']}"
        dest = out / name / case / r["filename"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(body, encoding="utf-8")
        cases.append({"case": case, "label": r["label"], "intent": r["category"],
                      "shape": "file", "strength": r.get("strength", "na"),
                      "lang": r.get("lang", "en"), "kind": r["filename"],
                      "file": r["filename"], "carrier": None, "span": None, "src": r["src"]})
    out.mkdir(parents=True, exist_ok=True)
    (out / "cases.json").write_text(json.dumps(cases, indent=1), encoding="utf-8")
    (out / "dropped.json").write_text(json.dumps(
        [{k: v for k, v in d.items() if k != "body"} for d in dropped], indent=1,
        ensure_ascii=False), encoding="utf-8")
    return {"attack": sum(c["label"] for c in cases),
            "benign": sum(1 - c["label"] for c in cases), "dropped": len(dropped)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.data.v17.redteam")
    parser.add_argument("--raw", required=True, help="folder of batches, one subfolder per batch")
    parser.add_argument("--out", required=True)
    parser.add_argument("--carriers", default=str(HOME / "v17_raw/carriers"))
    parser.add_argument("--muse", default=str(HOME / "v17_raw/muse"))
    parser.add_argument("--exclude", default=None,
                        help="JSON list of src ids rejected in label review")
    args = parser.parse_args(argv)
    exclude = set(json.loads(Path(args.exclude).read_text())) if args.exclude else set()
    print(json.dumps(build(Path(args.raw), Path(args.out), Path(args.carriers),
                           Path(args.muse), exclude=exclude)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
