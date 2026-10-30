"""Real agent-instruction files (AGENTS.md, CLAUDE.md, cursor rules, ...).

Legitimate agent guidance is the hardest harmless voice for BaitWatch: it is
imperative, addressed to AI agents and full of NEVER/ALWAYS. The seed data has
almost none. This fetcher pulls such files from GitHub code search, keeping
only permissively licensed repositories with some community signal, and
records every file's repo, path, blob sha and license in a lock file.

Fetched files are screened before use (see build.py): a public file can carry
a real injection, so the highest-scoring ones are reviewed by hand and any
file that plants instructions against the user is excluded.

    python -m read.data.v17.agentfiles --out ~/.local/share/baitwatch/v17_raw/agentfiles
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import time
from pathlib import Path

QUERIES = (
    "filename:AGENTS.md", "filename:CLAUDE.md", "filename:.cursorrules",
    "filename:copilot-instructions.md", "filename:SKILL.md", "filename:GEMINI.md",
    "filename:.windsurfrules", "filename:.clinerules", "extension:mdc path:.cursor/rules",
)
SIZE_BUCKETS = ("size:<1500", "size:1500..5000", "size:>5000")
PERMISSIVE = frozenset({"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC",
                        "MPL-2.0", "Unlicense", "0BSD", "CC0-1.0"})


def split_for_repo(repo: str, train_repos=(), test_repos=()) -> str:
    """train / val / test_planted for an agent-file repo, stable across runs."""
    from read.data.v17.snippets import stable_unit

    r = repo.lower()
    if r in {x.lower() for x in test_repos}:
        return "test_planted"
    if r in {x.lower() for x in train_repos}:
        return "train"
    u = stable_unit("v17-agent:" + r)
    return "test_planted" if u < 0.2 else ("val" if u < 0.3 else "train")


def _gh(args: list[str]) -> dict | list | None:
    proc = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
    if proc.returncode != 0 and not (args and args[0] == "graphql" and proc.stdout.strip()):
        return None     # GraphQL returns partial data (missing repos) with a non-zero exit
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def search(pages: int = 3, pause_s: float = 7.0) -> list[dict]:
    """(repo, path, sha) hits; code search allows ~10 requests a minute."""
    hits: dict[tuple[str, str], dict] = {}
    for q in QUERIES:
        for size in SIZE_BUCKETS:
            for page in range(1, pages + 1):
                data = _gh(["-X", "GET", "search/code", "-f", f"q={q} {size}",
                            "-f", "per_page=100", "-f", f"page={page}"])
                time.sleep(pause_s)
                items = (data or {}).get("items", []) if isinstance(data, dict) else []
                for it in items:
                    key = (it["repository"]["full_name"], it["path"])
                    hits.setdefault(key, {"repo": key[0], "path": key[1], "sha": it["sha"],
                                          "query": q})
                if len(items) < 100:
                    break
    return list(hits.values())


def repo_infos(repos: list[str], batch: int = 50) -> dict[str, dict]:
    """License / stars / fork for many repos, 50 per GraphQL request."""
    out: dict[str, dict] = {}
    for i in range(0, len(repos), batch):
        chunk = repos[i: i + batch]
        fields = []
        for j, full in enumerate(chunk):
            owner, name = full.split("/", 1)
            fields.append(f'r{j}: repository(owner: {json.dumps(owner)}, name: {json.dumps(name)}) '
                          '{ stargazerCount isFork isArchived licenseInfo { spdxId } }')
        data = _gh(["graphql", "-f", "query={ " + " ".join(fields) + " }"])
        repos_data = (data or {}).get("data") or {} if isinstance(data, dict) else {}
        for j, full in enumerate(chunk):
            d = repos_data.get(f"r{j}") or {}
            out[full] = {"license": (d.get("licenseInfo") or {}).get("spdxId"),
                         "stars": d.get("stargazerCount", 0), "fork": d.get("isFork", False),
                         "archived": d.get("isArchived", False)}
    return out


def _fetch_blob(h: dict, files_dir: Path, max_bytes: int) -> tuple[str, str | None]:
    dest = files_dir / (h["repo"].replace("/", "__") + "__" + h["path"].replace("/", "__"))
    if dest.exists():
        return dest.name, dest.name
    blob = _gh([f'repos/{h["repo"]}/git/blobs/{h["sha"]}'])
    if not isinstance(blob, dict) or blob.get("encoding") != "base64":
        return dest.name, None
    raw = base64.b64decode(blob["content"])
    if len(raw) > max_bytes:
        return dest.name, None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return dest.name, None
    dest.write_text(text, encoding="utf-8")
    return dest.name, dest.name


def fetch(out: Path, min_stars: int = 10, max_bytes: int = 60_000, workers: int = 8) -> dict:
    """Resumable: search hits, repo info and the lock are saved as they arrive."""
    from concurrent.futures import ThreadPoolExecutor

    out.mkdir(parents=True, exist_ok=True)
    (out / "files").mkdir(exist_ok=True)
    hits_path, lock_path = out / "search_hits.json", out / "agentfiles_lock.json"
    if hits_path.exists():
        hits = json.loads(hits_path.read_text())
    else:
        hits = search()
        hits_path.write_text(json.dumps(hits, indent=1))
    lock = json.loads(lock_path.read_text()) if lock_path.exists() else {"files": {}, "repos": {}}
    todo = sorted({h["repo"] for h in hits} - set(lock["repos"]))
    lock["repos"].update(repo_infos(todo))
    lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True))
    wanted = [h for h in hits
              if lock["repos"].get(h["repo"], {}).get("license") in PERMISSIVE
              and lock["repos"][h["repo"]].get("stars", 0) >= min_stars
              and not lock["repos"][h["repo"]].get("fork")
              and f'{h["repo"]}:{h["path"]}' not in lock["files"]]
    with ThreadPoolExecutor(workers) as pool:
        for n, (h, (_name, local)) in enumerate(zip(
                wanted, pool.map(lambda h: _fetch_blob(h, out / "files", max_bytes), wanted))):
            if local:
                info = lock["repos"][h["repo"]]
                lock["files"][f'{h["repo"]}:{h["path"]}'] = {
                    **h, "license": info["license"], "stars": info["stars"], "local": local}
            if n % 50 == 0:
                lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True))
    lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True))
    return {"hits": len(hits), "repos": len(lock["repos"]), "files_kept": len(lock["files"])}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.data.v17.agentfiles")
    parser.add_argument("--out", default=str(Path.home() / ".local/share/baitwatch/v17_raw/agentfiles"))
    parser.add_argument("--min-stars", type=int, default=10)
    args = parser.parse_args(argv)
    print(json.dumps(fetch(Path(args.out), args.min_stars), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
