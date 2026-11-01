"""Carrier repositories for data v1.7.

Real files from permissively licensed repositories are the carriers that
generated snippets get planted into, and their clean files are harmless
training rows in their own right. Three pools, disjoint by repository:

- TRAIN_REPOS: carriers and harmless rows for train/val.
- TEST_REPOS: carriers for the held-out test set only.
- The FPR corpus (read.data.benign_corpus.CORPUS_STARTER) is never used here.

Nothing is vendored: clones live outside the repo and every resolved commit
is recorded in ``carriers_lock.json`` next to them.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from read.data.benign_corpus import CORPUS_STARTER
from read.data.v17.agentfiles import PERMISSIVE

TRAIN_REPOS: tuple[str, ...] = (
    "pallets/click", "psf/black", "encode/httpx", "fastapi/typer",
    "pydantic/pydantic", "python-poetry/poetry", "scrapy/scrapy",
    "vitejs/vite", "sveltejs/svelte", "axios/axios", "prettier/prettier",
    "fastify/fastify", "honojs/hono", "nestjs/nest", "tailwindlabs/tailwindcss",
    "spf13/cobra", "gin-gonic/gin", "junegunn/fzf", "charmbracelet/bubbletea",
    "BurntSushi/ripgrep", "sharkdp/bat", "tokio-rs/tokio", "clap-rs/clap",
    "astral-sh/uv", "denoland/deno", "oven-sh/bun", "biomejs/biome",
    "microsoft/vscode-extension-samples", "docker/compose",
    "terraform-aws-modules/terraform-aws-vpc", "openai/codex",
    "modelcontextprotocol/servers", "anthropics/anthropic-sdk-python",
    "laravel/framework", "ohmyzsh/ohmyzsh", "nvm-sh/nvm", "Homebrew/install",
    "rust-lang/rustup", "pre-commit/pre-commit", "typicode/husky",
    "actions/checkout", "actions/setup-node",
)

TEST_REPOS: tuple[str, ...] = (
    "pallets/jinja", "fastapi/fastapi", "koajs/koa", "vuejs/core",
    "urfave/cli", "sharkdp/fd", "serde-rs/serde", "astral-sh/ruff",
    "withastro/astro", "pnpm/pnpm", "cline/cline", "go-chi/chi",
)


# GitHub reports NOASSERTION for these; their LICENSE files were read by hand.
LICENSE_OVERRIDES = {
    "oven-sh/bun": "MIT",                       # LICENSE.md: "Bun itself is MIT-licensed"
    "modelcontextprotocol/servers": "Apache-2.0",  # MIT -> Apache-2.0 transition; docs CC-BY-4.0
    "withastro/astro": "MIT",
}


def _license(full: str) -> str | None:
    if full in LICENSE_OVERRIDES:
        return LICENSE_OVERRIDES[full]
    proc = subprocess.run(["gh", "api", f"repos/{full}", "--jq", ".license.spdx_id"],
                          capture_output=True, text=True)
    return proc.stdout.strip() or None if proc.returncode == 0 else None


def _corpus_names() -> set[str]:
    return {"/".join(r.url.rstrip("/").split("/")[-2:]).lower() for r in CORPUS_STARTER}


def check_disjoint() -> None:
    train, test = {r.lower() for r in TRAIN_REPOS}, {r.lower() for r in TEST_REPOS}
    if train & test:
        raise ValueError(f"repos in both pools: {sorted(train & test)}")
    corpus = _corpus_names()
    for full in train | test:
        if full in corpus:
            raise ValueError(f"{full} is in the FPR corpus")


def clone_pool(repos: tuple[str, ...], target: Path) -> dict:
    """Shallow, blob-limited clones; returns {repo: {commit, license}}."""
    check_disjoint()
    target.mkdir(parents=True, exist_ok=True)
    lock_path = target / "carriers_lock.json"
    lock = json.loads(lock_path.read_text()) if lock_path.exists() else {}
    for full in repos:
        dest = target / full.replace("/", "__")
        if not dest.exists():
            subprocess.run(["git", "clone", "--quiet", "--depth", "1",
                            "--filter=blob:limit=300k", "--single-branch",
                            f"https://github.com/{full}", str(dest)], check=True)
        head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True).stdout.strip()
        entry = lock.get(full, {})
        entry["commit"] = head
        if "license" not in entry:
            entry["license"] = _license(full)
        if entry["license"] not in PERMISSIVE:
            raise ValueError(f"{full}: license {entry['license']!r} is not permissive")
        lock[full] = entry
    lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True))
    return lock


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.data.v17.sources")
    parser.add_argument("--out", default=str(Path.home() / ".local/share/baitwatch/v17_raw/carriers"))
    args = parser.parse_args(argv)
    out = Path(args.out)
    clone_pool(TRAIN_REPOS, out / "train")
    clone_pool(TEST_REPOS, out / "test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
