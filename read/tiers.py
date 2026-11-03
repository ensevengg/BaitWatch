"""Which files a coding agent reaches first. No imports from ``read``: the hook
loads this without pulling in torch.
"""

from __future__ import annotations

import os

# Tier 0: files coding agents load as instructions or configuration.
AGENT_FILE_NAMES = frozenset({
    "agents.md", "agent.md", "claude.md", "claude.local.md", "gemini.md",
    "codex.md", "conventions.md", ".cursorrules", ".clinerules",
    ".windsurfrules", ".roorules", ".goosehints", "copilot-instructions.md",
    ".mcp.json", "mcp.json", "skill.md",
})
AGENT_DIR_PREFIXES = (
    ".claude/", ".cursor/", ".windsurf/", ".clinerules/", ".roo/",
    ".continue/", ".github/instructions/", ".github/prompts/",
    ".github/chatmodes/", ".vscode/",
)
# Tier 1: what an agent reads next — READMEs, contributing guides, manifests
# and install/CI scripts it is likely to run.
TIER1_NAMES = frozenset({
    "readme", "readme.md", "readme.rst", "readme.txt", "contributing.md",
    "install.md", "setup.md", "package.json", "pyproject.toml", "setup.py",
    "setup.cfg", "makefile", "dockerfile", "docker-compose.yml",
    "requirements.txt", "cargo.toml", "go.mod", "install.sh", "setup.sh",
})
TIER1_DIR_PREFIXES = (".github/workflows/", ".devcontainer/")
# Tier 2: text an agent can be pointed at. Everything else is tier 3. Tiers 0
# and 1 must be covered; the hook preset treats tiers 2 and 3 as best effort.
TEXT_SUFFIXES = (".md", ".mdx", ".rst", ".txt", ".adoc", ".org", ".ipynb",
                 ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd")
# Long release histories, at the root but rarely read as instructions.
_HISTORY_PREFIXES = ("changelog", "changes", "history", "news", "license", "copying")

def priority_tier(rel_path: str) -> int:
    rel = rel_path.replace(os.sep, "/").lower()
    name = rel.rsplit("/", 1)[-1]
    depth = rel.count("/")
    if name in AGENT_FILE_NAMES or rel.startswith(AGENT_DIR_PREFIXES) \
            or any(f"/{p}" in f"/{rel}" for p in AGENT_DIR_PREFIXES):
        return 0
    text_like = name.endswith(TEXT_SUFFIXES)
    if rel.startswith(TIER1_DIR_PREFIXES):
        return 1
    if name in TIER1_NAMES or name.startswith("readme"):
        # A monorepo can hold thousands of these; only the shallow ones come first.
        return 1 if depth <= 1 else 2
    if depth == 0 and text_like and not name.startswith(_HISTORY_PREFIXES):
        return 1
    if text_like or rel.startswith(".github/"):
        return 2
    return 3


_LOCKFILES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "poetry.lock", "uv.lock",
    "go.sum", "composer.lock", "gemfile.lock", "pipfile.lock", "npm-shrinkwrap.json",
})
_GENERATED_SUFFIXES = (".lock", ".snap", ".min.js", ".min.css", ".map", ".svg", ".csv", ".tsv")
_GENERATED_DIRS = ("__snapshots__/", "snapshots/", "vendor/", "third_party/", "testdata/",
                   "fixtures/", "__fixtures__/", "generated/", "locale/", "locales/", "i18n/")


def is_generated(rel_path: str) -> bool:
    """Lockfiles, snapshots, bundles, data and vendored files.

    A repository scan spends nothing on these; they make up nearly half of some large
    repositories and score as noise. The hook scans one if an agent opens it.
    """
    rel = rel_path.replace(os.sep, "/").lower()
    name = rel.rsplit("/", 1)[-1]
    return (name in _LOCKFILES or name.endswith(_GENERATED_SUFFIXES)
            or any(f"/{d}" in f"/{rel}" for d in _GENERATED_DIRS))
