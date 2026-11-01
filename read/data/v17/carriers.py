"""Index carrier files by kind and read them the way the scanner does."""

from __future__ import annotations

import random
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from read.data.v17.embed import family
from read.walk import walk

MAX_CARRIER_BYTES = 200_000
MAX_AVG_LINE = 250          # minified / generated files make poor carriers


@dataclass(frozen=True)
class Carrier:
    repo: str
    rel: str
    path: Path
    kind: str


DOC_SUFFIXES = frozenset({"", ".md", ".mdx", ".markdown", ".rst", ".txt", ".adoc"})
_DOC_KINDS = {"readme": "README.md", "contributing": "CONTRIBUTING.md",
              "changelog": "CHANGELOG.md", "history": "CHANGELOG.md", "news": "CHANGELOG.md",
              "releases": "CHANGELOG.md", "security": "SECURITY.md"}


def classify(rel: str) -> str:
    p = PurePosixPath(rel)
    name, low = p.name, p.name.lower()
    parts = [x.lower() for x in p.parts]
    suffix = p.suffix.lower()
    doc_like = suffix in DOC_SUFFIXES
    if doc_like and low.startswith(("readme", "contributing", "changelog", "history", "news",
                                    "releases", "security")):
        return _DOC_KINDS[next(k for k in _DOC_KINDS if low.startswith(k))]
    if low == "agents.md" or low in ("gemini.md", ".windsurfrules", ".clinerules"):
        return "AGENTS.md"
    if low == "claude.md":
        return "CLAUDE.md"
    if low == ".cursorrules" or (suffix == ".mdc" and ".cursor" in parts):
        return ".cursorrules"
    if low == "copilot-instructions.md" or low.endswith(".instructions.md"):
        return ".github/copilot-instructions.md"
    if low == "skill.md":
        return "SKILL.md"
    if doc_like and ("issue_template" in parts or low.startswith("pull_request_template")):
        return "issue_template"
    if low == "package.json":
        return "package.json"
    if ".claude" in parts and suffix == ".json":
        return "claude_settings"
    if ".vscode" in parts and suffix in (".json", ".jsonc"):
        return "vscode_tasks"
    if "mcp" in low and suffix == ".json":
        return "mcp_json"
    if suffix in (".json", ".jsonc"):
        return "json"
    if suffix in (".toml", ".cfg", ".ini"):
        return "pyproject.toml"
    if low in ("makefile", "justfile", "gnumakefile") or suffix == ".mk":
        return "Makefile"
    if suffix in (".sh", ".bash", ".zsh", ".fish", ".ps1") or low in ("install", "configure"):
        return "shell_script"
    if ".github" in parts and "workflows" in parts:
        return "workflow_yaml"
    if low.startswith(("docker-compose", "compose")) and suffix in (".yml", ".yaml"):
        return "compose_yaml"
    if suffix in (".yml", ".yaml"):
        return "yaml"
    if low.startswith("dockerfile") or suffix == ".dockerfile":
        return "dockerfile"
    if low.startswith(".env"):
        return "env_example"
    if suffix == ".py":
        return "python_comment"
    if suffix == ".go":
        return "go_comment"
    if suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rs", ".java", ".c",
                  ".h", ".cc", ".cpp", ".cs", ".swift", ".kt", ".scala", ".php", ".dart"):
        return "js_comment"
    if suffix in (".md", ".mdx", ".rst", ".txt", ".adoc"):
        return "docs"
    return "other"


# Where to look when a kind has too few real carriers.
FALLBACK = {
    "AGENTS.md": ("CLAUDE.md", ".cursorrules", ".github/copilot-instructions.md", "docs"),
    "CLAUDE.md": ("AGENTS.md", ".cursorrules", "docs"),
    ".cursorrules": ("AGENTS.md", "CLAUDE.md", "docs"),
    ".github/copilot-instructions.md": ("AGENTS.md", "CLAUDE.md", "docs"),
    "SKILL.md": ("AGENTS.md", "docs"),
    "issue_template": ("CONTRIBUTING.md", "docs"),
    "SECURITY.md": ("docs",), "CHANGELOG.md": ("docs",), "CONTRIBUTING.md": ("docs",),
    "README.md": ("docs",),
    "mcp_json": ("json", "package.json"), "vscode_tasks": ("json", "package.json"),
    "claude_settings": ("json", "package.json"), "package.json": ("json",),
    "compose_yaml": ("yaml", "workflow_yaml"), "workflow_yaml": ("yaml", "compose_yaml"),
    "env_example": ("pyproject.toml", "yaml"), "dockerfile": ("shell_script",),
    "Makefile": ("shell_script",), "go_comment": ("js_comment",),
}


def read_text(path: Path) -> str | None:
    try:
        raw = path.read_bytes()[:MAX_CARRIER_BYTES]
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    if not text.strip() or "\x00" in text:
        return None
    lines = text.count("\n") + 1
    if len(text) / lines > MAX_AVG_LINE:
        return None
    return text


class CarrierPool:
    def __init__(self, carriers: list[Carrier]):
        self.all = carriers
        self.by_kind: dict[str, list[Carrier]] = defaultdict(list)
        for c in carriers:
            self.by_kind[c.kind].append(c)

    def pick(self, kind: str, rng: random.Random, min_pool: int = 8) -> Carrier:
        for k in (kind, *FALLBACK.get(kind, ())):
            if len(self.by_kind.get(k, ())) >= min_pool:
                return rng.choice(self.by_kind[k])
        fam = family(kind)
        same = [c for k, cs in self.by_kind.items() if family(k) == fam
                and k not in ("other",) for c in cs]
        return rng.choice(same or self.all)

    def counts(self) -> dict[str, int]:
        return {k: len(v) for k, v in sorted(self.by_kind.items())}


def index_repos(root: Path) -> list[Carrier]:
    out: list[Carrier] = []
    for repo_dir in sorted(p for p in Path(root).iterdir() if p.is_dir()):
        repo = repo_dir.name.replace("__", "/", 1)
        result = walk(repo_dir)
        for f in result.files:
            if f.path.stat().st_size > MAX_CARRIER_BYTES:
                continue
            out.append(Carrier(repo, f.rel_path, f.path, classify(f.rel_path)))
    return out


def index_agentfiles(files_dir: Path, lock: dict) -> list[Carrier]:
    out: list[Carrier] = []
    for meta in lock.get("files", {}).values():
        path = Path(files_dir) / meta["local"]
        if path.exists():
            out.append(Carrier(meta["repo"], meta["path"], path, classify(meta["path"])))
    return out
