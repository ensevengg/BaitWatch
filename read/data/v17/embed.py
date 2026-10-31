"""Plant a snippet into a carrier file and record its exact character span.

Both labels go through the same wrappers with the same weights, so markup
(HTML comments, blockquotes, <details>, JSON keys, comment prefixes) carries
no label signal: only what the planted text asks for does.
"""

from __future__ import annotations

import json
import random
import re

MD_KINDS = frozenset({
    "README.md", "CONTRIBUTING.md", "AGENTS.md", "CLAUDE.md", ".cursorrules",
    ".github/copilot-instructions.md", "SKILL.md", "docs", "CHANGELOG.md",
    "SECURITY.md", "issue_template",
})
HASH_KINDS = frozenset({
    "pyproject.toml", "Makefile", "shell_script", "workflow_yaml", "python_comment",
    "dockerfile", "env_example", "compose_yaml",
})
SLASH_KINDS = frozenset({"js_comment", "go_comment"})
JSON_KINDS = frozenset({"package.json", "mcp_json", "vscode_tasks", "claude_settings"})
ALL_KINDS = MD_KINDS | HASH_KINDS | SLASH_KINDS | JSON_KINDS


def family(kind: str) -> str:
    if kind in MD_KINDS:
        return "md"
    if kind in HASH_KINDS:
        return "hash"
    if kind in SLASH_KINDS:
        return "slash"
    if kind in JSON_KINDS:
        return "json"
    k = kind.lower()
    if any(t in k for t in ("json",)):
        return "json"
    if any(t in k for t in ("js", "ts", "go", "rust", "java", "c#", "swift", "kotlin")):
        return "slash"
    if any(t in k for t in ("yaml", "yml", "toml", "python", "py", "sh", "make", "docker", "env")):
        return "hash"
    return "md"


def normalize_kind(kind: str) -> str:
    """Map free-form kinds the generator invented onto the known set."""
    if kind in ALL_KINDS:
        return kind
    k = kind.lower().strip()
    table = (
        ("copilot", ".github/copilot-instructions.md"), ("cursor", ".cursorrules"),
        ("agents", "AGENTS.md"), ("claude_settings", "claude_settings"),
        ("settings.json", "claude_settings"), ("claude", "CLAUDE.md"),
        ("skill", "SKILL.md"), ("readme", "README.md"), ("contributing", "CONTRIBUTING.md"),
        ("changelog", "CHANGELOG.md"), ("security", "SECURITY.md"), ("issue", "issue_template"),
        ("package", "package.json"), ("pyproject", "pyproject.toml"), ("toml", "pyproject.toml"),
        ("makefile", "Makefile"), ("workflow", "workflow_yaml"), ("compose", "compose_yaml"),
        ("docker", "dockerfile"), ("env", "env_example"), ("mcp", "mcp_json"),
        ("tasks", "vscode_tasks"), ("vscode", "vscode_tasks"), ("python", "python_comment"),
        ("go", "go_comment"), ("js", "js_comment"), ("ts", "js_comment"),
        ("shell", "shell_script"), ("sh", "shell_script"), ("bash", "shell_script"),
        ("yaml", "workflow_yaml"), ("doc", "docs"), ("md", "docs"),
    )
    for needle, mapped in table:
        if needle in k:
            return mapped
    return "docs"


_SUMMARIES = ("Advanced", "Internal notes", "Troubleshooting", "More details",
              "Maintainer notes", "Setup details", "Click to expand", "Notes",
              "Environment setup", "For automation")
_HEADINGS = ("Setup", "Notes", "Development", "Troubleshooting", "For contributors",
             "Agent instructions", "AI assistants", "Maintenance", "Configuration",
             "Before you start", "Local development", "Release process", "Tooling",
             "Working in this repo", "Conventions")
_NOTE_PREFIXES = ("**Note:** ", "**IMPORTANT:** ", "Note: ", "_Note for contributors:_ ",
                  "**Heads up:** ", "> **Warning**\n> ", "> [!NOTE]\n> ",
                  "> [!IMPORTANT]\n> ", "**Tip:** ")
_JSON_KEYS = ("description", "_comment", "//", "note", "notes", "detail", "summary",
              "help", "instructions", "x-notes")
_CMD_RE = re.compile(r"^\s*(curl|wget|npm|npx|pnpm|yarn|pip|pipx|uv|uvx|git|docker|make|bash|sh|"
                     r"brew|cargo|go |iwr|irm|powershell|python|node|chmod|echo|export|ssh|crontab)",
                     re.I)


def _md_wrap(text: str, rng: random.Random) -> str:
    lines = text.splitlines() or [text]
    if _CMD_RE.match(text) and len(lines) <= 6 and rng.random() < 0.6:
        if rng.random() < 0.35:   # indented code block (CommonMark), as in real READMEs
            return "\n".join("    " + ln for ln in lines)
        return "```" + rng.choice(("sh", "bash", "", "console", "shell")) + "\n" + text + "\n```"
    if rng.random() < 0.06:       # any text can sit in an indented block
        return "\n".join("    " + ln for ln in lines)
    roll = rng.random()
    if roll < 0.24:
        return text                                                # plain paragraph
    if roll < 0.40:
        sep = rng.choice((" ", "\n"))
        return f"<!--{sep}{text}{sep}-->"
    if roll < 0.50:
        return "\n".join("> " + ln if ln else ">" for ln in lines)
    if roll < 0.62:
        prefix = rng.choice(_NOTE_PREFIXES)
        if prefix.startswith(">"):
            return prefix + "\n> ".join(lines)
        return prefix + text
    if roll < 0.74:
        bullet = rng.choice(("- ", "* ", f"{rng.randint(1, 9)}. "))
        return bullet + "\n  ".join(lines)
    if roll < 0.84:
        return (f"<details>\n<summary>{rng.choice(_SUMMARIES)}</summary>\n\n"
                f"{text}\n\n</details>")
    if roll < 0.95:
        return f"{rng.choice(('##', '###', '####'))} {rng.choice(_HEADINGS)}\n\n{text}"
    return f"[^{rng.randint(1, 9)}]: {text}"


def _hash_wrap(text: str, rng: random.Random, kind: str) -> str:
    lines = text.splitlines() or [text]
    if kind == "python_comment" and rng.random() < 0.3:
        return '"""\n' + text + '\n"""'
    if kind == "Makefile" and _CMD_RE.match(text) and rng.random() < 0.4:
        target = rng.choice(("setup", "bootstrap", "init", "dev", "deps", "doctor"))
        return f"{target}:\n" + "\n".join("\t" + ln for ln in lines)
    return "\n".join("# " + ln if ln else "#" for ln in lines)


def _slash_wrap(text: str, rng: random.Random) -> str:
    lines = text.splitlines() or [text]
    roll = rng.random()
    if roll < 0.55:
        return "\n".join("// " + ln if ln else "//" for ln in lines)
    if roll < 0.8:
        return "/**\n" + "\n".join(" * " + ln for ln in lines) + "\n */"
    return "/* " + "\n   ".join(lines) + " */"


def _json_wrap(text: str, rng: random.Random) -> str:
    return f'"{rng.choice(_JSON_KEYS)}": {json.dumps(text, ensure_ascii=False)},'


def wrap(text: str, kind: str, form: str, rng: random.Random) -> str:
    """Markup around a prose snippet; structured snippets are planted as-is."""
    if form == "structured":
        return text
    fam = family(kind)
    if fam == "md":
        return _md_wrap(text, rng)
    if fam == "hash":
        return _hash_wrap(text, rng, kind)
    if fam == "slash":
        return _slash_wrap(text, rng)
    return _json_wrap(text, rng)


def _fence_mask(lines: list[str]) -> list[bool]:
    """True for lines inside a ``` fence (markdown carriers)."""
    inside, out = False, []
    for ln in lines:
        if ln.lstrip().startswith(("```", "~~~")):
            out.append(True)
            inside = not inside
            continue
        out.append(inside)
    return out


def insertion_points(carrier: str, fam: str) -> list[int]:
    """Line indexes a block may be inserted *before* (0..len(lines))."""
    lines = carrier.split("\n")
    n = len(lines)
    if fam == "md":
        fenced = _fence_mask(lines)
        pts = [i for i in range(1, n) if not fenced[i - 1] and not fenced[min(i, n - 1)]
               and lines[i - 1].strip() == ""]
    elif fam == "json":
        pts = [i for i in range(1, n) if lines[i - 1].rstrip().endswith((",", "{"))]
    else:
        pts = [i for i in range(1, n)
               if lines[i - 1].strip() == "" or not lines[i].startswith((" ", "\t"))]
    if fam == "json":
        return pts or [n]     # stay inside the object when the carrier has one
    return (pts or []) + [n]  # end of file is always allowed: EOF payloads are common


def plant(carrier: str, block: str, fam: str, rng: random.Random,
          position: str | None = None) -> tuple[str, int, int]:
    """Insert ``block`` on its own lines; returns (text, start_char, end_char).

    ``position`` (head|middle|tail|None) biases where in the file it lands;
    tails matter because payloads appended at EOF are a common evasion.
    """
    lines = carrier.split("\n")
    pts = insertion_points(carrier, fam)
    position = position or rng.choice(("head", "middle", "middle", "tail"))
    third = max(1, len(pts) // 3)
    pool = {"head": pts[:third], "middle": pts[third: 2 * third] or pts,
            "tail": pts[2 * third:] or pts}[position]
    at = rng.choice(pool)
    indent = ""
    if fam in ("json", "slash", "hash") and at < len(lines):
        m = re.match(r"[ \t]*", lines[at])
        indent = m.group(0) if m else ""
    block_lines = [indent + ln if ln else ln for ln in block.split("\n")]
    pad_before = [""] if fam == "md" and at > 0 and lines[at - 1].strip() else []
    pad_after = [""] if fam == "md" else []
    new_lines = lines[:at] + pad_before + block_lines + pad_after + lines[at:]
    head = lines[:at] + pad_before
    start = len("\n".join(head)) + 1 if head else 0
    text = "\n".join(new_lines)
    body = "\n".join(block_lines)
    end = start + len(body)
    assert text[start:end] == body, "span bookkeeping drifted"
    return text, start, end
