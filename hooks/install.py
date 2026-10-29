"""Install/uninstall the BaitWatch hook in Claude Code settings.

Claude Code stores hooks in ``~/.claude/settings.json`` (user scope) or
``.claude/settings.json`` (project scope).  Installation is a merge, never a
replace: unrelated hooks, permissions and env keys survive, and running the
installer twice produces the same file.

Muse Code uses a different, still-unconfirmed hook contract. The installer
refuses to write a guess; ``docs/HOOKS.md`` records the open question.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "MIN_CLAUDE_VERSION",
    "InstallReport",
    "detect_claude_version",
    "hook_command",
    "install",
    "settings_path",
    "uninstall",
]

TOOL_MATCHER = "Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch|Read"

# ``onFailure: "block"`` needs a host that honours it.  2.1.295 is the first
# Claude Code release with the documented fail-closed hook contract.
MIN_CLAUDE_VERSION = (2, 1, 295)


@dataclass
class InstallReport:
    path: Path
    changed: bool
    action: str
    removed: int = 0
    added: int = 0


def hook_command(gate: str, python: str | None = None) -> str:
    interpreter = python or sys.executable
    # ``-I`` isolates the hook from the scanned checkout: without it, Python
    # puts the current directory first on sys.path, so a hostile repo could
    # ship ``hooks/__init__.py`` (or ``json.py``) and replace the guard.
    return f'"{interpreter}" -I -m hooks gate-{gate}'


def parse_claude_version(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in str(value).strip().split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        if digits:
            parts.append(int(digits))
    return tuple(parts)


def detect_claude_version() -> str | None:
    """Best-effort host version: env override, then ``claude --version``.

    Returns ``None`` when the CLI is not installed or does not answer.  The
    installer refuses that case: an unknown host may ignore
    ``onFailure: block``, so the user has to state a supported version.
    """
    override = os.environ.get("BAITWATCH_CLAUDE_VERSION", "").strip()
    if override:
        return override
    executable = shutil.which("claude")
    if not executable:
        return None
    try:
        completed = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"\d+(?:\.\d+)+", completed.stdout or "")
    return match.group(0) if match else None


def settings_path(scope: str = "user", *, root: Path | None = None) -> Path:
    if scope == "project":
        return (root or Path.cwd()) / ".claude" / "settings.json"
    if scope == "user":
        return Path.home() / ".claude" / "settings.json"
    raise ValueError(f"scope must be 'user' or 'project', got {scope!r}")


def _is_ours(entry: dict) -> bool:
    for hook in entry.get("hooks", []):
        command = str(hook.get("command", ""))
        if "-m hooks gate-a" in command or "-m hooks gate-b" in command:
            return True
    return False


def _hook_entry(gate: str, python: str | None, *, matcher: str | None) -> dict:
    entry: dict = {
        "hooks": [
            {
                "type": "command",
                "command": hook_command(gate, python),
                "timeout": 30,
                # A timeout or startup failure must never let the action
                # continue.  The CLI also enforces an internal deadline below
                # 30 s, so it usually prints a decision first.
                "onFailure": "block",
            }
        ]
    }
    if matcher:
        entry["matcher"] = matcher
    return entry


def _merge(settings: dict, python: str | None, *, remove: bool) -> tuple[dict, int, int]:
    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        hooks = {}
        settings["hooks"] = hooks
    removed = added = 0
    for event in ("UserPromptSubmit", "PreToolUse"):
        entries = hooks.get(event, [])
        if not isinstance(entries, list):
            entries = []
        kept = []
        for entry in entries:
            if isinstance(entry, dict) and _is_ours(entry):
                removed += 1
            else:
                kept.append(entry)
        if not remove:
            if event == "UserPromptSubmit":
                kept.insert(0, _hook_entry("a", python, matcher=None))
            else:
                kept.insert(0, _hook_entry("b", python, matcher=TOOL_MATCHER))
            added += 1
        hooks[event] = kept
    return settings, removed, added


def _write_atomic(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2) + "\n"
    if path.exists():
        try:
            if path.read_text(encoding="utf-8") == payload:
                return
        except OSError:
            pass
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
        os.replace(tmp_name, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def install(
    scope: str = "user",
    *,
    python: str | None = None,
    root: Path | None = None,
    dry_run: bool = False,
    claude_version: str | None = None,
) -> InstallReport:
    if claude_version is None:
        # Fail closed: without a known host version we cannot prove that
        # ``onFailure: block`` is honoured, and an unverified hook that times
        # out lets the action run.
        raise ValueError(
            "Claude Code version is unknown: refusing to install a hook that may "
            "not fail closed. Upgrade Claude Code, then pass --claude-version "
            "X.Y.Z (2.1.295 or later) or set BAITWATCH_CLAUDE_VERSION."
        )
    parsed = parse_claude_version(claude_version)
    if parsed < MIN_CLAUDE_VERSION:
        raise ValueError(
            f"Claude Code {claude_version} is too old: BaitWatch needs "
            f"{'.'.join(str(part) for part in MIN_CLAUDE_VERSION)} or later "
            "for fail-closed hook timeouts (onFailure: block)."
        )
    path = settings_path(scope, root=root)
    if path.exists():
        try:
            settings = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"{path}: refusing to overwrite invalid JSON ({exc})") from exc
        if not isinstance(settings, dict):
            raise ValueError(f"{path}: settings must be a JSON object")
    else:
        settings = {}
    merged, removed, added = _merge(settings, python, remove=False)
    changed = True
    if path.exists():
        try:
            changed = json.loads(path.read_text(encoding="utf-8")) != merged
        except (OSError, json.JSONDecodeError):
            changed = True
    if not dry_run and changed:
        _write_atomic(path, merged)
    return InstallReport(path, changed, "install", removed=removed, added=added)


def uninstall(
    scope: str = "user", *, root: Path | None = None, dry_run: bool = False
) -> InstallReport:
    path = settings_path(scope, root=root)
    if not path.exists():
        return InstallReport(path, False, "uninstall")
    try:
        settings = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: cannot parse settings ({exc})") from exc
    if not isinstance(settings, dict):
        raise ValueError(f"{path}: settings must be a JSON object")
    merged, removed, _added = _merge(settings, None, remove=True)
    changed = removed > 0
    if changed and not dry_run:
        _write_atomic(path, merged)
    return InstallReport(path, changed, "uninstall", removed=removed)
