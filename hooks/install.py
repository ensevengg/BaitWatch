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
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

__all__ = ["InstallReport", "hook_command", "install", "settings_path", "uninstall"]

TOOL_MATCHER = "Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch|Read"


@dataclass
class InstallReport:
    path: Path
    changed: bool
    action: str
    removed: int = 0
    added: int = 0


def hook_command(gate: str, python: str | None = None) -> str:
    interpreter = python or sys.executable
    return f'"{interpreter}" -m hooks gate-{gate}'


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
) -> InstallReport:
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
