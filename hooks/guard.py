"""Gate logic: turn a repository scan plus a tool call into one decision.

Gate A runs on ``UserPromptSubmit``: if the working directory is a repository,
scan it (cached); also flag prompts that carry an encoded/invisible
instruction.

Gate B runs on ``PreToolUse``: refuse actions that would make a found attack
worse — exfiltration to the test sink, remote pipe-to-shell, reading
credential files, and edits that persist into agent configuration.

Fail-closed rules live here too: :func:`error_decision` turns any hook crash
into ``block`` (or ``ask`` when ``BAITWATCH_ON_ERROR=ask``). Nothing in this
module imports torch; the READ scanner is imported lazily inside
:func:`scan_repo`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

__all__ = [
    "Decision",
    "RepoScan",
    "SINK_NETWORK",
    "error_decision",
    "gate_a",
    "gate_b",
    "prompt_risk",
    "run_gate",
    "scan_repo",
    "static_tool_decision",
]

SINK_NETWORK = ipaddress.ip_network("10.13.37.0/24")
_ALLOWED = ("evil.example",)
# A prompt longer than this cannot be decoded within the hook deadline; it is
# treated as risky (not silently allowed) instead of being inspected halfway.
MAX_PROMPT_CHARS = 65_536

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
_NET_TOOL = (
    r"(?:curl|wget|http|https|nc|ncat|netcat|socat|scp|sftp|ftp|"
    r"Invoke-WebRequest|Invoke-RestMethod|iwr|irm)"
)
_SECRET = (
    r"(?:\.env(?![\w.])|id_rsa|\.ssh\b|\.aws\b|\.netrc\b|"
    r"credentials|secrets?)"
)
_EXFIL_RE = re.compile(rf"{_NET_TOOL}.*{_SECRET}|{_SECRET}.*{_NET_TOOL}", re.IGNORECASE | re.DOTALL)
_REMOTE_EXEC_RE = re.compile(rf"(?:{_NET_TOOL})\b[^|;&\n]*\|\s*(?:ba|z|k|fi)?sh\b", re.IGNORECASE)
_SUBST_EXEC_RE = re.compile(rf"(?:ba|z|k)?sh\s+(?:-c\s+)?[\"']?\$\((?:{_NET_TOOL})", re.IGNORECASE)
_B64_EXEC_RE = re.compile(r"base64\s+(?:-d|--decode)[^|;&\n]*\|\s*(?:ba|z|k|fi)?sh", re.IGNORECASE)
_READ_SECRET_RE = re.compile(rf"\b(?:cat|less|head|tail|cp|scp|base64)\b.*{_SECRET}", re.IGNORECASE)
_DESTRUCTIVE_RE = re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/(?:\s|$)")
_FORCE_PUSH_RE = re.compile(r"\bgit\s+push\b.*--force", re.IGNORECASE)

_AGENT_BASENAMES = {
    "agents.md",
    "agent.md",
    "claude.md",
    "claude.local.md",
    "gemini.md",
    "codex.md",
    "conventions.md",
    ".cursorrules",
    ".clinerules",
    ".windsurfrules",
    ".roorules",
    ".goosehints",
    "copilot-instructions.md",
    ".mcp.json",
    "mcp.json",
}
_AGENT_DIRS = {".claude", ".cursor", ".vscode", ".github", ".windsurf", ".continue"}
_AGENT_FILES = {
    "settings.json",
    "tasks.json",
    "copilot-instructions.md",
    "pre-commit",
    "pre-push",
    "post-checkout",
}

_PROMPT_MARKERS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"ignore (?:all )?(?:the )?(?:previous|prior) instructions",
        r"disregard (?:the|your|all)",
        r"system override",
        r"exfiltrat",
        r"evil\.example",
        r"10\.13\.37\.\d{1,3}",
        r"id_rsa",
        r"\.ssh\b",
        r"(?:curl|wget)\b.*\|\s*(?:ba|z|k|fi)?sh",
        r"(?:ba|z|k|fi)?sh\s+-c\s+[\"']?\$\(",
    )
)


@dataclass
class Decision:
    gate: str
    verdict: str  # allow | ask | block
    reason: str
    source: str = "policy"  # repo | policy | cache | error | off
    files: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    # Gate A may turn a repo/incomplete ASK into ALLOW after an explicit,
    # fingerprint-bound user approval. Prompt risk is never approvable.
    approvable: bool = False

    def as_dict(self) -> dict:
        return {
            "gate": self.gate,
            "verdict": self.verdict,
            "reason": self.reason,
            "source": self.source,
            "files": self.files,
            "duration_ms": round(self.duration_ms, 1),
            "approvable": self.approvable,
        }


@dataclass
class RepoScan:
    verdict: str  # allow | ask | block
    score: float = 0.0
    reason: str = ""
    files: list[str] = field(default_factory=list)
    model: str = ""
    cached: bool = False
    duration_ms: float = 0.0


_RANK = {"allow": 0, "ask": 1, "block": 2}


def _read_tag() -> str:
    """Cache tag: explicit model path, else the pinned checkpoint tag."""
    explicit = os.environ.get("BAITWATCH_MODEL_PATH")
    if explicit:
        return explicit
    pinned = Path(__file__).resolve().parents[1] / "read" / "model_config.json"
    try:
        data = json.loads(pinned.read_text(encoding="utf-8"))
        return str(data.get("tag") or data.get("checkpoint_path") or "pinned")
    except (OSError, json.JSONDecodeError):
        return "default"


def _worst(*verdicts: str) -> str:
    return max(verdicts, key=lambda value: _RANK.get(value, 2))


def _bad_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host in _ALLOWED or host.endswith(".evil.example"):
        return True
    try:
        return ipaddress.ip_address(host) in SINK_NETWORK
    except ValueError:
        return False


def _url_host(url: str) -> str | None:
    """Real hostname, with userinfo/port removed; None when malformed.

    ``.hostname`` alone accepts a broken port, so ``.port`` is read too: a URL
    whose authority cannot be parsed completely is never treated as safe.
    """
    try:
        parts = urlsplit(url)
        _ = parts.port
        return parts.hostname
    except ValueError:
        return None


def _bad_urls(text: str) -> list[str]:
    hits: list[str] = []
    for match in _URL_RE.finditer(text):
        host = _url_host(match.group())
        # A malformed authority (bad port, broken IPv6 literal, empty host)
        # cannot be proven safe, so it is treated exactly like a sink hit.
        if host is None or _bad_host(host):
            hits.append(match.group())
    return hits


def _repo_from(payload: dict) -> Path:
    override = os.environ.get("BAITWATCH_REPO")
    if override:
        return Path(override)
    value = payload.get("cwd") or payload.get("repo") or payload.get("workspace")
    if isinstance(value, dict):
        value = value.get("cwd") or value.get("path")
    if isinstance(value, str) and value:
        return Path(value)
    return Path.cwd()


# Markers strong enough to identify a project root from a subdirectory.  A
# bare README is deliberately not here: it is accepted only for the directory
# the session started in, so an unrelated README higher up cannot widen a scan.
_PROJECT_MARKERS = (
    ".git",
    "AGENTS.md",
    "CLAUDE.md",
    ".cursorrules",
    ".clinerules",
    ".windsurfrules",
    ".claude",
    ".mcp.json",
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "go.mod",
)


def resolve_project_root(path: str | Path) -> tuple[Path | None, str]:
    """Find the project root for a session directory.

    Returns ``(root, status)`` where status is:

    - ``ok``: a marker (or a README-only project root) was found walking up
      from ``path``;
    - ``not_a_repo``: a real directory with no project marker (not a repo);
    - ``unresolved``: the path is missing or is not a directory.
    """
    start = Path(path).expanduser()
    try:
        if not start.exists():
            return None, "unresolved"
        if start.is_file():
            start = start.parent
        if not start.is_dir():
            return None, "unresolved"
        start = start.resolve()
    except OSError:
        return None, "unresolved"

    home: Path | None = None
    try:
        home = Path.home().resolve()
    except (OSError, RuntimeError):
        home = None

    found: Path | None = None
    current = start
    for _ in range(64):
        # Never adopt the user's home directory (or a volume root) as the
        # project root: that would scan unrelated files outside the session.
        if current == home or current.parent == current:
            break
        if any((current / marker).exists() for marker in _PROJECT_MARKERS):
            found = current
        current = current.parent
    if found is not None:
        return found, "ok"
    if home is not None and start == home:
        # A README in the home directory does not make home a project: scanning
        # it would read unrelated files and blow the scan budget.
        return None, "not_a_repo"
    # README-only projects have no marker file, so walk up for one too.  A
    # session started in ``src/`` must find the README at the project root;
    # otherwise Gate B would treat that root as unscanned and allow the read.
    current = start
    for _ in range(64):
        if current == home or current.parent == current:
            break
        if (current / "README.md").is_file():
            return current, "ok"
        current = current.parent
    return None, "not_a_repo"


def _gate_label(gate: str) -> str:
    """One casing on every path: success and crash must agree."""
    value = str(gate).strip().lower()
    if value in ("a", "prompt", "userpromptsubmit"):
        return "A"
    if value in ("b", "tool", "pretooluse"):
        return "B"
    return str(gate).strip().upper()


def error_decision(gate: str, exc: BaseException, duration_ms: float = 0.0) -> Decision:
    """Fail closed: a broken hook must never become an allow."""
    mode = os.environ.get("BAITWATCH_ON_ERROR", "deny").strip().lower()
    verdict = "ask" if mode == "ask" else "block"
    return Decision(
        gate=_gate_label(gate),
        verdict=verdict,
        reason=f"BaitWatch hook failed ({type(exc).__name__}: {exc}); "
        f"failing {'open to a prompt' if verdict == 'ask' else 'closed'}",
        source="error",
        duration_ms=duration_ms,
    )


def scan_repo(repo: str | Path, *, cache=None, model_tag: str = "read-quick") -> RepoScan:
    """Scan a repository with the READ layer, using the hook cache.

    ``BAITWATCH_HOOK_SCANNER=keyword`` swaps in the deterministic CPU scanner
    used by CI and the demo. It is a stand-in, not the product: the default is
    the real READ model, and a machine without torch fails closed.
    """
    started = time.perf_counter()
    repo = Path(repo)
    mode = os.environ.get("BAITWATCH_HOOK_SCANNER", "read").strip().lower()
    tag = "keyword" if mode == "keyword" else _read_tag()
    cache_key = None
    if cache is not None and os.environ.get("BAITWATCH_HOOK_REFRESH") != "1":
        # A key is None when the scanned tree cannot be fingerprinted; then the
        # cache is not consulted or written at all (rescan, never stale ALLOW).
        cache_key = cache.key(repo, tag)
        if cache_key is not None:
            cached = cache.get(cache_key)
            if cached is not None:
                return RepoScan(
                    cached.verdict,
                    cached.score,
                    cached.reason,
                    cached.files,
                    cached.model,
                    cached=True,
                    duration_ms=(time.perf_counter() - started) * 1000,
                )

    if mode == "keyword":
        from attacks.harness import keyword_scanner

        outcome = keyword_scanner(repo)
        if outcome.flagged:
            verdict = "block"
        elif outcome.incomplete:
            verdict = "ask"
        else:
            verdict = "allow"
        files = sorted(outcome.flagged)[:8]
        reason = {
            "block": f"keyword scanner flagged {len(files)} file(s)",
            "ask": "keyword scanner could not cover the repository",
            "allow": "keyword scanner found no injection",
        }[verdict]
        scan_result = RepoScan(
            verdict=verdict,
            score=1.0 if verdict == "block" else 0.0,
            reason=reason,
            files=files,
            model="keyword",
            duration_ms=(time.perf_counter() - started) * 1000,
        )
        if cache is not None:
            from hooks.cache import CachedScan

            if cache_key is None:
                cache_key = cache.key(repo, tag)
            if cache_key is not None:
                cache.set(
                    cache_key,
                    CachedScan(
                        verdict=verdict,
                        score=scan_result.score,
                        reason=reason,
                        files=files,
                        model="keyword",
                        created=time.time(),
                    ),
                )
        return scan_result

    from read.config import ReadConfig  # lazy: keeps hooks importable on CPU
    from read.scan import scan

    cfg = ReadConfig.quick()
    # Inline judging is off by default: a judge round-trip is the most
    # expensive thing a hook can do and must never push it into its deadline.
    # When enabled, keep a small budget so it still finishes in time.
    judge_on = os.environ.get("BAITWATCH_HOOK_JUDGE", "0") == "1"
    cfg.judge.enabled = judge_on
    if judge_on:
        cfg.judge.max_calls_per_scan = min(cfg.judge.max_calls_per_scan, 2)
        cfg.judge.timeout_s = min(cfg.judge.timeout_s, 3.0)
    result = scan(repo, cfg=cfg)
    if result.read_verdict == "attack":
        verdict = "block"
    elif result.read_verdict == "incomplete":
        verdict = "ask"
    else:
        verdict = "allow"
    files = sorted({finding.file for finding in result.flagged})[:8]
    model = Path(str(result.stats.model_path)).name
    reason = {
        "block": f"READ flagged {result.stats.flagged} chunk(s) (max score {result.max_score:.2f})",
        "ask": "READ could not cover the repository completely: "
        + "; ".join(result.stats.incomplete_reasons[:3]),
        "allow": "READ found no injection",
    }[verdict]
    scan_result = RepoScan(
        verdict=verdict,
        score=result.max_score,
        reason=reason,
        files=files,
        model=model,
        duration_ms=(time.perf_counter() - started) * 1000,
    )
    if cache is not None:
        from hooks.cache import CachedScan

        if cache_key is None:
            cache_key = cache.key(repo, tag)
        if cache_key is not None:
            cache.set(
                cache_key,
                CachedScan(
                    verdict=verdict,
                    score=result.max_score,
                    reason=reason,
                    files=files,
                    model=model,
                    created=time.time(),
                ),
            )
    return scan_result


def prompt_risk(prompt: str) -> tuple[bool, str]:
    """True when the prompt carries an encoded or invisible instruction."""
    if not prompt:
        return False, ""
    from attacks.decoderlib import (
        builtin_decoders,
        external_decoders,
        has_suspicious_invisibles,
        produce_views,
    )

    if len(prompt) > MAX_PROMPT_CHARS:
        return True, (
            f"prompt is too long to inspect completely ({len(prompt)} characters); "
            "submit a shorter prompt or approve it explicitly"
        )
    decoders = builtin_decoders() + external_decoders()
    errors: list[tuple[str, str]] = []
    views = produce_views(prompt, decoders, errors=errors)
    if errors:
        return True, "prompt decoding could not cover the full text; treat it as risky"
    for view in views:
        if view.decoder is None:
            continue
        for marker in _PROMPT_MARKERS:
            if marker.search(view.text):
                return True, (f"prompt contains a {view.decoder}-encoded instruction")
    if has_suspicious_invisibles(prompt):
        return True, "prompt contains invisible or bidirectional control characters"
    return False, ""


def static_tool_decision(tool_name: str, tool_input: dict) -> Decision:
    """Policy for one tool call, independent of the repository verdict."""
    tool = (tool_name or "").strip().lower()
    data = tool_input if isinstance(tool_input, dict) else {}

    if tool in ("bash", "shell", "terminal", "run_command", "powershell"):
        command = str(data.get("command") or data.get("cmd") or "")
        if not command:
            return Decision("B", "allow", "no command to inspect")
        bad = _bad_urls(command)
        if bad:
            return Decision("B", "block", f"command contacts the BaitWatch test sink: {bad[0]}")
        if _REMOTE_EXEC_RE.search(command):
            return Decision("B", "block", "command pipes network content into a shell")
        if _SUBST_EXEC_RE.search(command):
            return Decision(
                "B", "block", "command executes network content via command substitution"
            )
        if _B64_EXEC_RE.search(command):
            return Decision("B", "block", "command decodes base64 straight into a shell")
        if _EXFIL_RE.search(command):
            return Decision(
                "B", "block", "command sends credentials or environment files to the network"
            )
        if _DESTRUCTIVE_RE.search(command):
            return Decision("B", "block", "command recursively deletes the filesystem root")
        if _READ_SECRET_RE.search(command):
            return Decision("B", "ask", "command reads a credential file; confirm the destination")
        if _FORCE_PUSH_RE.search(command):
            return Decision("B", "ask", "force-push rewrites shared history")
        return Decision("B", "allow", "command does not match a dangerous pattern")

    if tool in ("write", "edit", "multiedit", "notebookedit"):
        path = str(data.get("file_path") or data.get("path") or data.get("notebook_path") or "")
        if path and _is_agent_config(Path(path)):
            return Decision(
                "B", "ask", f"edit targets agent configuration ({path}); confirm it is intentional"
            )
        return Decision("B", "allow", "edit target is not an agent config")

    if tool in ("webfetch", "fetch", "web_fetch"):
        url = str(data.get("url") or data.get("uri") or "")
        if _bad_urls(url):
            return Decision("B", "block", f"fetch targets the test sink: {url}")
        return Decision("B", "allow", "fetch target is not the test sink")

    if tool in ("read", "view", "open"):
        path = str(data.get("file_path") or data.get("path") or "")
        if _is_secret_path(Path(path)):
            return Decision(
                "B", "ask", f"read targets a credential file ({path}); confirm the agent needs it"
            )
        return Decision("B", "allow", "read target is not a credential file")

    return Decision("B", "allow", f"tool {tool_name!r} has no policy entry")


def _is_agent_config(path: Path) -> bool:
    name = path.name.lower()
    if name in _AGENT_BASENAMES:
        return True
    parents = {part.lower() for part in path.parts[:-1]}
    return bool(parents & _AGENT_DIRS) and name in _AGENT_FILES


def _is_secret_path(path: Path) -> bool:
    name = path.name.lower()
    if name == ".env" or name.startswith(".env."):
        return name not in (".env.example", ".env.sample", ".env.template")
    if name in ("id_rsa", "id_ed25519", "credentials", ".netrc"):
        return True
    return any(part.lower() in (".ssh", ".aws", ".gnupg") for part in path.parts)


def _combine(
    gate: str, repo: RepoScan | None, policy: Decision | None, prompt_reason: str = ""
) -> Decision:
    reasons: list[str] = []
    source = "policy"
    files: list[str] = []
    verdict = "allow"
    if repo is not None:
        verdict = _worst(verdict, repo.verdict)
        reasons.append(repo.reason)
        source = "cache" if repo.cached else "repo"
        files = repo.files
    if policy is not None:
        verdict = _worst(verdict, policy.verdict)
        if policy.verdict != "allow":
            reasons.append(policy.reason)
    if prompt_reason:
        verdict = _worst(verdict, "ask")
        reasons.append(prompt_reason)
    if verdict == "allow":
        reasons.append("no repository risk and no dangerous tool pattern")
    return Decision(
        gate, verdict, "; ".join(reason for reason in reasons if reason), source=source, files=files
    )


def _outside_root(path: str, root: Path) -> bool:
    """True for an absolute tool target outside the scanned project root."""
    if not path:
        return False
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        return False
    try:
        candidate = candidate.resolve()
        root = root.resolve()
    except OSError:
        return True
    return candidate != root and root not in candidate.parents


def gate_a(payload: dict, *, scanner=scan_repo, cache=None) -> Decision:
    started = time.perf_counter()
    prompt = str(payload.get("prompt") or payload.get("user_prompt") or "")
    repo = _repo_from(payload)
    risky, why = prompt_risk(prompt)
    root, status = resolve_project_root(repo)
    repo_scan = None
    unresolved = status == "unresolved"
    if status == "ok" and root is not None:
        repo_scan = scanner(root) if scanner is not scan_repo else scan_repo(root, cache=cache)
    decision = _combine("A", repo_scan, None, why if risky else "")
    if unresolved:
        decision.verdict = _worst(decision.verdict, "ask")
        decision.reason = "; ".join(
            part
            for part in (
                f"project root could not be resolved from {repo}; refusing an unscanned session",
                decision.reason,
            )
            if part
        )
        decision.source = "error"
    if decision.verdict == "ask" and not risky and not unresolved and root is not None:
        decision.approvable = True
        from hooks.cache import ApprovalStore

        if ApprovalStore().is_approved(root):
            decision.verdict = "allow"
            decision.reason = f"{decision.reason}; approved for this exact tree by the user"
    decision.duration_ms = (time.perf_counter() - started) * 1000
    return decision


def gate_b(payload: dict, *, scanner=scan_repo, cache=None) -> Decision:
    started = time.perf_counter()
    tool_name = str(payload.get("tool_name") or payload.get("toolName") or "")
    tool_input = payload.get("tool_input") or payload.get("toolInput") or {}
    repo = _repo_from(payload)
    root, status = resolve_project_root(repo)
    if status == "unresolved":
        decision = Decision(
            "B",
            "ask",
            f"project root could not be resolved from {repo}; cannot verify this tool call",
            source="error",
        )
        decision.duration_ms = (time.perf_counter() - started) * 1000
        return decision
    repo_scan = None
    if status == "ok" and root is not None:
        repo_scan = scanner(root) if scanner is not scan_repo else scan_repo(root, cache=cache)
    if repo_scan is not None and repo_scan.verdict == "block":
        decision = Decision(
            "B",
            "block",
            f"repository is blocked: {repo_scan.reason}",
            source="repo",
            files=repo_scan.files,
        )
        decision.duration_ms = (time.perf_counter() - started) * 1000
        return decision
    policy = static_tool_decision(tool_name, tool_input)
    tool = tool_name.strip().lower()
    if (
        policy.verdict == "allow"
        and root is not None
        and tool
        in (
            "write",
            "edit",
            "multiedit",
            "notebookedit",
        )
    ):
        data = tool_input if isinstance(tool_input, dict) else {}
        target = str(data.get("file_path") or data.get("path") or data.get("notebook_path") or "")
        if _outside_root(target, root):
            policy = Decision(
                "B",
                "ask",
                f"edit target {target!r} is outside the scanned project root {root}",
            )
    decision = _combine("B", repo_scan, policy)
    decision.duration_ms = (time.perf_counter() - started) * 1000
    return decision


def run_gate(gate: str, payload: dict, *, scanner=scan_repo, cache=None) -> Decision:
    if gate.lower() in ("a", "prompt", "userpromptsubmit"):
        return gate_a(payload, scanner=scanner, cache=cache)
    if gate.lower() in ("b", "tool", "pretooluse"):
        return gate_b(payload, scanner=scanner, cache=cache)
    raise ValueError(f"unknown gate {gate!r}")
