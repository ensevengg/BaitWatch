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

import hashlib
import ipaddress
import json
import os
import re
import shlex
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlsplit

__all__ = [
    "DEFAULT_HOOK_DEADLINE_S",
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
# A first scan reads the whole repository, one batch after another, and security comes
# before speed. Most repositories finish in under 3 minutes. Later scans read only
# what changed, and a scan that runs out of time resumes where it stopped.
DEFAULT_HOOK_DEADLINE_S = 600.0
HOOK_DECISION_MARGIN_S = 8.0
BLOCK_MIN_SCORE = 0.7

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
    detail: str = ""  # for the person at Gate A; never sent to the agent
    notice: str = ""  # shown to the person when a prompt is allowed

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
    covered: list[str] | None = None  # files read in full; None: not recorded
    detail: str = ""  # what was flagged and why, for the person at Gate A
    notice: str = ""  # what the scan did and did not check


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
# bare README is deliberately not a strong marker: it is handled by the
# fallback in resolve_project_root below, which adopts the nearest ancestor
# containing one when no strong marker exists.  That fallback stops before
# the user's home directory and before a volume root.  It has no depth cap:
# cutting the walk to one or two levels would leave deeper sessions in a real
# README-only project unscanned.  The trade-off is that a session below a
# large README-bearing tree (for example ~/notes/2026/oct under ~/notes) can
# adopt that tree; the scanner's normal file cap and incomplete-evidence
# handling keep an oversized result fail-closed rather than silently clean.
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

    - ``ok``: a strong marker was found walking up from ``path``, or (when no
      strong marker exists) the nearest ``README.md`` ancestor below home and
      below the volume root was adopted;
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

    current = start
    for _ in range(64):
        # Never adopt the user's home directory (or a volume root) as the
        # project root: that would scan unrelated files outside the session.
        if current == home or current.parent == current:
            break
        if any((current / marker).exists() for marker in _PROJECT_MARKERS):
            return current, "ok"
        current = current.parent
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


def _store_cached_scan(
    cache, repo: Path, tag: str, cache_key: str | None, scan_result: RepoScan, model: str
) -> None:
    """Store a verdict only for the exact tree fingerprint seen pre-scan.

    Recreating a key after the scan would attach this verdict to whatever
    tree happens to be present then, which may not be the tree that was
    scanned.  A missing or changed pre-scan key therefore stores nothing.
    """
    if cache is None or cache_key is None:
        return
    if cache.key(repo, tag) != cache_key:
        return
    from hooks.cache import CachedScan

    cache.set(
        cache_key,
        CachedScan(
            verdict=scan_result.verdict,
            score=scan_result.score,
            reason=scan_result.reason,
            files=scan_result.files,
            model=model,
            created=time.time(),
            covered=scan_result.covered,
            detail=scan_result.detail,
        ),
    )


def _verdict_from_read(
    read_verdict: str, flagged: list, min_model_score: float
) -> tuple[str, list]:
    """The verdict, and the flagged files that only matter if an agent opens them.

    - Block: the model and the judge agree on an agent-facing file, the score is at
      least 0.7, or BaitWatch itself failed. All 17 attack repositories we test have
      two such signals.
    - Ask: they agree somewhere else, the judge alone flags an agent-facing file, the
      score is low, or no judge confirmed a model flag. Asking still stops the prompt.
    - The judge alone on any other file does not stop the prompt: it mostly reacts to
      ordinary install instructions there. That file is refused when opened.
    """
    from hooks.lightread import load

    if read_verdict != "attack":
        return ("ask" if read_verdict == "incomplete" else "allow"), []
    tier = load("tiers").priority_tier
    deferred: list[str] = []
    verdict = "allow"
    for finding in flagged:
        if finding.layer == "system":
            return "block", []
        confirmed = finding.layer != "model" or bool(finding.evidence.get("judge_confirmed"))
        two_signal = confirmed and finding.evidence.get("model_score", 0.0) >= min_model_score
        agent_facing = tier(finding.file) <= 1
        if two_signal and agent_facing and finding.score >= BLOCK_MIN_SCORE:
            return "block", []
        if not confirmed or two_signal or agent_facing:
            verdict = "ask"
        else:
            deferred.append(finding.file)
    return verdict, sorted(set(deferred))


def _flag_detail(flagged: list, limit: int = 3) -> str:
    """Where and why, for the person at Gate A.

    The judge read attacker-controlled text, so this stays short, on one line, and
    labelled as its reading. It is never sent to the agent.
    """
    lines = []
    for finding in flagged[:limit]:
        line = finding.evidence.get("line")
        where = f"{finding.file}:{line}" if line else finding.file
        why = " ".join(str(finding.explanation or "no judge explanation").split())[:200]
        why = "".join(ch for ch in why if ch.isprintable())
        lines.append(f"- {where} (judge's reading: {why})")
    return "\n".join(lines)


def _hook_judge_on() -> bool:
    """On when a key is present, unless BAITWATCH_HOOK_JUDGE=0."""
    return os.environ.get("BAITWATCH_HOOK_JUDGE", "1") != "0" and bool(
        os.environ.get("META_API_KEY")
    )


def _hook_deadline() -> float:
    try:
        value = float(os.environ.get("BAITWATCH_HOOK_DEADLINE", str(DEFAULT_HOOK_DEADLINE_S)))
    except ValueError:
        return DEFAULT_HOOK_DEADLINE_S
    return value if value > 0 else DEFAULT_HOOK_DEADLINE_S


def scan_repo(repo: str | Path, *, cache=None, model_tag: str = "read-quick") -> RepoScan:
    """Scan a repository with the READ layer, using the hook cache.

    ``BAITWATCH_HOOK_SCANNER=keyword`` swaps in the deterministic CPU scanner
    used by CI and the demo. It is a stand-in, not the product: the default is
    the real READ model, and a machine without torch fails closed.
    """
    started = time.perf_counter()
    repo = Path(repo)
    mode = os.environ.get("BAITWATCH_HOOK_SCANNER", "read").strip().lower()
    # A verdict reached without the judge must not answer for one reached with it.
    tag = "keyword" if mode == "keyword" else _read_tag() + ("+judge" if _hook_judge_on() else "")
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
                    covered=cached.covered,
                    detail=cached.detail,
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
        _store_cached_scan(cache, repo, tag, cache_key, scan_result, "keyword")
        return scan_result

    from hooks.cache import scanner_signature
    from read.batches import scan_in_batches
    from read.cache import DEFAULT_FILE_CACHE_PATH, FileResultCache
    from read.config import ReadConfig  # lazy: keeps hooks importable on CPU

    cfg = ReadConfig.quick()
    judge_on = _hook_judge_on()
    cfg.judge.enabled = judge_on
    store = FileResultCache(DEFAULT_FILE_CACHE_PATH)
    # Leave time to print a decision before the hook's own deadline. What a scan
    # did not reach is picked up by the next one.
    result = scan_in_batches(
        repo,
        cfg,
        store=store if store.enabled else None,
        store_salt=f"{tag}|{scanner_signature()}",
        time_limit_s=max(1.0, _hook_deadline() - HOOK_DECISION_MARGIN_S),
        stop_score=BLOCK_MIN_SCORE,
    )
    stats = result.stats
    flagged = result.flagged
    confirmed = any(
        finding.layer != "model" or finding.evidence.get("judge_confirmed") for finding in flagged
    )
    verdict, deferred = _verdict_from_read(result.read_verdict, flagged, cfg.review_low)
    files = sorted({finding.file for finding in flagged})[:8]
    names = ", ".join(files[:3])
    model = Path(str(stats.model_path)).name
    total = stats.best_effort_gaps + len(stats.files_covered)
    if result.read_verdict != "attack":
        ask_reason = "READ could not cover the repository completely: " + "; ".join(
            stats.incomplete_reasons[:3]
        )
    elif confirmed:
        ask_reason = (
            f"READ flagged {stats.flagged} chunk(s) in {names} "
            f"(max score {result.max_score:.2f}): review before continuing"
        )
    elif judge_on:
        ask_reason = (
            f"the model flagged {names} (max score {result.max_score:.2f}), but the judge "
            f"could not confirm it: {stats.judge_last_error or 'no answer'}"
        )
    else:
        ask_reason = (
            f"the model flagged {names} (max score {result.max_score:.2f}), but no judge "
            "confirmed it, and the model alone often flags harmless files. "
            "Set META_API_KEY to turn the judge on"
        )
    reason = {
        "block": f"READ flagged {stats.flagged} chunk(s) in {names} "
        f"(max score {result.max_score:.2f})",
        "ask": ask_reason,
        "allow": f"READ found no injection in the {len(stats.files_covered)} files it checked",
    }[verdict]
    # A deferred file stays out of "covered", so Gate B refuses it when it is opened.
    covered = [rel for rel in stats.files_covered if rel not in deferred]
    notice = ""
    if deferred:
        notice = (
            f"BaitWatch found text aimed at agents in {', '.join(deferred[:3])}"
            f"{' and others' if len(deferred) > 3 else ''}. The prompt can run, "
            "but an agent is stopped if it opens these files."
        )
    elif verdict == "allow" and not stats.files_cached:
        notice = (
            f"BaitWatch checked {len(stats.files_covered)} of {total} files and found no "
            "injection. This lowers the risk; it does not prove the repository is safe."
        )
        if stats.best_effort_gaps:
            notice += (
                " Files it skipped, such as generated ones, are checked if an agent opens them."
            )
    if verdict == "allow" and not judge_on:
        notice = f"{notice} No judge is running: set META_API_KEY for better results.".strip()
    scan_result = RepoScan(
        verdict=verdict,
        score=result.max_score,
        reason=reason,
        files=files,
        model=model,
        duration_ms=(time.perf_counter() - started) * 1000,
        covered=covered,
        detail=_flag_detail(flagged) if verdict != "allow" else "",
        notice=notice,
    )
    # An outage or running out of time is temporary, so scan again next time. Budget
    # cuts are stable: rescanning would give the same answer at the same cost.
    if not (
        stats.scan_time_limit_hit
        or (judge_on and (stats.judge_unavailable or stats.judge_deadline_hit))
    ):
        _store_cached_scan(cache, repo, tag, cache_key, scan_result, model)
    return scan_result


# Words that make a tier-3 file (source code, data) worth a model load when an
# agent opens it. Tier 0-2 files are always scanned; loading the model for every
# source file an agent opens would add about 5 s per file.
_AGENT_TALK_RE = re.compile(
    r"\b(?:ai|llm|agents?|assistants?|claude|copilot|cursor|gpt|codex|gemini|muse|"
    r"ignore (?:all|any|previous|prior)|instructions?|system prompt)\b",
    re.IGNORECASE,
)
_IMPERATIVE_RE = re.compile(
    r"\b(?:always|never|must|do not|don't|make sure|before you|when you|you should|you must|"
    r"first,|run|execute|download|install|fetch|send|upload|delete|disable|skip|bypass|"
    r"add|remove|set)\b",
    re.IGNORECASE,
)
_PROSE_WORDS = frozenset(
    [
        "the",
        "and",
        "all",
        "your",
        "you",
        "this",
        "that",
        "with",
        "from",
        "before",
        "after",
        "send",
        "run",
        "read",
        "file",
        "files",
        "user",
        "secret",
        "token",
        "not",
        "a",
        "an",
        "of",
        "to",
        "in",
        "is",
        "are",
        "be",
        "it",
        "on",
        "for",
        "as",
        "at",
        "by",
        "or",
        "if",
        "we",
        "our",
        "can",
        "will",
        "should",
        "must",
        "when",
        "then",
        "use",
        "using",
    ]
)
_BINARY_LOOKING = {
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".zip",
    ".gz",
    ".bin",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".pyc",
    ".class",
    ".wasm",
    ".woff",
    ".woff2",
    ".ttf",
    ".doc",
    ".docx",
    ".xlsx",
}
_READING_COMMANDS = {"cat", "head", "tail", "less", "more", "bat", "nl", "sed", "awk"}
_MAX_READ_TARGETS = 5
_SHELL_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")


def _read_targets(tool: str, data: dict) -> list[str]:
    """Files this tool call will show the agent, as far as can be told statically."""
    if tool in ("read", "view", "open", "grep"):
        path = data.get("file_path") or data.get("path")
        return [str(path)] if path else []
    if tool not in ("bash", "shell", "terminal", "run_command"):
        return []
    targets: list[str] = []
    for part in _SHELL_SPLIT_RE.split(str(data.get("command") or data.get("cmd") or "")):
        try:
            words = shlex.split(part)
        except ValueError:
            continue
        if not words or Path(words[0]).name not in _READING_COMMANDS:
            continue
        args = [word for word in words[1:] if not word.startswith("-") and not word.isdigit()]
        if Path(words[0]).name in ("sed", "awk"):
            args = args[1:]  # the first free argument is the script
        targets.extend(args)
    return targets[:_MAX_READ_TARGETS]


def _has_imperative_prose(text: str) -> bool:
    """A line that reads as an English instruction, such as one in a comment or string."""
    for line in text.splitlines():
        words = re.findall(r"[A-Za-z']+", line)
        if (
            len(words) >= 7
            and _IMPERATIVE_RE.search(line)
            and sum(word.lower() in _PROSE_WORDS for word in words) >= 2
        ):
            return True
    return False


def _worth_scanning_on_read(path: Path, rel: str) -> bool:
    """Tier 0-2 always; tier 3 when it looks agent-directed, decoded or not.

    On real attack windows this sees 91%, and it asks for the model on 38% of
    ordinary source files. Scanning anything with prose sees all of them, but
    asks on 71%, at about 5 s per file.
    """
    from attacks.decoderlib import builtin_decoders, produce_views
    from hooks.lightread import load

    tiers = load("tiers")
    if tiers.priority_tier(rel) <= 2 or tiers.is_generated(rel):
        return True
    rule_hits = load("rules").rule_hits
    try:
        with open(path, "rb") as handle:
            raw = handle.read(262_144)
    except OSError:
        return False
    if path.suffix.lower() in _BINARY_LOOKING and b"\x00" not in raw[:8192]:
        return True  # text wearing a binary extension, which the repository scan skips
    text = raw.decode("utf-8", "replace")
    return any(
        _AGENT_TALK_RE.search(view.text) or rule_hits(view.text) or _has_imperative_prose(view.text)
        for view in produce_views(text, builtin_decoders())
    )


def _file_digest(path: Path) -> str:
    """SHA-256 in blocks: a hook must not load a large file into memory to name it."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _judge_time_left(started: float) -> float:
    """Seconds the judge may still start calls in a gate that began at ``started``."""
    elapsed = time.perf_counter() - started
    return max(0.0, _hook_deadline() - HOOK_DECISION_MARGIN_S - elapsed)


def scan_opened_file(path: Path, rel: str, *, cache=None, started: float | None = None) -> Decision:
    """Score one file the repository scan did not cover, as the agent opens it."""
    from hooks.cache import CachedScan
    from read.config import ReadConfig
    from read.scan import scan
    from read.walk import priority_tier

    try:
        digest = _file_digest(path)
    except OSError as exc:
        return Decision("B", "ask", f"could not read {rel} to check it: {exc}", source="read")
    key = f"open|{digest}|{rel}|{_read_tag()}|{_hook_judge_on()}"
    if cache is not None:
        hit = cache.get(key)
        if hit is not None:
            return Decision("B", hit.verdict, hit.reason, source="read", files=hit.files)
    cfg = ReadConfig.quick()
    # One file: its gaps count, whatever its tier.
    cfg.bulk_best_effort = False
    cfg.judge.max_windows_per_file = cfg.judge.max_windows_per_agent_file
    cfg.judge.enabled = _hook_judge_on()
    if cfg.judge.enabled:
        # The repository scan in this gate may already have used most of the deadline.
        gate_start = time.perf_counter() if started is None else started
        cfg.judge.deadline_s = _judge_time_left(gate_start)
    result = scan(path, cfg=cfg)
    stats = result.stats
    if result.read_verdict == "attack":
        verdict = "block" if cfg.judge.enabled and result.max_score >= BLOCK_MIN_SCORE else "ask"
        reason = f"{rel} contains text aimed at the agent (score {result.max_score:.2f})"
    elif stats.partial_files and priority_tier(rel) <= 2:
        verdict, reason = "ask", f"{rel} is too large to check in full"
    elif stats.judge_overflow_files:
        verdict, reason = "ask", f"{rel} has more suspicious sections than could be judged"
    elif any(f.status == "reviewed" and f.evidence.get("note") for f in result.findings):
        verdict, reason = "ask", f"{rel} looks suspicious and could not be judged"
    else:
        verdict, reason = "allow", f"{rel} checked on open"
    if cache is not None and not (stats.judge_unavailable or stats.judge_deadline_hit):
        cache.set(key, CachedScan(verdict, result.max_score, reason, [rel], "read", time.time()))
    return Decision("B", verdict, reason, source="read", files=[rel])


def _project_path(raw: str, root: Path, cwd) -> Path | None:
    """The opened path inside ``root``, or None when it is outside the project.

    ``root`` is resolved but the session path may not be, for example through a
    symlinked project directory. Only the parent is resolved on that path, so an
    in-repo symlink keeps its own name.
    """
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = Path(cwd) / candidate
    lexical = Path(os.path.normpath(candidate))
    if lexical.is_relative_to(root):
        return lexical
    try:
        aliased = lexical.parent.resolve() / lexical.name
    except (OSError, RuntimeError):
        return None
    return aliased if aliased.is_relative_to(root) else None


def _opened_file_decision(
    tool, data, repo_scan, root, cwd, *, cache=None, started: float | None = None
) -> Decision | None:
    """Check files this call opens that the repository scan left out, worst first."""
    if repo_scan is None or repo_scan.covered is None or root is None:
        return None
    covered = set(repo_scan.covered)
    worst: Decision | None = None
    for raw in _read_targets(tool, data):
        lexical = _project_path(raw, root, cwd)
        if lexical is None:
            continue  # outside the project: the credential rules still apply
        rel = lexical.relative_to(root).as_posix()
        if rel in covered or not lexical.is_file():
            continue
        target = lexical.resolve()
        if not _worth_scanning_on_read(target, rel):
            continue
        decision = scan_opened_file(target, rel, cache=cache, started=started)
        if worst is None or _RANK[decision.verdict] > _RANK[worst.verdict]:
            worst = decision
    return worst


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
        # "Found no injection" next to a refusal contradicts itself: only the refusal counts.
        refused = (policy is not None and policy.verdict != "allow") or prompt_reason
        if repo.verdict != "allow" or not refused:
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
        gate,
        verdict,
        "; ".join(reason for reason in reasons if reason),
        source=source,
        files=files,
        detail=repo.detail if repo is not None else "",
        notice=repo.notice if repo is not None and not repo.cached else "",
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
    if (
        decision.verdict == "block"
        and not risky
        and not unresolved
        and root is not None
        and repo_scan is not None
        and repo_scan.verdict == "block"
    ):
        from hooks.cache import ApprovalStore

        if ApprovalStore().is_approved(root, block=True):
            decision.verdict = "allow"
            decision.detail = ""
            decision.reason = (
                f"{decision.reason}; the user chose to continue past this for this exact tree"
            )
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
    if repo_scan is not None and repo_scan.verdict in ("ask", "block"):
        from hooks.cache import ApprovalStore

        if ApprovalStore().is_approved(root, block=repo_scan.verdict == "block"):
            # The user approved this exact tree at Gate A. Actions are still checked below.
            repo_scan = replace(
                repo_scan,
                verdict="allow",
                reason=f"{repo_scan.reason}; approved for this exact tree by the user",
            )
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
    if policy.verdict != "block" and root is not None and scanner is scan_repo:
        opened = _opened_file_decision(
            tool,
            tool_input if isinstance(tool_input, dict) else {},
            repo_scan,
            root,
            repo,
            cache=cache,
            started=started,
        )
        if opened is not None and _RANK[opened.verdict] > _RANK[policy.verdict]:
            policy = opened
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
