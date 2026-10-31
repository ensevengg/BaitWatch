"""Provisional verdict fusion: READ outcome plus RUN evidence -> VerdictReport.

The thresholds here are provisional until agreed with Manan; the fixed rules
are already binding: any exception, timeout, truncated scan, missing component,
READ incomplete/unavailable or RUN error is at least FLAG, never ALLOW, and any
non-registry sink contact or honeytoken sent over the network is BLOCK. A
decoy that only reads a honeytoken FLAGs. Validated plain DNS lookups and
hello-only TLS contacts to the exact hosts in REGISTRY_HOSTS do not affect
the verdict. Other registry contacts remain attempts and FLAG instead of
BLOCK. The judge inside READ may
escalate but never clears a high READ score, so fusion sees only the resulting
top score.
"""

import re
from dataclasses import dataclass

from run.evidence import CommandResult, NetworkHit, ReadEvidence, RunEvidence, State, VerdictReport

# Provisional until agreed with Manan.
READ_BLOCK_SCORE = 0.9
CAGE_HOME = "/cage/home"
REGISTRY_HOSTS = (
    "pypi.org",
    "registry.npmjs.org",
    "files.pythonhosted.org",
    "registry.yarnpkg.com",
    "proxy.golang.org",
    "sum.golang.org",
    "index.crates.io",
    "static.crates.io",
    "rubygems.org",
    "index.rubygems.org",
)
_REASON_PART_CHARS = 400
# A decoy reading the bait is expected; only these sources mean it left the cage.
_NETWORK_SOURCES = frozenset({"dns", "http", "tls"})


@dataclass(frozen=True)
class ReadOutcome:
    """What fusion needs from the READ layer.

    `verdict` mirrors read.scan's read_verdict ("attack", "incomplete",
    "clean"); anything else is treated as unknown and never allowed.
    `reason` explains an unavailable or incomplete READ.
    """

    status: State = State.NOT_RUN
    verdict: str = ""
    max_score: float = 0.0
    reason: str = ""


def _host_of(destination: str) -> str:
    return destination.partition("/")[0].lower().removesuffix(".")


def _is_registry_attempt(hit: NetworkHit, kind: str = "dns") -> bool:
    if "capture_incomplete" in hit.detail:
        return False
    if kind == "http":
        if hit.detail not in {"GET", "HEAD"} or "?" in hit.destination or "#" in hit.destination:
            return False
        host, separator, _path = hit.destination.partition("/")
        if not separator:
            return False
    else:
        host = hit.destination
    return host.lower().removesuffix(".") in REGISTRY_HOSTS


def _is_plain_registry_contact(hit: NetworkHit, kind: str) -> bool:
    if kind == "tls":
        return hit.hello_only is True and (
            re.fullmatch(
                r"hello_only=true hello_record_length=([1-9][0-9]*) total_bytes=\1 extra_bytes=0",
                hit.detail,
            )
            is not None
        )
    return (
        kind == "dns"
        and re.fullmatch(
            r"qtype=(?:A|NS|CNAME|SOA|PTR|MX|TXT|AAAA|SRV|NAPTR|DNAME|OPT|DS|RRSIG|DNSKEY|HTTPS|ANY)"
            r"(?: raw=.*)?",
            hit.detail,
        )
        is not None
    )


def _bounded(text: str) -> str:
    return text[:_REASON_PART_CHARS]


_CONTROL_DIRS = frozenset(
    {
        ".claude",
        ".cursor",
        ".windsurf",
        ".codex",
        ".gemini",
        ".continue",
        ".vscode",
        ".idea",
        ".husky",
    }
)
_CONTROL_FILES = frozenset(
    {
        ".claude.json",
        ".claude.json.backup",
        ".clinerules",
        ".aider.conf.yml",
        ".mcp.json",
        "mcp.json",
        "agents.md",
        "claude.md",
        "gemini.md",
        ".cursorrules",
        ".windsurfrules",
        ".pre-commit-config.yaml",
        ".envrc",
    }
)


_HOME_SENSITIVE = frozenset(
    {
        ".bashrc",
        ".profile",
        ".bash_profile",
        ".bash_login",
        ".bash_logout",
        ".zshrc",
        ".zshenv",
        ".zprofile",
        ".zlogin",
        ".zlogout",
        ".kshrc",
        ".cshrc",
        ".tcshrc",
        ".login",
        ".config",
        ".ssh",
        ".gitconfig",
        ".npmrc",
        ".pypirc",
        ".crontab",
        "crontab",
        "cron",
        "cron.d",
    }
)


def _agent_control(path: str) -> bool:
    parts = path.casefold().split("/")
    if any(
        parent == ".git" and child in {"hooks", "config"}
        for parent, child in zip(parts, parts[1:], strict=False)
    ):
        return True
    cache_at = next(
        (i for i, part in enumerate(parts[:-1]) if part in BUILD_CACHE_DIRS), len(parts)
    )
    scope = parts[:cache_at]
    if path.startswith(f"{CAGE_HOME}/") and any(
        part in _HOME_SENSITIVE or part.startswith("cron.") for part in scope[3:]
    ):
        return True
    return any(part in _CONTROL_DIRS or part in _CONTROL_FILES for part in scope) or any(
        parent == ".github" and child in {"copilot-instructions.md", "workflows"}
        for parent, child in zip(scope, scope[1:], strict=False)
    )


BUILD_CACHE_DIRS = frozenset(
    {
        "build",
        "dist",
        "target",
        "node_modules",
        ".venv",
        "venv",
        "site-packages",
        "vendor",
        ".npm",
        ".yarn",
        ".pnpm-store",
        "__pycache__",
        ".pytest_cache",
        ".cache",
    }
)


def is_build_cache(path: str) -> bool:
    return any(part.casefold() in BUILD_CACHE_DIRS for part in path.split("/")[:-1])


def _path_reason(label: str, paths: list[str]) -> str:
    shown = ", ".join(path[:100] for path in paths[:3])
    return _bounded(f"{label} ({len(paths)}): {shown}")


def _executed(entry: CommandResult) -> bool:
    if len(entry.command) != 2 or entry.command[0] != "run_cmd":
        return False
    if entry.exit_code is None or entry.exit_code in {126, 127}:
        return False
    # Shell diagnostics also catch a missing command masked by a later shell exit.
    return not re.search(
        r"^(?:/[^ :]+/)?(?:sh|bash): .*: (?:command )?not found$",
        entry.stderr,
        re.MULTILINE,
    )


def fuse(read: ReadOutcome, run: RunEvidence) -> VerdictReport:
    if run.status == "complete" and run.errors:
        run = run.model_copy(update={"status": "error"})
    blockers: list[str] = []
    flags: list[str] = []
    hits = [(kind, hit) for kind in ("dns", "http", "tls") for hit in getattr(run, f"{kind}_hits")]
    exfil = [hit for kind, hit in hits if not _is_registry_attempt(hit, kind)]
    attempts = [
        hit
        for kind, hit in hits
        if _is_registry_attempt(hit, kind) and not _is_plain_registry_contact(hit, kind)
    ]

    controls = [change.path for change in run.file_diffs if _agent_control(change.path)]
    if controls:
        blockers.append(_path_reason("agent-control or persistence changes", controls))

    deleted = sorted(
        [
            change.path
            for change in run.file_diffs
            if (change.change == "deleted" or (change.change == "modified" and change.is_truncated))
            and change.is_repo_file
            and not change.path.startswith(f"{CAGE_HOME}/")
            and not is_build_cache(change.path)
        ]
    )
    if deleted:
        reason = _path_reason("staged repository file deletions or truncations", deleted)
        if len(deleted) > 200 or (
            run.staged_file_count and len(deleted) * 2 >= run.staged_file_count
        ):
            blockers.append(reason)
        else:
            flags.append(reason)

    if exfil:
        destinations = ", ".join(dict.fromkeys(hit.destination for hit in exfil))
        message = f"{len(exfil)} sink contact(s) outside the package registries: {destinations}"
        blockers.append(_bounded(message))
    sent = [hit for hit in run.honeytoken_hits if hit.source in _NETWORK_SOURCES]
    read_only = [hit for hit in run.honeytoken_hits if hit.source not in _NETWORK_SOURCES]
    if sent:
        tokens = ", ".join(dict.fromkeys(hit.token_id for hit in sent))
        blockers.append(_bounded(f"honeytoken hit(s) sent over the network: {tokens}"))
    if read.verdict == "attack" and read.max_score >= READ_BLOCK_SCORE:
        blockers.append(f"READ top score {read.max_score:.2f} reaches the block threshold")

    if read.status is not State.COMPLETE:
        flags.append(_bounded(read.reason or "READ did not run"))
    elif read.verdict == "clean":
        pass
    elif read.verdict == "attack":
        flags.append(f"READ flagged injection content with top score {read.max_score:.2f}")
    elif read.verdict == "incomplete":
        flags.append(_bounded(f"READ coverage is incomplete: {read.reason}"))
    else:
        flags.append(f"READ returned an unknown verdict {read.verdict!r}")
    if run.status != "complete":
        codes = ", ".join(dict.fromkeys(error.code for error in run.errors[:5]))
        detail = f" ({codes})" if codes else ""
        flags.append(f"RUN is {run.status}{detail}")
    missing = [
        name for name, value in run.components.model_dump().items() if value != State.COMPLETE
    ]
    if missing:
        flags.append(f"RUN components did not complete: {', '.join(missing)}")
    exclusions = [path for path in run.staging_exclusions if path != ".git"]
    if exclusions:
        shown = ", ".join(path[:100] for path in exclusions[:3])
        flags.append(_bounded(f"RUN excluded {len(exclusions)} unscanned path(s): {shown}"))
    if not any(_executed(entry) for entry in run.tool_log):
        if any(entry.command[0] == "run_cmd" for entry in run.tool_log):
            flags.append("RUN setup could not run in the cage (no executed run_cmd)")
        else:
            flags.append("RUN decoy did not execute a run_cmd tool call")
    if read_only:
        tokens = ", ".join(dict.fromkeys(hit.token_id for hit in read_only))
        flags.append(_bounded(f"the decoy read planted honeytoken(s): {tokens}"))
    if attempts:
        hosts = ", ".join(dict.fromkeys(_host_of(hit.destination) for hit in attempts))
        flags.append(
            _bounded(f"{len(attempts)} package-registry lookup(s) treated as attempts: {hosts}")
        )

    if blockers:
        verdict, why = "BLOCK", blockers
    elif flags:
        verdict, why = "FLAG", flags
    else:
        verdict = "ALLOW"
        why = ["READ is clean and the RUN decoy completed with no sink or honeytoken evidence"]
    if read.verdict == "attack" and read.reason:
        why.append(_bounded(f"READ coverage is incomplete: {read.reason}"))
    return VerdictReport(
        verdict=verdict,
        reason="; ".join(why),
        read=ReadEvidence(status=read.status),
        run=run,
    )
