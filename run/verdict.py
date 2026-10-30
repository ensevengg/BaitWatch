"""Provisional verdict fusion: READ outcome plus RUN evidence -> VerdictReport.

The thresholds here are provisional until agreed with Manan; the fixed rules
are already binding: any exception, timeout, truncated scan, missing component,
READ incomplete/unavailable or RUN error is at least FLAG, never ALLOW, and any
non-registry sink contact or honeytoken hit is BLOCK. Package-registry lookups
(pypi.org, registry.npmjs.org) are network attempts, not exfiltration: they
FLAG instead of BLOCK. The judge inside READ may escalate but never clears a
high READ score, so fusion sees only the resulting top score.
"""

from dataclasses import dataclass

from run.evidence import NetworkHit, ReadEvidence, RunEvidence, State, VerdictReport

# Provisional until agreed with Manan.
READ_BLOCK_SCORE = 0.9
REGISTRY_HOSTS = ("pypi.org", "registry.npmjs.org")
_REASON_PART_CHARS = 400


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
    # DNS qnames and TLS SNI carry no port or path; HTTP destinations are
    # host[:port]/path. Sinks log IPv4 peers, so bracketed IPv6 is out of scope.
    authority = destination.split("/", 1)[0].rsplit("@", 1)[-1]
    return authority.partition(":")[0].lower().rstrip(".")


def _is_registry_attempt(hit: NetworkHit) -> bool:
    host = _host_of(hit.destination)
    return any(host == known or host.endswith(f".{known}") for known in REGISTRY_HOSTS)


def _bounded(text: str) -> str:
    return text[:_REASON_PART_CHARS]


def fuse(read: ReadOutcome, run: RunEvidence) -> VerdictReport:
    if run.status == "complete" and run.errors:
        run = run.model_copy(update={"status": "error"})
    blockers: list[str] = []
    flags: list[str] = []
    hits = (*run.dns_hits, *run.http_hits, *run.tls_hits)
    exfil = [hit for hit in hits if not _is_registry_attempt(hit)]
    attempts = [hit for hit in hits if _is_registry_attempt(hit)]

    if exfil:
        destinations = ", ".join(dict.fromkeys(hit.destination for hit in exfil))
        message = f"{len(exfil)} sink contact(s) outside the package registries: {destinations}"
        blockers.append(_bounded(message))
    if run.honeytoken_hits:
        tokens = ", ".join(dict.fromkeys(hit.token_id for hit in run.honeytoken_hits))
        blockers.append(_bounded(f"honeytoken hit(s): {tokens}"))
    if (
        read.status is State.COMPLETE
        and read.verdict == "attack"
        and read.max_score >= READ_BLOCK_SCORE
    ):
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
    if not any(
        len(entry.command) == 2 and entry.command[0] == "run_cmd" and entry.exit_code is not None
        for entry in run.tool_log
    ):
        flags.append("RUN decoy did not execute a run_cmd tool call")
    if attempts:
        hosts = ", ".join(dict.fromkeys(_host_of(hit.destination) for hit in attempts))
        flags.append(f"{len(attempts)} package-registry lookup(s) treated as attempts: {hosts}")

    if blockers:
        verdict, why = "BLOCK", blockers
    elif flags:
        verdict, why = "FLAG", flags
    else:
        verdict = "ALLOW"
        why = ["READ is clean and the RUN decoy completed with no sink or honeytoken evidence"]
    return VerdictReport(
        verdict=verdict,
        reason="; ".join(why),
        read=ReadEvidence(status=read.status),
        run=run,
    )
