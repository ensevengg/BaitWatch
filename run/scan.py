"""Scan orchestration: READ over the files, RUN decoy in the cage, fused verdict.

The READ layer is a seam: `run_scan(..., read_scanner=...)` accepts any callable
returning a ReadOutcome, so tests can inject a result where the detector
checkpoint is absent. The default adapter fails closed: a READ that cannot run
is an error outcome, which fusion never allows.
"""

import os
import stat
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from run.evidence import RunError, RunEvidence, State, VerdictReport
from run.sandbox import SandboxConfig, detonate
from run.staging import ENV_TEMPLATES, StagingError, StagingLimits
from run.verdict import ReadOutcome, fuse

ReadScanner = Callable[[Path], ReadOutcome]


def _outcome_from(result, *, skipped_dirs_covered: bool = False) -> ReadOutcome:
    """Map a read.scan ScanResult onto what fusion consumes."""
    reasons = list(result.stats.incomplete_reasons)
    system = [finding for finding in result.findings if finding.layer == "system"]
    flagged = [
        finding for finding in result.findings if finding.layer != "system" and finding.is_flagged
    ]
    if system:
        notes = "; ".join(
            str(finding.evidence.get("note", "READ system failure"))[:200] for finding in system[:5]
        )
        reasons.append(f"{len(system)} READ system failure(s): {notes}")
    coverage_fields = (
        "partial_files",
        "files_truncated",
        "truncated_scan",
        "files_over_cap",
        "chunks_dropped",
        "views_dropped",
        "views_skipped_chunk_budget",
        "decoded_views_uncovered",
    )
    if any(getattr(result.stats, field) for field in coverage_fields):
        reasons.append("partial or truncated READ coverage")
    if result.stats.dirs_skipped and not skipped_dirs_covered:
        reasons.append("READ skipped directories available to RUN or coverage unknown")
    verdict = "attack" if flagged else "incomplete" if system else result.read_verdict
    if reasons and verdict == "clean":
        verdict = "incomplete"
    gaps = len(reasons)
    reasons = "; ".join(reasons)
    return ReadOutcome(
        status=State.ERROR if system else State.COMPLETE,
        verdict=verdict,
        max_score=max((finding.score for finding in flagged), default=0.0),
        reason=f"{gaps} coverage gap(s): {reasons}" if reasons else "",
    )


def _has_unscanned_directory(target: Path, excluded_dirs, limits: StagingLimits) -> bool:
    deadline = time.monotonic() + limits.timeout_seconds
    count = 0

    def visit(directory_fd: int, depth: int) -> bool:
        nonlocal count
        if depth > limits.max_depth:
            raise StagingError("READ coverage check exceeds nesting limit")
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                count += 1
                if count > limits.max_entries or time.monotonic() > deadline:
                    raise StagingError("READ coverage check exceeds entry or time limit")
                if (
                    entry.name in limits.exclude_names
                    or entry.name == ".env"
                    or (entry.name.startswith(".env.") and entry.name not in ENV_TEMPLATES)
                ):
                    continue
                mode = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False).st_mode
                if entry.name in excluded_dirs and (stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                    return True
                if stat.S_ISDIR(mode):
                    child = os.open(
                        entry.name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                    try:
                        if visit(child, depth + 1):
                            return True
                    finally:
                        os.close(child)
        return False

    root = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return visit(root, 0)
    finally:
        os.close(root)


def default_read_scanner(
    path: str | Path, *, staging_limits: StagingLimits | None = None
) -> ReadOutcome:
    """Run the READ layer's scan(); any failure is an error outcome, not a crash."""
    target = Path(path)
    if not target.exists():
        return ReadOutcome(status=State.ERROR, reason=f"READ could not run: no such path: {target}")
    try:
        from read.config import config_from_model_config
        from read.scan import scan

        config = replace(config_from_model_config(), strict_coverage=True)
        result = scan(target, config)
    except Exception as exc:  # noqa: BLE001 - a broken READ must never fail the scan open
        return ReadOutcome(
            status=State.ERROR,
            reason=f"READ could not run: {str(exc)[:300] or type(exc).__name__}",
        )
    try:
        covered = not result.stats.dirs_skipped or not _has_unscanned_directory(
            target, config.walker.excluded_dirs, staging_limits or StagingLimits()
        )
    except Exception as exc:  # noqa: BLE001 - coverage errors must retain known attack scores
        outcome = _outcome_from(result)
        return replace(
            outcome,
            status=State.ERROR,
            reason=f"{outcome.reason}; READ directory coverage check failed: {str(exc)[:300]}",
        )
    return _outcome_from(result, skipped_dirs_covered=covered)


def run_scan(
    repo: str | Path,
    *,
    config: SandboxConfig | None = None,
    backend=None,
    max_steps: int = 20,
    read_scanner: ReadScanner | None = None,
) -> VerdictReport:
    """Scan one repository and return the fused report.

    Without a backend the decoy never runs, so the verdict can only be FLAG or
    BLOCK; `baitwatch scan` requires --llm for the same reason.
    """
    scanner = default_read_scanner if read_scanner is None else read_scanner
    try:
        if read_scanner is None and isinstance(config, SandboxConfig):
            read = default_read_scanner(Path(repo), staging_limits=config.staging)
        else:
            read = scanner(Path(repo))
    except Exception as exc:  # noqa: BLE001 - an injected scanner is untrusted too
        read = ReadOutcome(status=State.ERROR, reason=f"READ scanner failed: {exc}")
    try:
        run = detonate(repo, config=config or SandboxConfig(), backend=backend, max_steps=max_steps)
    except Exception as exc:  # noqa: BLE001 - fail closed over the RUN layer too
        run = RunEvidence(
            errors=[RunError(code="SCAN_ABORTED", message=str(exc)[:1000] or "scan aborted")]
        )
    return fuse(read, run)
