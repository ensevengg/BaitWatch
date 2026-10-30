"""Scan orchestration: READ over the files, RUN decoy in the cage, fused verdict.

The READ layer is a seam: `run_scan(..., read_scanner=...)` accepts any callable
returning a ReadOutcome, so tests can inject a result where the detector
checkpoint is absent. The default adapter fails closed: a READ that cannot run
is an error outcome, which fusion never allows.
"""

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from run.evidence import RunError, RunEvidence, State, VerdictReport
from run.sandbox import SandboxConfig, detonate
from run.verdict import ReadOutcome, fuse

ReadScanner = Callable[[Path], ReadOutcome]


def _outcome_from(result) -> ReadOutcome:
    """Map a read.scan ScanResult onto what fusion consumes."""
    reasons = list(result.stats.incomplete_reasons)
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
    verdict = result.read_verdict
    if reasons and verdict == "clean":
        verdict = "incomplete"
    gaps = len(reasons)
    reasons = "; ".join(reasons)
    return ReadOutcome(
        status=State.COMPLETE,
        verdict=verdict,
        max_score=result.max_score,
        reason=f"{gaps} coverage gap(s): {reasons}" if reasons else "",
    )


def default_read_scanner(path: str | Path) -> ReadOutcome:
    """Run the READ layer's scan(); any failure is an error outcome, not a crash."""
    target = Path(path)
    if not target.exists():
        return ReadOutcome(status=State.ERROR, reason=f"READ could not run: no such path: {target}")
    try:
        from read.config import config_from_model_config
        from read.scan import scan

        result = scan(target, replace(config_from_model_config(), strict_coverage=True))
    except Exception as exc:  # noqa: BLE001 - a broken READ must never fail the scan open
        return ReadOutcome(
            status=State.ERROR,
            reason=f"READ could not run: {str(exc)[:300] or type(exc).__name__}",
        )
    return _outcome_from(result)


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
