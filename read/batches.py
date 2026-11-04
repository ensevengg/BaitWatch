"""Scan a repository one batch of files after another, keeping the work done.

Files an agent reaches first go first: agent-facing files, then docs and scripts,
then source. Generated files are left for the check on open. Each batch saves its
scores, verdicts and per-file results, so a scan that runs out of time resumes where
it stopped, and a later scan only reads the files that changed. Once ``stop_score``
is reached the verdict is decided and the remaining batches are skipped.

Gaps that belong to the whole repository are worked out here on every scan, so a
scan answered entirely from saved results still reports them, and a scan that ran
out of time says what it did not reach.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import time
from collections.abc import Callable
from pathlib import Path

from read.cache import FileResultCache
from read.config import ReadConfig, resolve_model_path
from read.findings import LAYER_MODEL, LAYER_SYSTEM, STATUS_REVIEWED, Finding, system_finding
from read.judge import JUDGE_SYSTEM_PROMPT
from read.scan import ScanResult, ScanStats, is_broken_symlink, scan
from read.tiers import is_generated, priority_tier
from read.walk import ScannedFile, walk

BYTES_PER_CHUNK = 1_500         # measured across public repositories
CHUNKS_PER_BATCH = 1_500        # about 15 s of model time on the demo GPU
MAX_LOW_SCORE_CALLS = 150       # low-score tier 2/3 windows judged per scan


def plan_batches(files: list[ScannedFile]) -> list[list[ScannedFile]]:
    """Tier 0 and 1 together, then tier 2 and tier 3 in pieces of about equal work."""
    batches: list[list[ScannedFile]] = []
    first = [f for f in files if priority_tier(f.rel_path) <= 1]
    if first:
        batches.append(first)
    for tier in (2, 3):
        current: list[ScannedFile] = []
        chunks = 0
        for f in (f for f in files if priority_tier(f.rel_path) == tier):
            current.append(f)
            chunks += max(1, f.read_bytes // BYTES_PER_CHUNK)
            if chunks >= CHUNKS_PER_BATCH:
                batches.append(current)
                current, chunks = [], 0
        if current:
            batches.append(current)
    return batches


def _digest(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while block := handle.read(1024 * 1024):
                digest.update(block)
    except OSError:
        return None
    return digest.hexdigest()


def result_salt(cfg: ReadConfig) -> str:
    """Everything in ``cfg`` that changes a file's result, so a saved one is never
    reused under other settings. Budgets and time limits are left out: a file whose
    work they cut short is not saved at all."""
    settings = dataclasses.asdict(cfg)
    settings.pop("model_path", None)
    judge = settings.pop("judge")
    wanted = {
        "enabled": judge["enabled"],
        "max_chunk_chars": judge["max_chunk_chars"],
        "max_windows_per_file": judge["max_windows_per_file"],
        "max_windows_per_agent_file": judge["max_windows_per_agent_file"],
        "max_whole_file_pieces": judge["max_whole_file_pieces"],
        "endpoints": [
            {key: endpoint.get(key) for key in ("model", "base_url", "reasoning_effort")}
            for endpoint in judge["endpoints"] or ()
        ],
        "prompt": JUDGE_SYSTEM_PROMPT,
    }
    return hashlib.sha256(
        json.dumps([settings, wanted], sort_keys=True, default=str).encode()
    ).hexdigest()[:16]


def _finding_from_dict(row: dict) -> Finding:
    return Finding(file=row["file"], chunk_id=row["chunk_id"], score=row["score"],
                   layer=row["layer"], evidence=row["evidence"], status=row["status"],
                   explanation=row.get("explanation"), decoded=row.get("decoded", False),
                   decoder=row.get("decoder"))


def is_confirmed(finding: Finding) -> bool:
    return finding.layer != LAYER_MODEL or bool(finding.evidence.get("judge_confirmed"))


def aimed_at_the_agent(finding: Finding) -> bool:
    """A verdict saved by an older version has no addressee, and counts as aimed at it."""
    return finding.evidence.get("judge_addressee", "reading_agent") == "reading_agent"


def is_two_signal(finding: Finding, min_model_score: float) -> bool:
    """The judge confirmed a window the model also scored high.

    All 17 attack repositories we test against have one. The judge alone mostly
    reacts to ordinary install instructions that the model scores near zero.
    """
    if finding.layer == LAYER_SYSTEM:
        return True
    return is_confirmed(finding) and finding.evidence.get("model_score", 0.0) >= min_model_score


def decides_block(finding: Finding, stop_score: float, flag_threshold: float) -> bool:
    """Enough to stop reading: the judge confirms a window the model flagged by itself, in
    a file an agent reaches first. A weaker model score asks, so reading goes on."""
    return (finding.is_flagged and finding.score >= stop_score
            and is_two_signal(finding, flag_threshold)
            and (finding.layer == LAYER_SYSTEM or aimed_at_the_agent(finding))
            and (finding.layer == LAYER_SYSTEM or priority_tier(finding.file) <= 1))


def _merge(into: ScanStats, part: ScanStats) -> None:
    once = {"model_path", "thresholds", "files_over_cap", "agent_files_over_cap",
            "truncated_scan", "dirs_skipped", "outside_symlinks", "files_skipped_binary",
            "best_effort_gaps", "unreadable_files"}
    for f in dataclasses.fields(ScanStats):
        if f.name in once:
            continue
        have, new = getattr(into, f.name), getattr(part, f.name)
        if isinstance(have, bool):
            setattr(into, f.name, have or new)
        elif isinstance(have, (int, float)):
            setattr(into, f.name, have + new)
        elif isinstance(have, list):
            have.extend(x for x in new if f.name != "incomplete_reasons" or x not in have)
        elif have is None and new is not None:
            setattr(into, f.name, new)


def _add_repository_gaps(stats: ScanStats, walked, cfg: ReadConfig, scannable: int) -> None:
    """What this scan left out, whether or not any file had to be read again."""
    gaps: list[str] = []
    if cfg.bulk_best_effort:
        if walked.agent_files_over_cap:
            gaps.append(f"file cap: {walked.agent_files_over_cap} agent-facing file(s) beyond "
                        f"max_files={cfg.walker.max_files} not scanned")
    elif walked.truncated_scan:
        gaps.append(f"file cap: {walked.files_over_cap} file(s) beyond "
                    f"max_files={cfg.walker.max_files} not scanned")
    if stats.scan_time_limit_hit:
        missing = scannable - len(set(stats.files_covered))
        gaps.append(f"scan time limit: up to {missing} file(s) not reached yet; "
                    "submitting the prompt again continues from there")
    stats.incomplete_reasons.extend(x for x in gaps if x not in stats.incomplete_reasons)


def scan_in_batches(target: str | Path, cfg: ReadConfig, *, detector=None, judge=None,
                    decoders: list | None = None, store: FileResultCache | None = None,
                    store_salt: str = "", time_limit_s: float | None = None,
                    stop_score: float | None = None,
                    trusted: Callable[[str], bool] | None = None) -> ScanResult:
    """``trusted``: files the person accepted as they are. Their findings are dropped
    and cannot end the scan early, so the rest of the repository is still read."""
    started = time.perf_counter()
    target = Path(target)
    walked = walk(target, cfg.walker)
    generated = [f for f in walked.files
                 if priority_tier(f.rel_path) >= 2 and is_generated(f.rel_path)]
    skipped = {f.rel_path for f in generated}
    scannable = [f for f in walked.files if f.rel_path not in skipped]
    stats = ScanStats(
        model_path=str(detector.model_path) if detector is not None else str(resolve_model_path(cfg.model_path)),
        thresholds={"flag_threshold": cfg.flag_threshold, "review_low": cfg.review_low,
                    "hard_high": cfg.hard_high},
        files_generated=len(generated),
        files_over_cap=walked.files_over_cap,
        agent_files_over_cap=walked.agent_files_over_cap,
        truncated_scan=walked.truncated_scan,
        dirs_skipped=len(walked.skipped_dirs),
        outside_symlinks=len(walked.skipped_outside_symlinks),
        files_skipped_binary=len(walked.skipped_binary),
        unreadable_files=len(walked.unreadable),
    )
    findings: list[Finding] = []
    low_left = MAX_LOW_SCORE_CALLS
    decided = False
    store_salt = f"{store_salt}|{result_salt(cfg)}"
    trusted = trusted or (lambda rel: False)

    def left() -> float | None:
        return None if time_limit_s is None else time_limit_s - (time.perf_counter() - started)

    for batch in plan_batches(scannable):
        keys: dict[str, str] = {}
        todo: set[str] = set()
        for f in batch:
            digest = _digest(f.path) if store is not None else None
            stored = None
            if digest is not None:
                keys[f.rel_path] = f"{store_salt}\0{f.rel_path}\0{digest}"
                stored = store.get(keys[f.rel_path])
            if stored is None:
                todo.add(f.rel_path)
                continue
            findings.extend(_finding_from_dict(row) for row in stored)
            stats.files_covered.append(f.rel_path)
            stats.files_cached += 1
            if stop_score is not None and not trusted(f.rel_path) and any(
                    decides_block(_finding_from_dict(row), stop_score, cfg.flag_threshold)
                    for row in stored):
                decided = True
        if decided:
            break
        if not todo:
            continue
        remaining = left()
        if remaining is not None and remaining <= 0:
            stats.scan_time_limit_hit = True
            break
        tier_two_plus = priority_tier(batch[0].rel_path) >= 2
        judge_cfg = dataclasses.replace(
            cfg.judge,
            deadline_s=remaining if remaining is not None else cfg.judge.deadline_s,
            max_bulk_calls_per_scan=low_left if tier_two_plus else None,
        )
        part = scan(target, dataclasses.replace(cfg, judge=judge_cfg), detector=detector,
                    judge=judge, decoders=decoders, only_files=todo, walked=walked)
        low_left = max(0, low_left - part.stats.judge_low_planned)
        findings.extend(part.findings)
        _merge(stats, part.stats)
        clean_run = not (part.stats.judge_unavailable or part.stats.judge_deadline_hit
                         or part.stats.detector_error)
        if store is not None and clean_run:
            for rel in part.stats.files_covered:
                if rel in keys:
                    rows = [x.to_dict() for x in part.findings if x.file == rel]
                    if not any(row["evidence"].get("note") for row in rows):
                        store.put(keys[rel], rows)
        if stop_score is not None and any(
                decides_block(x, stop_score, cfg.flag_threshold) and not trusted(x.file)
                for x in part.findings):
            decided = True
            break

    stats.scan_stopped_early = decided
    if cfg.on_file_error == "flag":
        findings.extend(system_finding(rel, f"unreadable file: {reason}")
                        for rel, reason in walked.unreadable
                        if not (cfg.bulk_best_effort and is_broken_symlink(reason)))
    _add_repository_gaps(stats, walked, cfg, len(scannable))
    unique: dict[tuple, Finding] = {}
    for x in findings:
        if x.layer != LAYER_SYSTEM and trusted(x.file):
            continue
        unique.setdefault((x.file, x.chunk_id, x.layer, x.status, x.score), x)
    merged = sorted(unique.values(), key=lambda x: (not x.is_flagged, -x.score))
    stats.flagged = sum(1 for x in merged if x.is_flagged)
    stats.reviewed = sum(1 for x in merged if x.status == STATUS_REVIEWED)
    stats.best_effort_gaps = (len(walked.files) + walked.files_over_cap - len(stats.files_covered))
    stats.elapsed_s = round(time.perf_counter() - started, 3)
    return ScanResult(findings=merged, stats=stats)
