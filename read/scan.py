"""Orchestrator: walk -> decode -> chunk -> detect -> judge -> findings.

Fail-closed rules implemented here (each has a test):

- A file that cannot be read becomes a flagged system finding (configurable,
  default "flag"), never silently skipped.
- If detector inference fails mid-scan, every chunk that never got a score is
  flagged as a system finding; the scan still returns.
- Judge failure (error, timeout, garbage, exhausted budget or spend cap) leaves
  the chunk flagged. Inside the uncertain band the judge CAN clear; above
  flag_threshold nothing the judge says removes the flag.
- A truncated scan (file cap, dropped chunks) is reported in stats so the
  verdict engine can refuse ALLOW on incomplete evidence.

Contract: ``scan(path) -> ScanResult``; iterate it for Finding records in the
order the verdict engine cares about (flagged first, by score desc).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import numpy as np

from read.chunking import Chunk, Chunker
from read.config import ReadConfig, config_from_model_config, resolve_model_path
from read.decoders import (builtin_decoders, load_external_decoders,
                           produce_views)
from read.detector import Detector
from read.findings import (LAYER_JUDGE, LAYER_MODEL, LAYER_SYSTEM,
                           STATUS_FLAGGED, STATUS_REVIEWED, Finding,
                           system_finding)
from read.judge import Judge, ScanBudget
from read.walk import walk

__all__ = ["ScanResult", "scan"]


@dataclass
class ScanStats:
    model_path: str
    files_scanned: int = 0
    files_skipped_binary: int = 0
    dirs_skipped: int = 0
    outside_symlinks: int = 0
    unreadable_files: int = 0
    files_truncated: int = 0        # oversized files scanned as a prefix
    chunks_scored: int = 0
    chunks_dropped: int = 0         # per-file chunk cap hit: unseen text remains
    views_decoded: int = 0
    views_dropped: int = 0          # decoded variants cut by the per-file view cap
    flagged: int = 0
    reviewed: int = 0
    judge_calls: int = 0
    judge_unavailable: int = 0
    elapsed_s: float = 0.0
    truncated_scan: bool = False    # walker file cap hit
    detector_error: str | None = None
    decoder_errors: list[str] = field(default_factory=list)
    thresholds: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return dict(vars(self))


@dataclass
class ScanResult:
    findings: list[Finding]
    stats: ScanStats

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    @property
    def flagged(self) -> list[Finding]:
        return [f for f in self.findings if f.is_flagged]

    @property
    def max_score(self) -> float:
        return max((f.score for f in self.flagged), default=0.0)

    def to_dict(self) -> dict:
        """The JSON the verdict engine consumes."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats.to_dict(),
            # READ-layer opinion only; the verdict engine fuses this with RUN.
            "read_verdict": "attack" if self.flagged else "clean",
        }


def _snippet(text: str, limit: int = 200) -> str:
    one_line = " ".join(text.split())
    return one_line[:limit] + ("…" if len(one_line) > limit else "")


def _read_text(fpath: Path, max_bytes: int, sniff_binary: bool = False) -> tuple[str, bool]:
    """Read up to max_bytes and decode.

    Returns (text, truncated). Encoding: UTF-8 (with BOM) first, then UTF-16
    when a BOM says so, then latin-1 which never fails. Truncation is detected
    by reading one extra byte, so oversized files still get their prefix scanned.
    With ``sniff_binary`` (single-file mode, no walker), a NUL byte rejects the
    file as binary and the result is empty text.
    """
    with open(fpath, "rb") as fh:
        raw = fh.read(max_bytes + 1)
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    if sniff_binary and b"\x00" in raw[:8192]:
        return "", truncated
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        try:
            return raw.decode("utf-16"), truncated
        except UnicodeDecodeError:
            # odd-length truncation or a broken surrogate — degrade, don't crash
            return raw.decode("latin-1"), truncated
    try:
        return raw.decode("utf-8-sig"), truncated
    except UnicodeDecodeError:
        return raw.decode("latin-1"), truncated


def _load_detector(cfg: ReadConfig, cache: dict) -> Detector:
    resolved = str(resolve_model_path(cfg.model_path))
    if resolved not in cache:
        cache[resolved] = Detector(
            resolved,
            batch_size=cfg.batch_size,
            max_length=cfg.max_length,
        )
    return cache[resolved]


def scan(path: str | Path, cfg: ReadConfig | None = None,
         detector: Detector | None = None, judge: Judge | None = None,
         decoders: list | None = None) -> ScanResult:
    """Scan one repository (or any directory / single file) for injections.

    With no explicit config, the pinned thresholds from model_config.json
    apply; an explicitly passed ReadConfig is honored exactly as given.
    """
    started = time.perf_counter()
    if cfg is None:
        cfg = config_from_model_config()
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"scan target does not exist: {target}")

    if decoders is None and cfg.enable_decoders:
        decoders = builtin_decoders()
        try:
            # Search from the BaitWatch repo root only — never from the scan
            # target: a repo must not be able to run code during its own scan.
            decoders.extend(load_external_decoders(
                search_root=Path(__file__).resolve().parents[1]))
        except Exception:   # noqa: BLE001 - a broken decoder module never kills the scan
            pass

    det = detector if detector is not None else _load_detector(cfg, _GLOBAL_CACHE)
    chunker = Chunker(
        det.tokenizer,
        window_tokens=cfg.window_tokens,
        overlap_tokens=cfg.overlap_tokens,
        max_file_tokens=cfg.max_file_tokens,
        max_chunks=cfg.max_chunks_per_file,
    )
    judged = judge if judge is not None else (Judge(cfg.judge) if cfg.judge.enabled else None)
    budget = ScanBudget(cfg.judge.max_calls_per_scan, cfg.judge.max_tokens_per_scan) if judged else None

    walk_result = walk(target, cfg.walker) if target.is_dir() else None
    if walk_result is not None:
        scanned_files = [(f.path, f.rel_path, f.truncated) for f in walk_result.files]
    else:
        scanned_files = [(target, target.name, False)]
    stats = ScanStats(model_path=str(det.model_path), thresholds={
        "flag_threshold": cfg.flag_threshold,
        "review_low": cfg.review_low,
        "hard_high": cfg.hard_high,
    })
    if walk_result is not None:
        stats.files_skipped_binary = len(walk_result.skipped_binary)
        stats.dirs_skipped = len(walk_result.skipped_dirs)
        stats.outside_symlinks = len(walk_result.skipped_outside_symlinks)
        stats.unreadable_files = len(walk_result.unreadable)
        stats.truncated_scan = walk_result.truncated_scan

    findings: list[Finding] = []

    # Pass 1: read text, build decoded views, chunk everything.
    chunks: list[Chunk] = []
    decoder_errors: list[tuple[str, str]] = []
    for fpath, rel, ftrunc in scanned_files:
        stats.files_scanned += 1
        try:
            text, truncated = _read_text(fpath, cfg.walker.max_file_bytes,
                                         sniff_binary=(walk_result is None))
        except OSError as exc:
            if cfg.on_file_error == "skip":
                continue
            findings.append(system_finding(rel, f"unreadable file: {exc}"))
            stats.unreadable_files += 1
            continue
        if walk_result is None and not text:
            stats.files_skipped_binary += 1     # single-file NUL sniff rejection
            continue
        ftrunc = ftrunc or truncated
        if ftrunc:
            stats.files_truncated += 1
        views = produce_views(text, decoders, errors=decoder_errors)
        if len(views) > cfg.max_views_per_file:
            stats.views_dropped += len(views) - cfg.max_views_per_file
            views = views[:cfg.max_views_per_file]
        stats.views_decoded += len(views) - 1
        next_id = 0
        for view in views:
            file_chunks, dropped = chunker.chunk(
                view.text, rel, view=view.decoder or "original", first_chunk_id=next_id)
            chunks.extend(file_chunks)
            next_id += len(file_chunks)
            stats.chunks_dropped += dropped
    stats.decoder_errors = [f"{name}: {msg}" for name, msg in decoder_errors]

    # Pass 2: one batched GPU pass over all chunks.
    scores: np.ndarray | None = None
    if chunks:
        try:
            scores = det.scores([c.text for c in chunks])
            if len(scores) != len(chunks):
                raise RuntimeError(
                    f"detector returned {len(scores)} scores for {len(chunks)} chunks")
            if not np.isfinite(scores).all():
                stats.detector_error = "non-finite score(s) from detector"
                scores = None
        except Exception as exc:   # noqa: BLE001 - fail closed on any inference error
            stats.detector_error = str(exc)
            scores = None

    # Pass 3: banding + judge.
    if scores is not None:
        stats.chunks_scored = len(chunks)
        for chunk, score in zip(chunks, scores):
            score = float(score)
            evidence = {
                "text": _snippet(chunk.text),
                "line": chunk.start_line,
                "model_score": round(score, 4),
            }

            if score >= cfg.flag_threshold:
                findings.append(Finding(
                    file=chunk.file, chunk_id=chunk.chunk_id, score=score,
                    layer=LAYER_MODEL,
                    evidence=evidence,
                    status=STATUS_FLAGGED,
                    decoded=chunk.view != "original",
                    decoder=chunk.view if chunk.view != "original" else None,
                ))
            elif score >= cfg.review_low and judged is not None:
                result = judged.review(chunk.text, chunk.file, score, budget)
                stats.judge_calls += 1
                if result.verdict == "attack":
                    sev = result.severity if result.severity is not None else score
                    findings.append(Finding(
                        file=chunk.file, chunk_id=chunk.chunk_id,
                        score=max(score, sev), layer=LAYER_JUDGE,
                        evidence=evidence, status=STATUS_FLAGGED,
                        explanation=result.explanation,
                        decoded=chunk.view != "original",
                        decoder=chunk.view if chunk.view != "original" else None,
                    ))
                elif result.verdict == "benign":
                    findings.append(Finding(
                        file=chunk.file, chunk_id=chunk.chunk_id, score=score,
                        layer=LAYER_MODEL, evidence=evidence,
                        status=STATUS_REVIEWED,
                        explanation=result.explanation,
                        decoded=chunk.view != "original",
                        decoder=chunk.view if chunk.view != "original" else None,
                    ))
                else:
                    stats.judge_unavailable += 1
                    findings.append(system_finding(
                        chunk.file,
                        f"judge unavailable, fail-closed: {result.error}",
                        chunk_id=chunk.chunk_id,
                    ))
            elif score >= cfg.review_low:
                # No judge configured (CI / quick inline mode): the uncertain
                # band must still surface, as reviewed-not-flagged, so nothing
                # silently disappears and the ASK tier can act on it.
                findings.append(Finding(
                    file=chunk.file, chunk_id=chunk.chunk_id, score=score,
                    layer=LAYER_MODEL, evidence=evidence,
                    status=STATUS_REVIEWED,
                    decoded=chunk.view != "original",
                    decoder=chunk.view if chunk.view != "original" else None,
                ))
            # else: below review band, genuinely clean — no finding.

        # Flagged chunks still owed an explanation get judged last, by score.
        if judged is not None:
            unexplained = [f for f in findings
                           if f.is_flagged and f.layer == LAYER_MODEL and f.explanation is None]
            unexplained.sort(key=lambda f: f.score, reverse=True)
            if unexplained:
                by_key = {(c.file, c.chunk_id): c for c in chunks}
                for f in unexplained:
                    if budget is not None and not budget.can_call():
                        break
                    chunk = by_key[(f.file, f.chunk_id)]
                    result = judged.review(chunk.text, chunk.file, f.score, budget)
                    stats.judge_calls += 1
                    if result.verdict == "attack":
                        if result.severity is not None and result.severity > f.score:
                            f.score = result.severity
                            f.layer = LAYER_JUDGE
                        f.explanation = result.explanation or f.explanation
                    elif result.verdict == "benign":
                        # Escalate-only: the judge never clears a model flag,
                        # however confident. It records its dissent instead.
                        f.explanation = (
                            f"Judge assessed this as benign, flag kept "
                            f"(model score {f.score:.2f}): "
                            + (result.explanation or "no explanation given")
                        )
                    else:
                        stats.judge_unavailable += 1
                        f.explanation = None

    elif chunks:   # detector failed: fail closed over everything we could not score
        for chunk in chunks:
            findings.append(system_finding(
                chunk.file, "detector inference failed, fail-closed",
                chunk_id=chunk.chunk_id))

    if walk_result is not None and cfg.on_file_error == "flag":
        # lstat-level failures never reached the read loop; flag them too.
        findings.extend(system_finding(rel, f"unreadable file: {reason}")
                        for rel, reason in walk_result.unreadable)

    stats.flagged = sum(1 for f in findings if f.is_flagged)
    stats.reviewed = sum(1 for f in findings if f.status == STATUS_REVIEWED)
    stats.elapsed_s = round(time.perf_counter() - started, 3)
    findings.sort(key=lambda f: (not f.is_flagged, -f.score))
    return ScanResult(findings=findings, stats=stats)


# One process, one warm model: repeated scan() calls reuse it (hook/daemon path).
_GLOBAL_CACHE: dict = {}


if __name__ == "__main__":
    # Roadmap D2 gate entry point: python -m read.scan attacks/examples/
    from read.cli import main
    raise SystemExit(main())
