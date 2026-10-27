"""Orchestrator: walk -> decode -> chunk -> detect -> judge -> findings.

Fail-closed rules implemented here (each has a test):

- A file that cannot be read becomes a flagged system finding (configurable,
  default "flag"), never silently skipped.
- If detector inference fails mid-scan, every chunk that never got a score is
  flagged as a system finding; the scan still returns.
- Judge failure (error, timeout, garbage, spend cap) leaves the chunk flagged.
  Inside the uncertain band the judge CAN clear; above flag_threshold
  nothing the judge says removes the flag.
- Evidence the scan could not cover — walker file cap, decoded content past
  its cap, review-band chunks the judge budget could not reach, decoder
  crashes, and (with ``strict_coverage``) the unscanned middle of oversized
  files — makes the READ verdict "incomplete", never "clean".

Contract: ``scan(path) -> ScanResult``; iterate it for Finding records in the
order the verdict engine cares about (flagged first, by score desc).
"""

from __future__ import annotations

import math
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import numpy as np

from read.cache import DEFAULT_CACHE_PATH, ScoreCache, model_identity
from read.chunking import Chunk, Chunker
from read.config import ReadConfig, config_from_model_config, resolve_model_path
from read.decoders import (builtin_decoders, load_external_decoders,
                           mask_blobs, produce_views)
from read.detector import Detector
from read.findings import (LAYER_JUDGE, LAYER_MODEL, LAYER_SYSTEM,
                           STATUS_FLAGGED, STATUS_REVIEWED, Finding,
                           system_finding)
from read.judge import Judge, JudgeResult, ScanBudget
from read.walk import sniff_encoding, walk

__all__ = ["ScanResult", "scan", "VERDICT_ATTACK", "VERDICT_INCOMPLETE", "VERDICT_CLEAN"]

VERDICT_ATTACK = "attack"
VERDICT_INCOMPLETE = "incomplete"
VERDICT_CLEAN = "clean"


@dataclass
class ScanStats:
    model_path: str
    files_scanned: int = 0
    files_skipped_binary: int = 0
    dirs_skipped: int = 0
    outside_symlinks: int = 0
    unreadable_files: int = 0
    files_truncated: int = 0        # oversized files: head + tail scanned, middle not
    partial_files: int = 0          # files with any unscanned span (byte or chunk caps)
    chunks_scored: int = 0
    chunks_unique: int = 0          # distinct chunk texts
    chunks_cached: int = 0          # distinct chunk texts served by the score cache
    chunks_dropped: int = 0         # windows skipped by per-file caps (approx.)
    views_decoded: int = 0
    views_dropped: int = 0          # decoded views/segments cut by caps
    flagged: int = 0
    reviewed: int = 0
    judge_calls: int = 0            # judge requests actually attempted
    judge_unavailable: int = 0
    judge_skipped: int = 0          # review-band chunks the per-scan budget did not cover
    elapsed_s: float = 0.0
    truncated_scan: bool = False    # walker file cap hit
    files_over_cap: int = 0         # files the walker cap left unscanned
    detector_error: str | None = None
    decoder_errors: list[str] = field(default_factory=list)
    incomplete_reasons: list[str] = field(default_factory=list)
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

    @property
    def read_verdict(self) -> str:
        """attack > incomplete > clean. Incomplete evidence is never clean."""
        if self.flagged:
            return VERDICT_ATTACK
        if self.stats.incomplete_reasons:
            return VERDICT_INCOMPLETE
        return VERDICT_CLEAN

    def to_dict(self) -> dict:
        """The JSON the verdict engine consumes."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats.to_dict(),
            # READ-layer opinion only; the verdict engine fuses this with RUN.
            "read_verdict": self.read_verdict,
        }


def _snippet(text: str, limit: int = 200) -> str:
    one_line = " ".join(text.split())
    return one_line[:limit] + ("…" if len(one_line) > limit else "")


@dataclass
class FileText:
    text: str                       # head (or the whole file)
    truncated: bool                 # bytes between head and tail were not read
    tail: str = ""                  # last bytes of an oversized file
    tail_line_offset: int | None = None   # newlines before the tail, if counted


_LINE_COUNT_LIMIT = 64 << 20        # count lines before a tail only up to 64 MB


def _decode(raw: bytes, encoding: str, more_follows: bool) -> str:
    """Decode with the sniffed encoding; never raises.

    UTF-8 cut mid-character by the byte cap loses only that character; a file
    that is not valid UTF-8 keeps every valid character (errors="replace")
    instead of turning the whole file into latin-1 mojibake.
    """
    if encoding in ("utf-16", "utf-16-le", "utf-16-be"):
        return raw[: len(raw) // 2 * 2].decode(encoding, errors="replace")
    if encoding == "utf-32":
        return raw[: len(raw) // 4 * 4].decode(encoding, errors="replace")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        if more_follows and exc.start >= len(raw) - 3:
            return raw[: exc.start].decode("utf-8-sig", errors="replace")
        return raw.decode("utf-8-sig", errors="replace")


def _tail_encoding(encoding: str, head: bytes) -> str:
    if encoding == "utf-16":
        return "utf-16-le" if head.startswith(b"\xff\xfe") else "utf-16-be"
    if encoding == "utf-32":
        return "utf-32-le" if head.startswith(b"\xff\xfe\x00\x00") else "utf-32-be"
    return encoding


def _read_file(fpath: Path, max_bytes: int, tail_bytes: int,
               encoding: str | None = None) -> FileText | None:
    """Head (``max_bytes``) + tail (``tail_bytes``) of a file, decoded.

    ``encoding=None`` sniffs it (single-file mode); None is returned for
    binary content. A file that fits head + tail is read whole.
    """
    with open(fpath, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        whole = size <= max_bytes + tail_bytes
        raw = fh.read(size if whole else max_bytes)
        if encoding is None:
            encoding = sniff_encoding(raw[:8192])
            if encoding is None:
                return None
        if whole:
            return FileText(_decode(raw, encoding, more_follows=False), truncated=False)
        head = _decode(raw, encoding, more_follows=True)
        unit = 4 if encoding == "utf-32" else 2 if encoding.startswith("utf-16") else 1
        start = size - tail_bytes
        start += (-start) % unit
        fh.seek(start)
        traw = fh.read(tail_bytes)
        tenc = _tail_encoding(encoding, raw)
        if tenc == "utf-8":
            while traw and (traw[0] & 0xC0) == 0x80:     # resync mid-character
                traw = traw[1:]
        tail = _decode(traw, tenc, more_follows=False)
        offset = None
        if unit == 1 and size <= _LINE_COUNT_LIMIT:
            fh.seek(0)
            remaining, offset = start, 0
            while remaining > 0:
                block = fh.read(min(1 << 20, remaining))
                if not block:
                    break
                offset += block.count(b"\n")
                remaining -= len(block)
    return FileText(head, truncated=True, tail=tail, tail_line_offset=offset)


def _load_detector(cfg: ReadConfig, cache: dict) -> Detector:
    resolved = str(resolve_model_path(cfg.model_path))
    if resolved not in cache:
        cache[resolved] = Detector(
            resolved,
            batch_size=cfg.batch_size,
            max_length=cfg.max_length,
        )
    return cache[resolved]


def _score_cache(cfg: ReadConfig, det, cache: dict) -> ScoreCache | None:
    path = Path(cfg.score_cache_path or DEFAULT_CACHE_PATH)
    ident = model_identity(str(det.model_path), str(getattr(det, "device", "?")),
                           str(getattr(det, "dtype", "?")))
    key = ("score_cache", str(path), ident)
    if key not in cache:
        cache[key] = ScoreCache(path, ident)
    sc = cache[key]
    return sc if sc.enabled else None


def _judge_all(judge, items: list[tuple[str, str, float]], budget: ScanBudget | None,
               concurrency: int, stats: ScanStats) -> list[JudgeResult]:
    """Judge (text, file, score) items in the given priority order.

    Identical texts are judged once. The budget is reserved *sequentially in
    priority order* before any call starts, so when it runs out the
    lowest-priority items are the ones skipped; the reserved calls then run
    ``concurrency`` at a time. Judges without ``estimate_tokens`` (test
    doubles) are called one by one in order instead.
    """
    index: dict[str, int] = {}
    requests: list[tuple[str, str, float]] = []
    for text, file, score in items:
        if text not in index:
            index[text] = len(requests)
            requests.append((text, file, score))

    def crashed(exc: Exception) -> JudgeResult:
        return JudgeResult("unavailable", None, None, error=f"judge crashed: {exc}")

    results: list[JudgeResult | None] = [None] * len(requests)
    estimate = getattr(judge, "estimate_tokens", None)
    if estimate is None or concurrency <= 1:
        for i, (text, file, score) in enumerate(requests):
            try:
                results[i] = judge.review(text, file, score, budget)
            except Exception as exc:   # noqa: BLE001 - a judge bug is a failure, not a crash
                results[i] = crashed(exc)
    else:
        planned: list[tuple[int, int | None]] = []
        for i, (text, file, score) in enumerate(requests):
            try:
                est = estimate(text, file, score)
            except Exception as exc:   # noqa: BLE001
                results[i] = crashed(exc)
                continue
            if budget is None:
                planned.append((i, None))
            elif budget.reserve(est):
                planned.append((i, est))
            else:
                results[i] = JudgeResult("skipped", None, None, error="judge budget exhausted")

        def run(plan: tuple[int, int | None]) -> JudgeResult:
            i, est = plan
            text, file, score = requests[i]
            try:
                return judge.review(text, file, score, budget, reserved=est)
            except Exception as exc:   # noqa: BLE001
                if budget is not None and est is not None:
                    budget.settle(est, None)
                return crashed(exc)

        if planned:
            with ThreadPoolExecutor(max_workers=min(concurrency, len(planned))) as pool:
                for (i, _), result in zip(planned, pool.map(run, planned)):
                    results[i] = result
    stats.judge_calls += sum(1 for r in results if r.verdict != "skipped")
    return [results[index[text]] for text, _, _ in items]


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

    decoder_errors: list[tuple[str, str]] = []
    if decoders is None and cfg.enable_decoders:
        decoders = builtin_decoders()
        try:
            # Search from the BaitWatch repo root only — never from the scan
            # target: a repo must not be able to run code during its own scan.
            decoders.extend(load_external_decoders(
                search_root=Path(__file__).resolve().parents[1]))
        except Exception as exc:   # noqa: BLE001 - a broken plugin never kills the scan
            decoder_errors.append(("external", f"decoder plugin failed to load: {exc}"))

    det = detector if detector is not None else _load_detector(cfg, _GLOBAL_CACHE)
    # Injected detectors (tests, harnesses) never touch the persistent cache.
    score_cache = (_score_cache(cfg, det, _GLOBAL_CACHE)
                   if detector is None and cfg.score_cache else None)
    chunker = Chunker(
        det.tokenizer,
        window_tokens=cfg.window_tokens,
        overlap_tokens=cfg.overlap_tokens,
        max_file_tokens=cfg.max_file_tokens,
        max_chunks=cfg.max_chunks_per_file,
        tail_windows=cfg.tail_windows,
    )
    stride = cfg.window_tokens - cfg.overlap_tokens
    judged = judge if judge is not None else (Judge(cfg.judge) if cfg.judge.enabled else None)
    budget = ScanBudget(cfg.judge.max_calls_per_scan, cfg.judge.max_tokens_per_scan) if judged else None

    walk_result = walk(target, cfg.walker) if target.is_dir() else None
    if walk_result is not None:
        scanned_files = [(f.path, f.rel_path, f.encoding) for f in walk_result.files]
    else:
        scanned_files = [(target, target.name, None)]
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
        stats.files_over_cap = walk_result.files_over_cap

    findings: list[Finding] = []

    # Pass 1: read text (head + tail), build decoded views, mask blobs, chunk.
    chunks: list[Chunk] = []
    for fpath, rel, encoding in scanned_files:
        try:
            ft = _read_file(fpath, cfg.walker.max_file_bytes, cfg.tail_bytes, encoding)
        except OSError as exc:
            if cfg.on_file_error == "skip":
                continue
            findings.append(system_finding(rel, f"unreadable file: {exc}"))
            stats.unreadable_files += 1
            continue
        if ft is None:
            stats.files_skipped_binary += 1     # single-file binary sniff rejection
            continue
        stats.files_scanned += 1
        partial = ft.truncated
        if ft.truncated:
            stats.files_truncated += 1
        segments = [(ft.text, 0)]
        if ft.tail:
            segments.append((ft.tail, ft.tail_line_offset))
        next_id = 0
        for seg_text, line_offset in segments:
            overflow: list[int] = []
            views = produce_views(seg_text, decoders, errors=decoder_errors,
                                  overflow=overflow)
            if overflow:
                stats.views_dropped += sum(overflow)
                partial = True
            if len(views) > cfg.max_views_per_file:
                stats.views_dropped += len(views) - cfg.max_views_per_file
                views = views[:cfg.max_views_per_file]
                partial = True
            stats.views_decoded += len(views) - 1
            for view in views:
                text = mask_blobs(view.text) if cfg.mask_blobs else view.text
                # Decoded text has no position in the file: no line number.
                file_chunks, uncovered = chunker.chunk(
                    text, rel, view=view.decoder or "original", first_chunk_id=next_id,
                    line_offset=line_offset if view.decoder is None else None)
                chunks.extend(file_chunks)
                next_id += len(file_chunks)
                if uncovered:
                    partial = True
                    stats.chunks_dropped += max(1, math.ceil(uncovered / stride))
        if partial:
            stats.partial_files += 1
    stats.decoder_errors = [f"{name}: {msg}" for name, msg in decoder_errors]

    # Pass 2: one batched GPU pass over the distinct chunk texts.
    scores: np.ndarray | None = None
    if chunks:
        index: dict[str, int] = {}
        unique: list[str] = []
        for c in chunks:
            if c.text not in index:
                index[c.text] = len(unique)
                unique.append(c.text)
        stats.chunks_unique = len(unique)
        cached = score_cache.get_many(unique) if score_cache is not None else {}
        stats.chunks_cached = len(cached)
        todo = [t for t in unique if t not in cached]
        try:
            fresh = np.asarray(det.scores(todo), dtype=np.float32) if todo else \
                np.empty(0, dtype=np.float32)
            if len(fresh) != len(todo):
                raise RuntimeError(
                    f"detector returned {len(fresh)} scores for {len(todo)} chunks")
            if not np.isfinite(fresh).all():
                stats.detector_error = "non-finite score(s) from detector"
            else:
                new = dict(zip(todo, (float(x) for x in fresh)))
                if score_cache is not None:
                    score_cache.put_many(new)
                new.update(cached)
                u_scores = np.asarray([new[t] for t in unique], dtype=np.float32)
                scores = u_scores[[index[c.text] for c in chunks]]
        except Exception as exc:   # noqa: BLE001 - fail closed on any inference error
            stats.detector_error = str(exc)
            scores = None

    # Pass 3: banding + judge.
    if scores is not None:
        stats.chunks_scored = len(chunks)
        band: list[tuple[Chunk, float, dict]] = []
        for chunk, score in zip(chunks, scores):
            score = float(score)
            evidence = {
                "text": _snippet(chunk.text),
                "line": chunk.start_line,
                "model_score": round(score, 4),
            }
            decoded = chunk.view != "original"
            decoder = chunk.view if decoded else None
            if score >= cfg.flag_threshold:
                findings.append(Finding(
                    file=chunk.file, chunk_id=chunk.chunk_id, score=score,
                    layer=LAYER_MODEL, evidence=evidence, status=STATUS_FLAGGED,
                    decoded=decoded, decoder=decoder,
                ))
            elif score >= cfg.review_low and judged is not None:
                band.append((chunk, score, evidence))
            elif score >= cfg.review_low:
                # No judge configured (CI / explicit --no-judge): the uncertain
                # band still surfaces, as reviewed-not-flagged, so nothing
                # silently disappears and the ASK tier can act on it.
                findings.append(Finding(
                    file=chunk.file, chunk_id=chunk.chunk_id, score=score,
                    layer=LAYER_MODEL, evidence=evidence, status=STATUS_REVIEWED,
                    decoded=decoded, decoder=decoder,
                ))
            # else: below review band, genuinely clean — no finding.

        if band:
            # Highest scores first: if the budget runs out, the least
            # suspicious chunks are the ones left unjudged.
            band.sort(key=lambda item: -item[1])
            results = _judge_all(judged, [(c.text, c.file, s) for c, s, _ in band],
                                 budget, cfg.judge.concurrency, stats)
            for (chunk, score, evidence), result in zip(band, results):
                decoded = chunk.view != "original"
                decoder = chunk.view if decoded else None
                if result.verdict == "attack":
                    sev = result.severity if result.severity is not None else score
                    findings.append(Finding(
                        file=chunk.file, chunk_id=chunk.chunk_id,
                        score=max(score, sev), layer=LAYER_JUDGE,
                        evidence=evidence, status=STATUS_FLAGGED,
                        explanation=result.explanation,
                        decoded=decoded, decoder=decoder,
                    ))
                elif result.verdict in ("benign", "skipped"):
                    if result.verdict == "skipped":
                        stats.judge_skipped += 1
                        evidence = {**evidence,
                                    "note": "not judged: per-scan judge budget exhausted"}
                    findings.append(Finding(
                        file=chunk.file, chunk_id=chunk.chunk_id, score=score,
                        layer=LAYER_MODEL, evidence=evidence, status=STATUS_REVIEWED,
                        explanation=result.explanation,
                        decoded=decoded, decoder=decoder,
                    ))
                else:
                    stats.judge_unavailable += 1
                    findings.append(system_finding(
                        chunk.file,
                        f"judge unavailable, fail-closed: {result.error}",
                        chunk_id=chunk.chunk_id,
                    ))

        # Flagged chunks still owed an explanation get judged last, by score.
        if judged is not None:
            unexplained = [f for f in findings
                           if f.is_flagged and f.layer == LAYER_MODEL and f.explanation is None]
            unexplained.sort(key=lambda f: f.score, reverse=True)
            if unexplained and (budget is None or budget.can_call()):
                by_key = {(c.file, c.chunk_id): c for c in chunks}
                items = [(by_key[(f.file, f.chunk_id)].text, f.file, f.score)
                         for f in unexplained]
                results = _judge_all(judged, items, budget, cfg.judge.concurrency, stats)
                for f, result in zip(unexplained, results):
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
                    elif result.verdict == "unavailable":
                        stats.judge_unavailable += 1

    elif chunks:   # detector failed: fail closed over everything we could not score
        for chunk in chunks:
            findings.append(system_finding(
                chunk.file, "detector inference failed, fail-closed",
                chunk_id=chunk.chunk_id))

    if walk_result is not None and cfg.on_file_error == "flag":
        # lstat-level failures never reached the read loop; flag them too.
        findings.extend(system_finding(rel, f"unreadable file: {reason}")
                        for rel, reason in walk_result.unreadable)

    reasons: list[str] = []
    if stats.truncated_scan:
        reasons.append(f"file cap: {stats.files_over_cap} file(s) beyond "
                       f"max_files={cfg.walker.max_files} not scanned")
    if stats.views_dropped:
        reasons.append(f"decoded content cap: {stats.views_dropped} decoded "
                       f"view(s)/segment(s) not scored")
    if stats.judge_skipped:
        reasons.append(f"judge budget: {stats.judge_skipped} review-band chunk(s) not judged")
    if stats.decoder_errors:
        reasons.append(f"decoder errors: {len(stats.decoder_errors)}")
    if cfg.strict_coverage and stats.partial_files:
        reasons.append(f"partial coverage: {stats.partial_files} file(s) only partly scanned")
    stats.incomplete_reasons = reasons

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
