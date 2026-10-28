"""Chunking: cut file text into <=512-token windows for Prompt Guard 2.

The model's context is 512 tokens *including* the [CLS]/[SEP] specials, so the
content window is capped at ``window_tokens`` (default 448) with a 64-token
overlap so a payload split across a window boundary still appears whole in one
chunk.  Chunks are cut on token offsets from the fast tokenizer, so the chunk
text is always a slice of the original file text (evidence keeps real lines).
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_SPECIALS = 2  # [CLS], [SEP]


@dataclass
class Chunk:
    file: str          # repo-relative path
    view: str          # "original" or the decoder name
    chunk_id: int      # unique within (file), across views
    text: str
    start_char: int    # offset into the view text
    end_char: int
    start_line: int | None   # 1-based; None when the position in the file is unknown


def chunk_lines(text: str) -> list[int]:
    """Line-start offsets for 1-based line lookup via bisect."""
    starts = [0]
    find = text.find
    i = find("\n")
    while i != -1:
        starts.append(i + 1)
        i = find("\n", i + 1)
    return starts


def line_at(line_starts: list[int], offset: int) -> int:
    lo, hi = 0, len(line_starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if line_starts[mid] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1


class Chunker:
    def __init__(self, tokenizer, window_tokens: int = 448, overlap_tokens: int = 64,
                 max_file_tokens: int = 24_000, max_chunks: int = 48,
                 tail_windows: int = 2):
        if window_tokens + MAX_SPECIALS > 512:
            raise ValueError("window_tokens + specials must fit the model's 512-token context")
        if overlap_tokens >= window_tokens:
            raise ValueError("overlap_tokens must be smaller than window_tokens")
        self.tok = tokenizer
        self.window = window_tokens
        self.overlap = overlap_tokens
        self.max_file_tokens = max_file_tokens
        self.max_chunks = max_chunks
        # Over a cap, the last windows are still scored: payloads appended to
        # the end of a long file are the cheapest evasion of a prefix scan.
        self.tail_windows = max(0, min(tail_windows, max_chunks - 1))

    def _content_offsets(self, text: str, base: int = 0,
                         max_tokens: int | None = None) -> tuple[list[tuple[int, int]], bool]:
        """(content offsets shifted by ``base``, whether max_tokens truncated)."""
        kwargs = {}
        if max_tokens is not None:
            kwargs = {"truncation": True, "max_length": max_tokens + MAX_SPECIALS}
        enc = self.tok(text, return_offsets_mapping=True, add_special_tokens=True, **kwargs)
        truncated = (max_tokens is not None
                     and len(enc["input_ids"]) >= max_tokens + MAX_SPECIALS)
        # Drop the specials' (0,0) placeholders, keep content offsets only.
        return [(s + base, e + base) for s, e in enc["offset_mapping"] if e > s], truncated

    def chunk(self, text: str, file: str, view: str = "original",
              first_chunk_id: int = 0,
              line_offset: int | None = 0,
              max_chunks: int | None = None) -> tuple[list[Chunk], int]:
        """Returns (chunks, uncovered_tokens).

        ``uncovered_tokens`` counts content tokens no window covers — from the
        chunk cap *or* the token cap — so a scan can honestly report that
        unseen text remains (at least 1 when the token cap hid an unknown
        amount). Over either cap the head windows and the last
        ``tail_windows`` windows are scored. ``line_offset`` shifts reported
        line numbers (tail segments); None means lines are unknown.
        ``max_chunks`` overrides the per-call window budget (scan uses it to
        enforce one chunk budget per *file* across all segments and views).
        """
        budget = self.max_chunks if max_chunks is None else max(0, max_chunks)
        if not text or not text.strip():
            return [], 0
        # Hitting the token cap means the file had more tokens than we
        # tokenized; offsets can't see past it.
        content, hit_token_cap = self._content_offsets(text, max_tokens=self.max_file_tokens)
        if not content:
            return [], 0
        if budget <= 0:
            return [], len(content) + (1 if hit_token_cap else 0)

        stride = self.window - self.overlap
        windows: list[tuple[int, int]] = []
        start_tok = 0
        while True:
            end_tok = min(start_tok + self.window, len(content))
            windows.append((start_tok, end_tok))
            if end_tok >= len(content):
                break
            start_tok += stride
        # Always cover the tail: a payload hidden at EOF must not depend on luck.
        tail = windows[-1]
        if len(windows) > 1 and (tail[1] - tail[0]) < self.window // 4:
            windows[-2] = (len(content) - min(self.window, len(content)), len(content))
            windows.pop()

        spans: list[tuple[int, int]] = []      # char spans to emit, in order
        k = max(0, min(self.tail_windows, budget - 1)) if budget > 1 else 0
        if hit_token_cap and k:
            head = windows[: budget - k]
            spans = [(content[a][0], content[b - 1][1]) for a, b in head]
            head_end = spans[-1][1] if spans else 0
            # Tokenize just the end of the file for the tail windows.
            tail_start = max(head_end, len(text) - self.window * k * 8)
            tail, _ = self._content_offsets(text[tail_start:], base=tail_start)
            tail = tail[-(self.window * k - self.overlap * (k - 1)):]
            for i in range(k):
                a = i * (self.window - self.overlap)
                if a >= len(tail):
                    break
                b = min(a + self.window, len(tail))
                spans.append((tail[a][0], tail[b - 1][1]))
            uncovered = 1
        else:
            if len(windows) > budget:
                keep = windows[: budget - k] + (windows[-k:] if k else [])
            else:
                keep = windows
            covered = [False] * len(content)
            for a, b in keep:
                covered[a:b] = [True] * (b - a)
            uncovered = covered.count(False) + (1 if hit_token_cap else 0)
            spans = [(content[a][0], content[b - 1][1]) for a, b in keep]

        chunks: list[Chunk] = []
        line_starts = chunk_lines(text) if line_offset is not None else []
        for i, (s_char, e_char) in enumerate(spans):
            chunks.append(Chunk(
                file=file,
                view=view,
                chunk_id=first_chunk_id + i,
                text=text[s_char:e_char],
                start_char=s_char,
                end_char=e_char,
                start_line=(line_at(line_starts, s_char) + line_offset
                            if line_offset is not None else None),
            ))
        return chunks, uncovered
