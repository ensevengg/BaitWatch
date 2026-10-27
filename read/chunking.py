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
    start_line: int    # 1-based, computed by the caller via line index


def chunk_lines(text: str) -> list[int]:
    """Line-start offsets for 1-based line lookup via bisect."""
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
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
                 max_file_tokens: int = 24_000, max_chunks: int = 48):
        if window_tokens + MAX_SPECIALS > 512:
            raise ValueError("window_tokens + specials must fit the model's 512-token context")
        if overlap_tokens >= window_tokens:
            raise ValueError("overlap_tokens must be smaller than window_tokens")
        self.tok = tokenizer
        self.window = window_tokens
        self.overlap = overlap_tokens
        self.max_file_tokens = max_file_tokens
        self.max_chunks = max_chunks

    def chunk(self, text: str, file: str, view: str = "original",
              first_chunk_id: int = 0) -> tuple[list[Chunk], int]:
        """Returns (chunks, uncovered_tokens).

        ``uncovered_tokens`` counts every content token beyond the last produced
        window — from the chunk cap *or* the tokenizer's own truncation — so a
        scan can honestly report that unseen text remains.
        """
        if not text or not text.strip():
            return [], 0
        enc = self.tok(text, return_offsets_mapping=True, add_special_tokens=True,
                       truncation=True, max_length=self.max_file_tokens + MAX_SPECIALS)
        # Hitting the cap means the file had more tokens than we tokenized;
        # offsets can't see past it, so flag at least one token as unseen.
        hit_token_cap = len(enc["input_ids"]) >= self.max_file_tokens + MAX_SPECIALS
        offsets = [o for o in enc["offset_mapping"]]
        # Drop the specials' (0,0) placeholders, keep content offsets only.
        content = [(s, e) for s, e in offsets if e > s]
        if not content:
            return [], 0

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

        limited = windows[: self.max_chunks]
        covered = limited[-1][1] if limited else 0
        uncovered = max(0, len(content) - covered)
        if hit_token_cap:
            uncovered = max(uncovered, 1)
        chunks: list[Chunk] = []
        line_starts = chunk_lines(text)
        for i, (a, b) in enumerate(limited):
            s_char = content[a][0]
            e_char = content[b - 1][1]
            chunks.append(Chunk(
                file=file,
                view=view,
                chunk_id=first_chunk_id + i,
                text=text[s_char:e_char],
                start_char=s_char,
                end_char=e_char,
                start_line=line_at(line_starts, s_char),
            ))
        return chunks, uncovered
