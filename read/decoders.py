"""Decoder registry: unhide payloads before the detector reads a file.

Each decoder turns one file's text into zero or more *decoded views* — plain
text that was hidden in the original (base64 blobs, HTML comments, zero-width
characters).  Every view is chunked and scored alongside the original, and a
finding from a decoded view reports which decoder found it.

Aditya's transform table (attacks side, D2) plugs in through
:func:`load_external_decoders`: a module named ``baitwatch_decoders`` importable
from the repo root (or ``attacks/decoders.py``) defining ``register(registry)``.
The built-in decoders here cover the documented smuggling channels; his set
replaces or extends them.  Contract for any decoder: ``decode(encode(seed)) == seed`` must
hold on the attacks side — that round-trip is Aditya's test.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class View:
    text: str
    decoder: str | None   # None for the original file text


class Decoder(Protocol):
    name: str
    def decode(self, text: str) -> list[str]: ...


def _printable_text(data: bytes, min_len: int = 8) -> str | None:
    """UTF-8 text that is >=95% printable, else None (binary, too short)."""
    try:
        as_text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(as_text) < min_len:
        return None
    ok = sum(ch.isprintable() or ch in "\n\r\t" for ch in as_text)
    return as_text if ok / len(as_text) >= 0.95 else None


# Base64 runs: standard or URL-safe alphabet, padding only at the end — so
# `KEY=<blob>` splits at the "=" instead of poisoning the run.
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
# A line that is nothing but base64 (optionally quoted / commented): wrapped
# blobs (PEM-style, `base64 -w 76`) are rejoined before decoding.
_B64_LINE_RE = re.compile(r"^[\s>#*/\"'`]*([A-Za-z0-9+/_-]{16,}={0,2})[\s\"'`,;\\]*$")
_HEX_RUN_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
_B32_RUN_RE = re.compile(r"[A-Z2-7]{16,}={0,6}", re.IGNORECASE)
_ENTITY_RE = re.compile(r"&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);")
_ENTITY_RUN_RE = re.compile(r"(?:&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]+);)+")
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_PCT_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
# Zero-width and invisible formatting chars used to smuggle text past review.
# Includes the Trojan-Source bidi controls (CVE-2021-42574) — U+202A..U+202E
# and the U+2066..U+2069 isolates — which reorder how code/text *displays*
# versus what an agent actually reads.
_ZERO_WIDTH = "".join(chr(c) for c in (
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D,
    0x202E, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2066, 0x2067, 0x2068,
    0x2069, 0xFEFF, 0x00AD,
))
_ZERO_WIDTH_RE = re.compile(f"[{re.escape(_ZERO_WIDTH)}]")
_BIDI_CONTROL_RE = re.compile("[‪-‮⁦-⁩]")
# Invisible chars glued to ASCII text are the smuggling signature. Legit uses
# (emoji ZWJ sequences, Indic/Persian ZWJ/ZWNJ) sit between non-ASCII chars.
_ZW_ASCII_ADJ_RE = re.compile(
    f"(?<=[A-Za-z0-9])[{re.escape(_ZERO_WIDTH)}]|[{re.escape(_ZERO_WIDTH)}](?=[A-Za-z0-9])")
_ZW_SUSPICIOUS_MIN = 3
# Every invisible carrier (zero-width, tags, variation selectors), stripped
# from the cleaned view so the detector reads what the agent reads.
_INVISIBLE_RE = re.compile(
    f"[{re.escape(_ZERO_WIDTH)}︀-️\U000e0000-\U000e007f\U000e0100-\U000e01ef]")
# "ASCII smuggling" runs: variation selectors used as invisible data channels.
# (No f-string here: "{8,}" would be parsed as a format field.)
_VS_RUN_RE = re.compile("[" + chr(0xFE00) + "-" + chr(0xFE0F) + "]{8,}")
_VS_SUPP_RE = re.compile("[" + chr(0xE0100) + "-" + chr(0xE01EF) + "]+")
# Unicode Tags block (U+E0000..U+E007F): each tag char mirrors one ASCII char
# and renders as nothing — the canonical LLM "ASCII smuggling" channel.
_TAG_RUN_RE = re.compile("[\U000e0000-\U000e007f]{4,}")


def _b64_candidates(run: str) -> list[str]:
    """Normalized, padded forms of a run worth trying (std / URL-safe)."""
    s = run.rstrip("=")
    has_std = "+" in s or "/" in s
    has_url = "-" in s or "_" in s
    if has_std and has_url:
        # e.g. "sha512-<b64>": keep the part after the last URL-safe char.
        s = re.split(r"[-_]", s)[-1]
        has_url = False
    if has_url:
        s = s.replace("-", "+").replace("_", "/")
    if len(s) % 4 == 1:            # one stray char can never be valid base64
        s = s[:-1]
    if len(s) < 16:
        return []
    return [s + "=" * (-len(s) % 4)]


def _decode_b64_run(run: str) -> str | None:
    for cand in _b64_candidates(run):
        try:
            raw = base64.b64decode(cand, validate=True)
        except (binascii.Error, ValueError):
            continue
        text = _printable_text(raw)
        if text is not None:
            return text
    return None


class Base64Decoder:
    """Decodes base64 runs whose result is mostly printable text.

    Handles the shapes real payloads take: `KEY=<blob>`, unpadded, URL-safe
    alphabet, and blobs wrapped across lines.
    """
    name = "base64"

    def decode(self, text: str) -> list[str]:
        out: list[str] = []

        def add(decoded: str | None) -> None:
            if decoded is not None and decoded not in out:
                out.append(decoded)

        # Wrapped blocks first: consecutive lines that are pure base64.
        block: list[str] = []
        for line in text.splitlines() + [""]:
            m = _B64_LINE_RE.match(line)
            if m:
                block.append(m.group(1))
                continue
            if len(block) >= 2:
                add(_decode_b64_run("".join(block)))
            block = []
        for match in _B64_RUN_RE.finditer(text):
            add(_decode_b64_run(match.group()))
        return out


class HexDecoder:
    """Decodes long hex runs that turn out to be printable text."""
    name = "hex"

    def decode(self, text: str) -> list[str]:
        out: list[str] = []
        for match in _HEX_RUN_RE.finditer(text):
            decoded = _printable_text(bytes.fromhex(match.group()))
            if decoded is not None and decoded not in out:
                out.append(decoded)
        return out


class Base32Decoder:
    """Decodes base32 runs whose result is mostly printable text."""
    name = "base32"

    def decode(self, text: str) -> list[str]:
        out: list[str] = []
        for match in _B32_RUN_RE.finditer(text):
            s = match.group().upper().rstrip("=")
            if len(s) % 8 in (1, 3, 6):   # impossible base32 lengths
                continue
            try:
                raw = base64.b32decode(s + "=" * (-len(s) % 8))
            except (binascii.Error, ValueError):
                continue
            decoded = _printable_text(raw)
            if decoded is not None and decoded not in out:
                out.append(decoded)
        return out


# Markup escapes whose decoding changes punctuation, not the text a model
# reads: lines/files using only these are markup, not encoded payloads.
_BENIGN_ENTITY_BODIES = frozenset({
    "amp", "quot", "lt", "gt", "apos", "nbsp", "#39", "#x27", "#x22",
    "#xa", "#10", "#xd", "#13", "#x9", "#9",   # whitespace escapes (drawio SVGs)
})


def _is_interesting_entity(match: re.Match) -> bool:
    return match.group(1).lower() not in _BENIGN_ENTITY_BODIES


class HtmlEntityDecoder:
    """Unescapes HTML entities (``&#73;gnore…``) into plain text.

    Gated so ordinary files that merely contain ``&amp;`` do not produce a
    whole-file copy: a decoded view is emitted only for a run of entities
    that decodes to real text, for a line carrying several non-markup
    entities and reading as prose once decoded, or when such entities cover
    a material fraction of the whole text.
    """
    name = "html_entity"

    def decode(self, text: str) -> list[str]:
        matches = list(_ENTITY_RE.finditer(text))
        if not matches:
            return []
        out: list[str] = []

        def add(decoded: str) -> None:
            if decoded.strip() and decoded != text and decoded not in out:
                out.append(decoded)

        for m in _ENTITY_RUN_RE.finditer(text):
            decoded = html.unescape(m.group())
            if len(decoded.strip()) >= 8 and any(
                    _is_interesting_entity(e) for e in _ENTITY_RE.finditer(m.group())):
                add(decoded)
        for line in text.splitlines():
            line_matches = list(_ENTITY_RE.finditer(line))
            if len(line_matches) >= 3 and any(
                    _is_interesting_entity(e) for e in line_matches):
                decoded = html.unescape(line)
                # A line of markup that merely uses &quot;/&amp; decodes to
                # itself; only lines that read as prose once decoded are
                # worth a separate view.
                if _english_hits(decoded) >= 3:
                    add(decoded)
        interesting = [m for m in matches if _is_interesting_entity(m)]
        entity_chars = sum(len(m.group()) for m in interesting)
        if len(interesting) >= 4 and entity_chars / max(1, len(text)) >= 0.10:
            add(html.unescape(text))
        return out


class UrlEncodingDecoder:
    """Percent-decodes text containing ``%XX`` escapes.

    Gated like the HTML-entity decoder: a lone ``%20`` in a URL or file name
    emits nothing. Only decoded runs, lines carrying several escapes, or a
    text materially covered by escapes produce a view.
    """
    name = "url_encoding"

    def decode(self, text: str) -> list[str]:
        matches = list(_PCT_RE.finditer(text))
        if not matches:
            return []
        out: list[str] = []

        def add(decoded: str) -> None:
            if decoded.strip() and decoded != text and decoded not in out:
                out.append(decoded)

        for m in _PCT_RUN_RE.finditer(text):
            decoded = urllib.parse.unquote(m.group())
            if len(decoded.strip()) >= 8:
                add(decoded)
        for line in text.splitlines():
            if len(_PCT_RE.findall(line)) >= 3:
                decoded = urllib.parse.unquote(line)
                # Percent-escapes in URLs/code ("/snow%20%E2%98%83/") decode
                # to themselves in context; only prose-like decoded lines
                # earn a separate view.
                if _english_hits(decoded) >= 3:
                    add(decoded)
        if len(matches) >= 4 and 3 * len(matches) / max(1, len(text)) >= 0.10:
            add(urllib.parse.unquote(text))
        return out


_COMMON_WORDS = frozenset({
    "the", "and", "all", "your", "you", "this", "that", "with", "from",
    "before", "after", "any", "ignore", "instructions", "instruction",
    "previous", "send", "run", "read", "file", "files", "user", "secret",
    "secrets", "token", "tokens", "curl", "not", "do", "tell", "mention",
    "contents", "content", "server", "please", "post", "env", "collect",
    "https", "evil", "example", "hidden", "never", "must", "agent", "agents",
    "system", "prompt", "override", "download", "execute", "install",
    "password", "credentials", "task", "its", "to",
})


def _english_hits(text: str) -> int:
    return sum(1 for w in re.findall(r"[a-z]+", text.lower()) if w in _COMMON_WORDS)


class Rot13Decoder:
    """ROT13-decodes lines that read as English only after decoding.

    The English-likeness gate keeps this from emitting a gibberish copy of
    every ordinary file: a line is surfaced only when the decoded form has
    at least two common words and more than the original.
    """
    name = "rot13"

    def decode(self, text: str) -> list[str]:
        cands = []
        for line in text.splitlines():
            if len(line) < 12:
                continue
            decoded = codecs.decode(line, "rot_13")
            if _english_hits(decoded) >= 2 and _english_hits(decoded) > _english_hits(line):
                cands.append(decoded)
        return ["\n".join(cands)] if cands else []


class ReversedDecoder:
    """Reverses lines that read as English only when reversed."""
    name = "reversed"

    def decode(self, text: str) -> list[str]:
        cands = []
        for line in text.splitlines():
            if len(line) < 12:
                continue
            decoded = line[::-1]
            if _english_hits(decoded) >= 2 and _english_hits(decoded) > _english_hits(line):
                cands.append(decoded)
        return ["\n".join(cands)] if cands else []


class HtmlCommentDecoder:
    """Pulls HTML comments out into the open; they render invisibly on forges."""
    name = "html_comment"

    def decode(self, text: str) -> list[str]:
        return [m.strip() for m in _HTML_COMMENT_RE.findall(text) if m.strip()]


def has_suspicious_invisibles(text: str) -> bool:
    """Bidi controls, or invisible chars glued to ASCII text (>= 3 sites)."""
    if _BIDI_CONTROL_RE.search(text):
        return True
    hits = 0
    for _ in _ZW_ASCII_ADJ_RE.finditer(text):
        hits += 1
        if hits >= _ZW_SUSPICIOUS_MIN:
            return True
    return False


class ZeroWidthDecoder:
    """Strips invisible characters so hidden instructions become visible text.

    Emits two views: the cleaned full text, and a *hidden-text extract* — only
    the lines that actually carried zero-width characters. The extract matters
    because rules-file backdoors glue zero-width chars across an otherwise
    benign file, and a payload diluted into hundreds of benign tokens scores
    far below the same payload alone.

    Only fires on the smuggling signature (see has_suspicious_invisibles):
    emoji and Indic/Persian text use ZWJ/ZWNJ legitimately, and a full-file
    copy of every such file doubled scan cost for no new detections.
    """
    name = "zero_width"
    join_segments = False     # the extract must stay apart from the full copy

    def decode(self, text: str) -> list[str]:
        if not has_suspicious_invisibles(text):
            return []
        out: list[str] = []
        cleaned = _INVISIBLE_RE.sub("", text)
        if cleaned != text and cleaned.strip():
            out.append(unicodedata.normalize("NFC", cleaned))
        lines = text.splitlines()
        marked = [unicodedata.normalize("NFC", _INVISIBLE_RE.sub("", ln).strip())
                  for ln in lines if _ZERO_WIDTH_RE.search(ln)]
        extract = "\n".join(m for m in marked if m)
        # Only worth a separate view when the marked lines are a minority —
        # otherwise the cleaned text above already is the extract.
        if extract.strip() and len(marked) * 2 < max(1, len(lines)):
            if extract not in out:
                out.append(extract)
        return out


class TagDecoder:
    """Decodes Unicode Tag-block runs (U+E0020..U+E007E mirror ASCII)."""
    name = "unicode_tags"

    def decode(self, text: str) -> list[str]:
        out: list[str] = []
        for m in _TAG_RUN_RE.finditer(text):
            chars = [chr(ord(c) - 0xE0000) for c in m.group()
                     if 0x20 <= ord(c) - 0xE0000 <= 0x7E]
            decoded = "".join(chars)
            # Subdivision-flag emoji carry ~5 tag letters ("gbsct"); payloads
            # are longer.
            if len(decoded) >= 8 and decoded not in out:
                out.append(decoded)
        return out


class VariationSelectorDecoder:
    """Decodes 'ASCII smuggled' payloads hidden in variation selectors.

    Two documented encodings: pairs of U+FE00..U+FE0F selectors (one nibble
    each) or single U+E0100..U+E01EF selectors (one byte each). Runs shorter
    than 8 selectors are ignored — emoji (U+FE0F) is legitimate and common.
    """

    name = "variation_selector"

    @staticmethod
    def _printable(data: bytes) -> str | None:
        try:
            as_text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if len(as_text) < 8:
            return None
        ok = sum(ch.isprintable() or ch in "\n\r\t" for ch in as_text)
        return as_text if ok / len(as_text) >= 0.95 else None

    def decode(self, text: str) -> list[str]:
        out: list[str] = []
        for m in _VS_RUN_RE.finditer(text):
            run = m.group()
            if len(run) % 2 == 0:
                data = bytes(((ord(run[i]) - 0xFE00) << 4) | (ord(run[i + 1]) - 0xFE00)
                             for i in range(0, len(run), 2))
                if (decoded := self._printable(data)):
                    out.append(decoded)
        for m in _VS_SUPP_RE.finditer(text):
            data = bytes(ord(c) - 0xE0100 for c in m.group())
            if (decoded := self._printable(data)):
                out.append(decoded)
        return out


def builtin_decoders() -> list[Decoder]:
    return [Base64Decoder(), Base32Decoder(), HexDecoder(),
            HtmlCommentDecoder(), HtmlEntityDecoder(), ZeroWidthDecoder(),
            VariationSelectorDecoder(), TagDecoder(),
            UrlEncodingDecoder(), Rot13Decoder(), ReversedDecoder()]


# -- blob masking ---------------------------------------------------------------

_MASK_RUN_RE = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")
# PEM armor (certs, keys, CSRs): base64 DER between BEGIN/END lines. DER's
# runs of "A"/"I" defeat the vowel test, and the bare "BEGIN PRIVATE KEY"
# header alone scores 0.94 — the block carries no readable text, so it is
# blanked (newlines kept); anything around it is still scored.
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN ([A-Z0-9 ]{1,40})-----[ \t]*\r?\n"
    r"((?:[A-Za-z0-9+/=: \t,-]*\r?\n){0,4000}?)"
    r"-----END \1-----")
_MASK_HEX_RE = re.compile(r"\b[0-9A-Fa-f]{40,}\b")
_VOWELS = frozenset("aeiouAEIOU")


def _looks_like_blob(run: str) -> bool:
    """High-entropy machine data, not words glued together.

    Encoded/random data has letters in both cases plus digits (or + and /),
    almost no separators, and few vowels (~19% of letters vs ~38% in English);
    camelCase or kebab-case prose fails the vowel test, so a readable
    instruction can never be masked away.
    """
    letters = [c for c in run if c.isalpha()]
    if not letters:
        return False
    classes = (any(c.isupper() for c in letters) + any(c.islower() for c in letters)
               + any(c.isdigit() for c in run))
    if classes < 3 and "+" not in run and "/" not in run:
        return False
    if sum(c in "-_" for c in run) > 0.1 * len(run):
        return False
    return sum(c in _VOWELS for c in letters) / len(letters) < 0.3


def mask_blobs(text: str) -> str:
    """Replace base64/hex blobs with a short placeholder before scoring.

    The fine-tuned detector scores raw base64 as an attack whatever it
    encodes (a random data-URI scored 0.92), which flagged certificates,
    integrity hashes and embedded images. Readable content inside a blob is
    scored through the decoders' views instead. Runs never span a newline, so
    line numbers are preserved.
    """
    def sub_b64(m: re.Match) -> str:
        return f"<blob:{len(m.group())}>" if _looks_like_blob(m.group()) else m.group()

    def sub_hex(m: re.Match) -> str:
        run = m.group()
        if any(c.isdigit() for c in run) and any(c.isalpha() for c in run):
            return f"<hex:{len(run)}>"
        return run

    def sub_pem(m: re.Match) -> str:
        return "\n" * m.group(0).count("\n")

    text = _PEM_BLOCK_RE.sub(sub_pem, text)
    return _MASK_HEX_RE.sub(sub_hex, _MASK_RUN_RE.sub(sub_b64, text))


def load_external_decoders(search_root: Path | None = None) -> list[Decoder]:
    """Load Aditya's decoder module, if present.

    ONLY ``<search_root>/attacks/decoders.py`` is considered, via
    spec_from_file_location. There is deliberately no sys.path import: a
    scanned repo must never be able to get code executed during its own scan,
    and sys.path is caller-controlled. The module must define
    ``register(registry: list[Decoder])``. Returns [] when nothing is
    installed; a broken external module raises to the caller.
    """
    import importlib.util

    if search_root is None:
        return []
    candidate = Path(search_root) / "attacks" / "decoders.py"
    if not candidate.exists():
        return []
    spec = importlib.util.spec_from_file_location("baitwatch_decoders", candidate)
    if spec is None or spec.loader is None:
        return []
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    found: list[Decoder] = []
    register = getattr(mod, "register", None)
    if callable(register):
        register(found)
    return [d for d in found if hasattr(d, "name") and callable(getattr(d, "decode", None))]


SEGMENT_SEPARATOR = "\n\n"


def produce_views(text: str, decoders: list[Decoder] | None,
                  errors: list[tuple[str, str]] | None = None,
                  depth: int = 3, max_segments: int = 256,
                  overflow: list[int] | None = None) -> list[View]:
    """Original text first, then one view per decoder.

    Each decoder's segments (every HTML comment, every decoded blob) are
    joined into a single view: scored alone, a 3-word comment such as
    "prettier-ignore-start" lands at 0.7–0.96 on this detector, while the
    joined comments of a file read as what they are. The chunker splits a
    long joined view like any other text, so no segment is ever dropped by a
    view-count cap. Decoders that set ``join_segments = False`` (zero-width:
    full cleaned copy + hidden-line extract) keep one view per segment.

    Decoding is applied again to decoded output, ``depth`` levels deep, so
    nested encodings (base64 of base64, base64 behind zero-width chars) are
    unwrapped. Segments are deduplicated; past ``max_segments`` the count of
    unscored segments is appended to ``overflow`` so the caller can report
    incomplete evidence. A decoder that raises is recorded in ``errors`` as
    (name, message) and skipped — one broken decoder never kills the scan.
    """
    views = [View(text=text, decoder=None)]
    if not decoders:
        return views
    seen = {text}
    found_by: dict[str, list[str]] = {}
    joins: dict[str, bool] = {}
    frontier = [text]
    total = dropped = 0
    for _ in range(max(1, depth)):
        next_frontier: list[str] = []
        for source in frontier:
            for dec in decoders:
                try:
                    found = dec.decode(source)
                except Exception as exc:   # noqa: BLE001 - isolate plugin bugs
                    if errors is not None:
                        errors.append((dec.name, str(exc)))
                    continue
                for seg in found:
                    if not isinstance(seg, str) or not seg.strip() or seg in seen:
                        continue
                    seen.add(seg)
                    if total >= max_segments:
                        dropped += 1
                        continue
                    total += 1
                    found_by.setdefault(dec.name, []).append(seg)
                    joins[dec.name] = getattr(dec, "join_segments", True)
                    next_frontier.append(seg)
        frontier = next_frontier
        if not frontier:
            break
    if dropped and overflow is not None:
        overflow.append(dropped)
    for name, segs in found_by.items():
        if joins[name]:
            views.append(View(text=SEGMENT_SEPARATOR.join(segs), decoder=name))
        else:
            views.extend(View(text=s, decoder=name) for s in segs)
    return views
