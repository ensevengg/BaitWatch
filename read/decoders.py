"""Decoder registry: unhide payloads before the detector reads a file.

Each decoder turns one file's text into zero or more *decoded views* — plain
text that was hidden in the original (base64 blobs, HTML comments, zero-width
characters).  Every view is chunked and scored alongside the original, and a
finding from a decoded view reports which decoder found it.

Aditya's transform table (attacks side, D2) plugs in through
:func:`load_external_decoders`: a module named ``baitwatch_decoders`` importable
from the repo root (or ``attacks/decoders.py``) defining ``register(registry)``.
The three reference decoders here cover the demo payloads; his set replaces or
extends them.  Contract for any decoder: ``decode(encode(seed)) == seed`` must
hold on the attacks side — that round-trip is Aditya's test.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
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


_BASE64_RE = re.compile(rb"[A-Za-z0-9+/=]{24,}")
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
# "ASCII smuggling" runs: variation selectors used as invisible data channels.
# (No f-string here: "{8,}" would be parsed as a format field.)
_VS_RUN_RE = re.compile("[" + chr(0xFE00) + "-" + chr(0xFE0F) + "]{8,}")
_VS_SUPP_RE = re.compile("[" + chr(0xE0100) + "-" + chr(0xE01EF) + "]+")


class Base64Decoder:
    """Decodes base64-looking runs whose result is mostly printable text."""
    name = "base64"

    def decode(self, text: str) -> list[str]:
        out: list[str] = []
        data = text.encode("utf-8", errors="replace")
        for match in _BASE64_RE.finditer(data):
            try:
                decoded = base64.b64decode(match.group(), validate=True)
            except (binascii.Error, ValueError):
                continue
            try:
                as_text = decoded.decode("utf-8")
            except UnicodeDecodeError:
                continue
            printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in as_text)
            if len(as_text) >= 8 and printable / len(as_text) >= 0.95:
                out.append(as_text)
        return out


class HtmlCommentDecoder:
    """Pulls HTML comments out into the open; they render invisibly on forges."""
    name = "html_comment"

    def decode(self, text: str) -> list[str]:
        return [m.strip() for m in _HTML_COMMENT_RE.findall(text) if m.strip()]


class ZeroWidthDecoder:
    """Strips invisible characters so hidden instructions become visible text.

    Emits two views: the cleaned full text, and a *hidden-text extract* — only
    the lines that actually carried zero-width characters. The extract matters
    because rules-file backdoors glue zero-width chars across an otherwise
    benign file, and a payload diluted into hundreds of benign tokens scores
    far below the same payload alone.
    """
    name = "zero_width"

    def decode(self, text: str) -> list[str]:
        out: list[str] = []
        cleaned = _ZERO_WIDTH_RE.sub("", text)
        if cleaned != text and cleaned.strip():
            out.append(unicodedata.normalize("NFC", cleaned))
        lines = text.splitlines()
        marked = [unicodedata.normalize("NFC", _ZERO_WIDTH_RE.sub("", ln).strip())
                  for ln in lines if _ZERO_WIDTH_RE.search(ln)]
        extract = "\n".join(m for m in marked if m)
        # Only worth a separate view when the marked lines are a minority —
        # otherwise the cleaned text above already is the extract.
        if extract.strip() and len(marked) * 2 < max(1, len(lines)):
            if extract not in out:
                out.append(extract)
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
    return [Base64Decoder(), HtmlCommentDecoder(), ZeroWidthDecoder(),
            VariationSelectorDecoder()]


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


def produce_views(text: str, decoders: list[Decoder] | None,
                  errors: list[tuple[str, str]] | None = None) -> list[View]:
    """Original text first, then decoded variants round-robin across decoders.

    Round-robin (not decoder-major order) so a pile of variants from one
    decoder cannot push another decoder's finding past the caller's view cap.
    Variants are deduplicated; the caller applies any cap and reports what it
    dropped. A decoder that raises is recorded in ``errors`` as (name,
    message) and skipped — one broken decoder never kills the scan.
    """
    views = [View(text=text, decoder=None)]
    if not decoders:
        return views
    seen = {text}
    queues: list[tuple[Decoder, list[str]]] = []
    for dec in decoders:
        try:
            found = dec.decode(text)
        except Exception as exc:
            if errors is not None:
                errors.append((dec.name, str(exc)))
            continue
        q = [v for v in found if isinstance(v, str) and v.strip() and v not in seen]
        queues.append((dec, q))
    while any(q for _, q in queues):
        for dec, q in queues:
            if not q:
                continue
            v = q.pop(0)
            if v not in seen:
                seen.add(v)
                views.append(View(text=v, decoder=dec.name))
    return views
