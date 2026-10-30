"""Symmetric transform table: one place where every smuggling channel lives.

Every transform is a pair of functions with one contract:

    seed in transform.decode(transform.encode(seed))

That round trip is what makes an attack reproducible and a decoder testable.
The encoders produce the bytes that land in ``attacks/repos`` and
``attacks/examples``; the decoders are registered with the READ scanner
through ``attacks/decoders.py`` and must recover the seed from a whole file.

Channels already covered by ``read.decoders`` (base64, hex, HTML comments,
zero-width stripping, Unicode tags, variation selectors) keep their transforms
here for the synthesizer, but are *not* registered again by the plugin: a
second decoder for the same channel only doubles scan cost.

Safety: seeds are plain ASCII, point at ``*.example`` hosts or
``10.13.37.0/24`` sinks, and never carry real credentials. ``attacks/lint.py``
enforces that over every generated artifact.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from collections.abc import Callable
from dataclasses import dataclass

__all__ = [
    "DECODER_TRANSFORMS",
    "TRANSFORMS",
    "DecodeBudget",
    "Transform",
    "decode_payload",
    "encode_seed",
    "printable_text",
]

ZW_SPACE = "\u200b"  # bit 0
ZW_JOINER = "\u200c"  # bit 1
ZW_START = "\u2063"  # invisible separator, delimits a bit run

RLO = "\u202e"
PDF = "\u202c"
BIDI_CONTROLS = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"

_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
_ZW_BITS = re.compile("[\u200b\u200c]{16,}")
_TAG_RUN = re.compile("[\U000e0000-\U000e007f]{4,}")
_VS_RUN = re.compile("[\ufe00-\ufe0f]{8,}")
_MD_IMAGE = re.compile(r"!\[([^\]\n]{4,})\]\(([^)\n]*)\)")
_ATOB = re.compile(
    r"(?:atob|Buffer\.from)\(\s*[\"']([A-Za-z0-9+/=_-]{16,})[\"']"
    r"(?:\s*,\s*[\"']base64[\"'])?\s*\)"
)
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
_U_ESCAPES = re.compile(r"(?:\\u[0-9A-Fa-f]{4}){4,}")

# Decoder budgets.  Gate A feeds arbitrary prompt text and hostile files reach
# the same code, so one call may never scan or emit unbounded output.  The
# input cap matches READ's default max_file_bytes; work is enforced by
# ``read.decoders.produce_views`` across all decoders for one segment.
MAX_DECODE_INPUT = 262_144
MAX_DECODE_OUTPUT = 131_072
MAX_DECODE_SEGMENTS = 64


class DecodeBudget:
    """Input/output budget for one decoder call on one source string."""

    def __init__(
        self,
        input_chars: int = MAX_DECODE_INPUT,
        output_chars: int = MAX_DECODE_OUTPUT,
        segments: int = MAX_DECODE_SEGMENTS,
    ) -> None:
        self.input_chars = input_chars
        self.output_chars = output_chars
        self.segments = segments

    def input(self, text: str) -> tuple[str, bool]:
        if len(text) <= self.input_chars:
            return text, False
        return text[: self.input_chars], True

    def output(self, items: list[str]) -> tuple[list[str], bool]:
        kept: list[str] = []
        total = 0
        spent = False
        for item in items:
            if len(kept) >= self.segments or total + len(item) > self.output_chars:
                spent = True
                break
            kept.append(item)
            total += len(item)
        return kept, spent


def printable_text(data: bytes, min_len: int = 8) -> str | None:
    """UTF-8 that is at least 95% printable, else None (binary or too short)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < min_len:
        return None
    ok = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    return text if ok / len(text) >= 0.95 else None


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def _dedupe(items: list[str | None]) -> list[str]:
    out: list[str] = []
    for item in items:
        if item and item not in out:
            out.append(item)
    return out


# -- encoders -----------------------------------------------------------------


def _plain_encode(seed: str) -> str:
    return seed


def _plain_decode(text: str) -> list[str]:
    return [text]


def _b64_encode(seed: str) -> str:
    return base64.b64encode(seed.encode("utf-8")).decode("ascii")


def _b64_decode(text: str) -> list[str]:
    found: list[str] = []
    for match in _B64_RUN.finditer(text):
        run = match.group().rstrip("=")
        if len(run) % 4 == 1:
            run = run[:-1]
        run = run.replace("-", "+").replace("_", "/")
        try:
            raw = base64.b64decode(run + "=" * (-len(run) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = printable_text(raw)
        if decoded is not None:
            found.append(decoded)
    return _dedupe(found)


def _hex_encode(seed: str) -> str:
    return seed.encode("utf-8").hex()


def _hex_decode(text: str) -> list[str]:
    found: list[str] = []
    for match in _HEX_RUN.finditer(text):
        decoded = printable_text(bytes.fromhex(match.group()))
        if decoded is not None:
            found.append(decoded)
    return _dedupe(found)


def _rot13_encode(seed: str) -> str:
    return _rot13(seed)


def _rot13_decode(text: str) -> list[str]:
    candidates: list[str] = []
    # Line by line: a payload embedded in a benign file sits on its own line.
    for line in text.splitlines():
        if sum(ch.isalpha() for ch in line) >= 8:
            candidates.append(_rot13(line.strip()))
    if sum(ch.isalpha() for ch in text) >= 8:
        candidates.append(_rot13(text))
    return _dedupe(candidates)


def _zero_width_binary_encode(seed: str) -> str:
    bits = "".join(f"{byte:08b}" for byte in seed.encode("utf-8"))
    body = "".join(ZW_SPACE if bit == "0" else ZW_JOINER for bit in bits)
    return ZW_START + body + ZW_START


def _zero_width_binary_decode(text: str) -> list[str]:
    found: list[str] = []
    for match in _ZW_BITS.finditer(text):
        run = match.group()
        if len(run) % 8:
            continue
        bits = "".join("0" if ch == ZW_SPACE else "1" for ch in run)
        raw = bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))
        decoded = printable_text(raw)
        if decoded is not None:
            found.append(decoded)
    return _dedupe(found)


def _bidi_encode(seed: str) -> str:
    return RLO + seed[::-1] + PDF


def _bidi_decode(text: str) -> list[str]:
    """One left-to-right pass; every RLO is used once, nested or not.

    The previous regex (``RLO(.*?)PDF``) rescanned to end-of-text for every
    unmatched opener, which is quadratic on hostile input.  This walk is O(n):
    an opener only starts a span at depth 0, and a span is emitted only when
    its depth returns to 0.
    """
    found: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char == RLO:
            if depth == 0:
                start = index + 1
            depth += 1
        elif char == PDF and depth:
            depth -= 1
            if depth == 0:
                inner = text[start:index]
                # Strip nested controls before reversing, so a doubly wrapped
                # seed still comes back exactly once.
                inner = "".join(ch for ch in inner if ch not in BIDI_CONTROLS)
                found.append(inner[::-1])
    if depth:
        # A paragraph ends an override in rendered text even when PDF was
        # omitted, so an unclosed span can still be recovered from the
        # remainder of its own paragraph without reversing later paragraphs.
        remainder = text[start:]
        remainder = re.split(r"\r?\n[ \t]*(?:\r?\n|$)|\u2029", remainder, maxsplit=1)[0]
        remainder = "".join(ch for ch in remainder if ch not in BIDI_CONTROLS)
        if remainder:
            found.append(remainder[::-1])
    stripped = "".join(ch for ch in text if ch not in BIDI_CONTROLS)
    if stripped != text:
        found.append(stripped)
    return _dedupe(found)


def _html_comment_encode(seed: str) -> str:
    return f"<!-- {seed} -->"


def _html_comment_decode(text: str) -> list[str]:
    return _dedupe([m.strip() for m in re.findall(r"<!--(.*?)-->", text, re.DOTALL)])


def _tags_encode(seed: str) -> str:
    return "".join(chr(0xE0000 + ord(ch)) for ch in seed if 0x20 <= ord(ch) <= 0x7E)


def _tags_decode(text: str) -> list[str]:
    found: list[str] = []
    for match in _TAG_RUN.finditer(text):
        decoded = "".join(
            chr(ord(ch) - 0xE0000) for ch in match.group() if 0x20 <= ord(ch) - 0xE0000 <= 0x7E
        )
        if len(decoded) >= 8:
            found.append(decoded)
    return _dedupe(found)


def _variation_encode(seed: str) -> str:
    out: list[str] = []
    for byte in seed.encode("utf-8"):
        out.append(chr(0xFE00 + (byte >> 4)))
        out.append(chr(0xFE00 + (byte & 0x0F)))
    return "".join(out)


def _variation_decode(text: str) -> list[str]:
    found: list[str] = []
    for match in _VS_RUN.finditer(text):
        run = match.group()
        if len(run) % 2:
            run = run[:-1]
        raw = bytes(
            ((ord(run[i]) - 0xFE00) << 4) | (ord(run[i + 1]) - 0xFE00)
            for i in range(0, len(run), 2)
        )
        decoded = printable_text(raw)
        if decoded is not None:
            found.append(decoded)
    return _dedupe(found)


def _markdown_image_encode(seed: str) -> str:
    return f"![{seed}](https://evil.example/assets/pixel.png)"


def _markdown_image_decode(text: str) -> list[str]:
    found: list[str] = []
    for alt, _target in _MD_IMAGE.findall(text):
        alt = alt.strip()
        if len(alt) >= 8:
            found.append(alt)
    return _dedupe(found)


def _js_eval_encode(seed: str) -> str:
    """Base64 around ROT13, with a decode chain the JS runtime can run.

    The generated expression is ``eval(rot13(atob("...")))``; the fixture
    files define ``rot13`` above it, so the hidden action really executes
    instead of evaluating ROT13 text.
    """
    inner = base64.b64encode(_rot13(seed).encode("utf-8")).decode("ascii")
    return f'eval(rot13(atob("{inner}")))'


def _js_eval_decode(text: str) -> list[str]:
    found: list[str] = []
    for match in _ATOB.finditer(text):
        run = match.group(1).rstrip("=").replace("-", "+").replace("_", "/")
        try:
            raw = base64.b64decode(run + "=" * (-len(run) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        inner = printable_text(raw, min_len=4)
        if inner is None:
            continue
        # The synthesizer wraps base64 around rot13; a plain atob payload is
        # returned as-is too, so the decoder is useful outside our own chains.
        found.extend([_rot13(inner), inner])
    return _dedupe(found)


def _js_escapes_encode(seed: str) -> str:
    body = "".join(f"\\x{byte:02x}" for byte in seed.encode("utf-8"))
    return f'eval("{body}")'


def _printable_str(text: str, min_len: int = 8) -> str | None:
    """Printable Unicode text, else None (control-heavy or too short)."""
    if len(text) < min_len:
        return None
    ok = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    return text if ok / len(text) >= 0.95 else None


def _decode_u_units(units: list[int]) -> str:
    """UTF-16 code units -> characters, combining surrogate pairs."""
    out: list[str] = []
    index = 0
    while index < len(units):
        unit = units[index]
        if (
            0xD800 <= unit <= 0xDBFF
            and index + 1 < len(units)
            and 0xDC00 <= units[index + 1] <= 0xDFFF
        ):
            out.append(chr(0x10000 + ((unit - 0xD800) << 10) + (units[index + 1] - 0xDC00)))
            index += 2
            continue
        if 0xD800 <= unit <= 0xDFFF:
            # A lone surrogate is not valid text; keep the run readable.
            out.append("\ufffd")
        else:
            out.append(chr(unit))
        index += 1
    return "".join(out)


def _js_escapes_decode(text: str) -> list[str]:
    found: list[str] = []
    for match in _HEX_ESCAPES.finditer(text):
        raw = bytes(int(pair, 16) for pair in re.findall(r"\\x([0-9A-Fa-f]{2})", match.group()))
        decoded = printable_text(raw)
        if decoded is not None:
            found.append(decoded)
    for match in _U_ESCAPES.finditer(text):
        # ``\uNNNN`` is a *character* escape, not a byte.  Each run is decoded
        # independently so one bad run cannot discard the others.
        try:
            units = [int(group, 16) for group in re.findall(r"\\u([0-9A-Fa-f]{4})", match.group())]
            decoded = _printable_str(_decode_u_units(units))
        except (ValueError, OverflowError):
            continue
        if decoded is not None:
            found.append(decoded)
    return _dedupe(found)


@dataclass(frozen=True)
class Transform:
    name: str
    encode: Callable[[str], str]
    decode: Callable[[str], list[str]]
    # True when read.decoders already covers this channel with a built-in.
    builtin: bool = False


TRANSFORMS: dict[str, Transform] = {
    item.name: item
    for item in (
        Transform("plain", _plain_encode, _plain_decode, builtin=True),
        Transform("base64", _b64_encode, _b64_decode, builtin=True),
        Transform("hex", _hex_encode, _hex_decode, builtin=True),
        Transform("rot13", _rot13_encode, _rot13_decode),
        Transform("zero_width_binary", _zero_width_binary_encode, _zero_width_binary_decode),
        Transform("bidi", _bidi_encode, _bidi_decode),
        Transform("html_comment", _html_comment_encode, _html_comment_decode, builtin=True),
        Transform("unicode_tags", _tags_encode, _tags_decode, builtin=True),
        Transform("variation_selectors", _variation_encode, _variation_decode, builtin=True),
        Transform("markdown_image", _markdown_image_encode, _markdown_image_decode),
        Transform("js_eval", _js_eval_encode, _js_eval_decode),
        Transform("js_escapes", _js_escapes_encode, _js_escapes_decode),
    )
}

# Channels the READ plugin registers: everything the built-ins do not cover.
DECODER_TRANSFORMS: tuple[str, ...] = tuple(
    name for name, transform in TRANSFORMS.items() if not transform.builtin
)


def encode_seed(seed: str, transform: str = "plain") -> str:
    try:
        codec = TRANSFORMS[transform]
    except KeyError:
        raise KeyError(
            f"unknown transform {transform!r}; known: {', '.join(sorted(TRANSFORMS))}"
        ) from None
    return codec.encode(seed)


def decode_payload(text: str, transform: str) -> list[str]:
    try:
        codec = TRANSFORMS[transform]
    except KeyError:
        raise KeyError(
            f"unknown transform {transform!r}; known: {', '.join(sorted(TRANSFORMS))}"
        ) from None
    return codec.decode(text)
