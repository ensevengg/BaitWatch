"""External decoder plugin for ``read.scan``.

``read.decoders.load_external_decoders`` loads this exact file
(``<repo_root>/attacks/decoders.py``) during a scan and calls
``register(registry)``.  It adds **only the channels the built-ins miss**.
As of READ v1.5f the built-ins cover base64, base32, hex, HTML comments and
entities, invisible-character stripping, Unicode tags, variation selectors,
URL encoding, ROT13 and reversed text.  The plugin therefore adds:

    zero_width_binary, bidi, markdown_image, js_eval, js_escapes

``rot13`` stays in the transform table because ``js_eval`` uses it, but the
plugin no longer registers it.  ``BUILTIN_NAMES`` mirrors ``read/decoders.py``;
``tests/attacks/test_decoders.py`` fails if the two drift apart.

Registering a built-in again would produce duplicate views and double scan
cost for no new coverage.

The decode logic lives in :mod:`attacks.synth.transforms` so the encoder and
the decoder can never drift apart: ``decode(encode(seed))`` is tested for
every transform in ``tests/attacks/test_transforms.py``.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Protocol


class _Decoder(Protocol):
    name: str

    def decode(self, text: str) -> list[str]: ...


# Names returned by read.decoders.builtin_decoders().  Keep in sync: the
# plugin is loaded by path, so it cannot import that module reliably, and
# registering a duplicate would silently double every decode view.
BUILTIN_NAMES = frozenset(
    {
        "base64",
        "base32",
        "hex",
        "html_comment",
        "html_entity",
        "zero_width",
        "variation_selector",
        "unicode_tags",
        "url_encoding",
        "rot13",
        "reversed",
    }
)


def _load_transforms():
    """Import the transform table, even when ``attacks`` is not on sys.path.

    The scan loads this file by path with ``spec_from_file_location``, from a
    process whose working directory is not necessarily the BaitWatch root.
    The relative fallback keeps the plugin self-contained without ever
    importing from the *scanned* repository.
    """
    try:
        from attacks.synth.transforms import DECODER_TRANSFORMS, TRANSFORMS

        return TRANSFORMS, DECODER_TRANSFORMS
    except ModuleNotFoundError:
        path = Path(__file__).resolve().parent / "synth" / "transforms.py"
        spec = importlib.util.spec_from_file_location("_baitwatch_transforms", path)
        if spec is None or spec.loader is None:  # pragma: no cover - packaging bug
            raise
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module.TRANSFORMS, module.DECODER_TRANSFORMS


class TransformDecoder:
    """Expose one row of the transform table as a READ decoder."""

    join_segments = True

    def __init__(self, name: str, decode, budget_factory=None) -> None:
        self.name = name
        self._decode = decode
        self._budget_factory = budget_factory
        # Set when this call had to truncate input or output.  produce_views
        # turns it into decoder evidence, which makes the scan incomplete.
        self.budget_spent = False

    def decode(self, text: str) -> list[str]:
        self.budget_spent = False
        if self._budget_factory is None:
            return self._decode(text)
        budget = self._budget_factory()
        source, spent_input = budget.input(text)
        items, spent_output = budget.output(self._decode(source))
        self.budget_spent = spent_input or spent_output
        return items


def register(registry: list[_Decoder]) -> None:
    transforms, names = _load_transforms()
    budget_factory = getattr(
        sys.modules.get(transforms[names[0]].decode.__module__), "DecodeBudget", None
    )
    existing = {getattr(item, "name", None) for item in registry} | BUILTIN_NAMES
    for name in names:
        if name in existing:
            continue
        registry.append(TransformDecoder(name, transforms[name].decode, budget_factory))
