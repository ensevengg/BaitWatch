"""Load ``read.decoders`` without importing the torch-heavy ``read`` package.

``read/__init__.py`` re-exports the scanner, which imports torch at module
load.  The attack harness, the hooks and the CPU test suite only need the
decoder registry, so they load that single file by path — the same mechanism
``read.scan`` uses for the external plugin.
"""

from __future__ import annotations

import importlib.util
import sys
from functools import lru_cache
from pathlib import Path

__all__ = [
    "REPO_ROOT",
    "builtin_decoders",
    "external_decoders",
    "has_suspicious_invisibles",
    "produce_views",
]

REPO_ROOT = Path(__file__).resolve().parents[1]
_DECODERS_PATH = REPO_ROOT / "read" / "decoders.py"


@lru_cache(maxsize=1)
def _module():
    if not _DECODERS_PATH.exists():
        raise FileNotFoundError(f"decoder module not found: {_DECODERS_PATH}")
    spec = importlib.util.spec_from_file_location("_baitwatch_read_decoders", _DECODERS_PATH)
    if spec is None or spec.loader is None:  # pragma: no cover - packaging bug
        raise ImportError(f"cannot load {_DECODERS_PATH}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves annotations through sys.modules[cls.__module__]
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def builtin_decoders() -> list:
    return _module().builtin_decoders()


def external_decoders() -> list:
    return _module().load_external_decoders(search_root=REPO_ROOT)


def has_suspicious_invisibles(text: str) -> bool:
    return _module().has_suspicious_invisibles(text)


def produce_views(text: str, decoders: list | None = None, **kwargs):
    return _module().produce_views(text, decoders, **kwargs)
