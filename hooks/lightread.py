"""Load torch-free parts of ``read`` without importing the ``read`` package.

``read/__init__.py`` imports the scanner and so torch, about 2.5 s. A hook runs on
every tool call, and a cached decision must not pay for that.
"""

from __future__ import annotations

import importlib.util
import sys
from functools import cache
from pathlib import Path
from types import ModuleType

_READ_DIR = Path(__file__).resolve().parents[1] / "read"


@cache
def load(name: str) -> ModuleType:
    """``read/<name>.py`` as a standalone module. It must not import from ``read``."""
    module_name = f"_baitwatch_light_{name}"
    spec = importlib.util.spec_from_file_location(module_name, _READ_DIR / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load read/{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
