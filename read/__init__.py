"""BaitWatch READ side.

Scans a repository for prompt-injection attacks aimed at AI coding agents.

Pipeline: walk (symlink-safe) -> decode hidden payloads -> chunk (<=512 tokens)
-> fine-tuned Llama Prompt Guard 2 detector -> Muse Spark judge (escalate-only)
-> Finding records for the verdict engine.

Contract (docs in README.md)::

    read.scan(path) -> ScanResult  # iterable of Finding{file, chunk_id, score,
                                   # layer, evidence, ...}
"""

from read.config import ReadConfig, config_from_model_config, model_config_path
from read.findings import Finding
from read.scan import ScanResult, scan

__all__ = [
    "ReadConfig",
    "ScanResult",
    "Finding",
    "scan",
    "config_from_model_config",
    "model_config_path",
]

__version__ = "1.0.0"
