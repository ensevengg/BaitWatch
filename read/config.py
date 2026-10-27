"""Configuration for the READ scan: thresholds, limits, model resolution.

Thresholds and the pinned checkpoint live in ``read/model_config.json`` once
training has pinned them (``python -m read.training.pin``); before that the
defaults below apply.  Every limit is overridable per call via :class:`ReadConfig`.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
MODEL_CONFIG_PATH = PACKAGE_DIR / "model_config.json"

DEFAULT_MODEL_DIRS = (
    Path("/mnt/d/hf_models/Llama-Prompt-Guard-2-22M"),
    Path("/mnt/d/hf_models/Llama-Prompt-Guard-2-86M"),
)

# Prompt Guard 2's config.json ships no label names: index 0 is benign,
# index 1 is injection (verified against the sanity strings in tests).
LABEL_BENIGN = "benign"
LABEL_INJECTION = "injection"

MAX_POSITION_EMBEDDINGS = 512  # model config; chunks must fit including specials


@dataclass
class WalkerConfig:
    max_file_bytes: int = 262_144          # larger text files are scanned as a prefix, marked truncated
    max_files: int = 5_000                 # beyond this the scan is marked truncated (fail-closed upstream)
    binary_sniff_bytes: int = 8_192
    # .vscode/.idea are NOT skipped: workspace settings/tasks are a documented
    # agent attack surface (auto-approve flags, folder-open tasks).
    excluded_dirs: frozenset[str] = frozenset({
        ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
        ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
        "dist", "build", ".next", ".parcel-cache", "target",
    })
    binary_extensions: frozenset[str] = frozenset({
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff", ".svgz",
        ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
        ".whl", ".egg", ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".obj",
        ".pyc", ".pyo", ".class", ".wasm", ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".wav", ".flac", ".ogg", ".webm",
        ".db", ".sqlite", ".sqlite3", ".mdb", ".parquet", ".arrow", ".feather",
        ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".safetensors", ".gguf", ".onnx",
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".ttc",
        ".ai", ".psd", ".sketch",              # design files: binary streams
    })


@dataclass
class JudgeConfig:
    enabled: bool = True
    # Tried in order; the first endpoint whose request succeeds wins. The local
    # llama-server fallback keeps the verdict fail-closed when the API is down.
    # Env overrides are resolved at construction (not import) so runtime
    # configuration actually takes effect.
    endpoints: tuple[dict, ...] | None = None
    timeout_s: float = 10.0                # per judge call, roadmap D5
    concurrency: int = 4                   # parallel judge calls per scan
    max_calls_per_scan: int = 12
    max_tokens_per_scan: int = 16_000      # judge input+output token budget per scan
    max_chunk_chars: int = 4_000           # never send more than this to the judge
    usd_cap: float = 120.0                 # hard cap per API key, enforced in code
    ledger_path: Path = field(
        default_factory=lambda: Path(
            os.environ.get("BAITWATCH_SPEND_LEDGER",
                           str(Path.home() / ".local/state/baitwatch/spend.json"))
        )
    )
    # Rough per-1k-token prices used only for the local spend estimate; the real
    # bill is Meta's, so the cap is deliberately conservative.
    usd_per_1k_input: float = 0.02
    usd_per_1k_output: float = 0.08

    def __post_init__(self) -> None:
        if self.endpoints is None:
            self.endpoints = (
                {
                    "name": "muse_spark",
                    "base_url": os.environ.get("BAITWATCH_JUDGE_BASE_URL",
                                               "https://api.llama.com/compatible/v1"),
                    "model": os.environ.get("BAITWATCH_JUDGE_MODEL", "muse-spark"),
                    "api_key_env": "META_API_KEY",
                },
                {
                    "name": "llama32_3b_local",
                    "base_url": os.environ.get("BAITWATCH_FALLBACK_BASE_URL",
                                               "http://127.0.0.1:8080/v1"),
                    "model": os.environ.get("BAITWATCH_FALLBACK_MODEL", "llama3.2-3b"),
                    "api_key_env": None,
                },
            )


@dataclass
class ReadConfig:
    model_path: Path | None = None         # resolved lazily, see resolve_model_path()
    flag_threshold: float = 0.8            # >= flagged by the model alone
    review_low: float = 0.3                # [review_low, flag_threshold) goes to the judge
    hard_high: float = 0.9                 # informational: judge explanation never clears these
    batch_size: int = 64
    max_length: int = 512
    window_tokens: int = 448               # content tokens per chunk (<= max_length - 2 specials)
    overlap_tokens: int = 64
    max_file_tokens: int = 24_000
    max_chunks_per_file: int = 64         # 64*384 covers the 24k-token cap
    max_views_per_file: int = 8           # original + decoded variants, capped
    on_file_error: str = "flag"            # "flag" (fail-closed) or "skip"
    enable_decoders: bool = True
    judge: JudgeConfig = field(default_factory=JudgeConfig)
    walker: WalkerConfig = field(default_factory=WalkerConfig)

    def with_model(self, model_path: Path | str) -> "ReadConfig":
        return replace(self, model_path=Path(model_path))

    @classmethod
    def quick(cls) -> "ReadConfig":
        """Inline-hook preset: agent-config files first, tight caps.

        The walker's priority ordering guarantees AGENTS.md/CLAUDE.md/README
        and .claude settings are scanned before anything else, so the highest
       -risk files are always covered within the budget; everything past the
        caps is reported via stats.truncated_scan / views_dropped and treated
        as incomplete evidence by the verdict engine.
        """
        cfg = cls()
        cfg.walker.max_files = 400
        cfg.max_chunks_per_file = 8
        cfg.max_file_tokens = 8_000
        cfg.batch_size = 128
        # The pinned checkpoint's thresholds, not the class defaults: the
        # hook must judge with the same cutoffs as a full scan.
        return config_from_model_config(cfg)


def model_config_path() -> Path:
    return MODEL_CONFIG_PATH


def load_model_config() -> dict | None:
    """The pinned-checkpoint file written by ``read.training.pin``."""
    if not MODEL_CONFIG_PATH.exists():
        return None
    with open(MODEL_CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


def resolve_model_path(explicit: Path | str | None = None) -> Path:
    """Order: argument > BAITWATCH_MODEL_PATH > pinned config > default dirs."""
    if explicit is not None:
        p = Path(explicit)
        if not p.exists():
            raise FileNotFoundError(f"model path does not exist: {p}")
        return p
    env = os.environ.get("BAITWATCH_MODEL_PATH")
    if env:
        p = Path(env)
        if not p.exists():
            raise FileNotFoundError(f"BAITWATCH_MODEL_PATH does not exist: {p}")
        return p
    pinned = load_model_config()
    if pinned:
        p = Path(pinned["checkpoint_path"])
        if p.exists():
            return p
        # Never fall back silently: the pinned thresholds belong to the pinned
        # checkpoint, and the base model under them is a different detector.
        raise FileNotFoundError(
            f"pinned checkpoint missing: {p} (read/model_config.json, tag "
            f"{pinned.get('tag')!r}). Restore it, re-pin with read.training.pin, "
            "or set BAITWATCH_MODEL_PATH explicitly.")
    for p in DEFAULT_MODEL_DIRS:
        if p.exists():
            return p
    raise FileNotFoundError(
        "No Prompt Guard 2 model found. Set BAITWATCH_MODEL_PATH or run "
        "read.training.pin to pin a trained checkpoint."
    )


def config_from_model_config(cfg: ReadConfig | None = None) -> ReadConfig:
    """ReadConfig seeded with the pinned thresholds, if the pin file exists."""
    cfg = cfg or ReadConfig()
    pinned = load_model_config()
    if not pinned:
        return cfg
    thresholds = pinned.get("thresholds", {})
    return replace(
        cfg,
        flag_threshold=float(thresholds.get("flag_threshold", cfg.flag_threshold)),
        review_low=float(thresholds.get("review_low", cfg.review_low)),
        hard_high=float(thresholds.get("hard_high", cfg.hard_high)),
    )
