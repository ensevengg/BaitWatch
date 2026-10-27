"""Obfuscation synthesizer: seeds, transforms and file-voice templates."""

from __future__ import annotations

from attacks.synth.transforms import (
    DECODER_TRANSFORMS,
    TRANSFORMS,
    Transform,
    decode_payload,
    encode_seed,
)

__all__ = ["DECODER_TRANSFORMS", "TRANSFORMS", "Transform", "decode_payload", "encode_seed"]
