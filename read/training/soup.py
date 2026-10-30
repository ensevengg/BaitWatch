"""Average checkpoints fine-tuned from the same base model.

    python -m read.training.soup --out DIR CKPT [CKPT ...]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import torch


def _load_state_dict(ckpt: Path) -> dict[str, torch.Tensor]:
    ckpt = Path(ckpt)
    safetensors = ckpt / "model.safetensors"
    if safetensors.exists():
        from safetensors.torch import load_file

        return load_file(str(safetensors))
    bin_path = ckpt / "pytorch_model.bin"
    if bin_path.exists():
        return torch.load(str(bin_path), map_location="cpu", weights_only=True)
    # Fall back to the model loader (handles sharded checkpoints).
    from transformers import AutoModelForSequenceClassification

    model = AutoModelForSequenceClassification.from_pretrained(
        str(ckpt), dtype=torch.float32)
    return model.state_dict()


def average_state_dicts(
        state_dicts: list[dict[str, torch.Tensor]]) -> dict[str, torch.Tensor]:
    """Mean of float tensors; refuses mismatched keys, shapes or int tensors."""
    if not state_dicts:
        raise ValueError("no checkpoints to average")
    ref = state_dicts[0]
    ref_keys = set(ref)
    for idx, sd in enumerate(state_dicts[1:], start=1):
        if set(sd) != ref_keys:
            missing = sorted(ref_keys - set(sd))
            extra = sorted(set(sd) - ref_keys)
            raise ValueError(
                f"checkpoint {idx} key mismatch: missing={missing[:5]} extra={extra[:5]}")
        for key in ref_keys:
            if sd[key].shape != ref[key].shape:
                raise ValueError(
                    f"checkpoint {idx} shape mismatch for {key}: "
                    f"{tuple(sd[key].shape)} vs {tuple(ref[key].shape)}")
            if not ref[key].is_floating_point() and not torch.equal(sd[key], ref[key]):
                raise ValueError(f"checkpoint {idx} non-float mismatch for {key}")
    averaged: dict[str, torch.Tensor] = {}
    for key in ref:
        if ref[key].is_floating_point():
            total = ref[key].to(torch.float32).clone()
            for sd in state_dicts[1:]:
                total += sd[key].to(torch.float32)
            averaged[key] = total / len(state_dicts)
        else:
            averaged[key] = ref[key].clone()
    return averaged


def make_soup(checkpoints: list[Path], out_dir: Path) -> Path:
    """Average ``checkpoints`` into ``out_dir``; returns ``out_dir``."""
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    checkpoints = [Path(c) for c in checkpoints]
    if not checkpoints:
        raise ValueError("no checkpoints to average")
    state_dicts = [_load_state_dict(c) for c in checkpoints]
    averaged = average_state_dicts(state_dicts)
    model = AutoModelForSequenceClassification.from_pretrained(
        str(checkpoints[0]), dtype=torch.float32)
    model.load_state_dict(averaged, strict=True)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(out_dir)
    tokenizer = AutoTokenizer.from_pretrained(str(checkpoints[0]))
    tokenizer.save_pretrained(out_dir)
    meta = {"inputs": [str(c) for c in checkpoints], "count": len(checkpoints)}
    (out_dir / "soup_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return out_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.training.soup")
    parser.add_argument("--out", required=True)
    parser.add_argument("checkpoints", nargs="+")
    args = parser.parse_args(argv)
    make_soup([Path(c) for c in args.checkpoints], Path(args.out))
    print(json.dumps({"out": args.out, "inputs": args.checkpoints}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
