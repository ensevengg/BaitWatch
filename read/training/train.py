"""Fine-tune Prompt Guard 2 as the BaitWatch detector.

Roadmap D2 v1: 22M, frozen encoder + head, bf16. ``--mode full`` (v2, D4)
unfreezes the encoder at a low LR. Class weights compensate the benign-heavy
seed set; the threshold is chosen afterwards on the *validation* split only
(read.training.tune_threshold) — never on test.

    python -m read.training.train --data-dir <dir> --out-dir <dir> [--smoke-steps N]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import re
import time
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset

from read.config import DEFAULT_MODEL_DIRS
from read.data.schema import SPLIT_TRAIN, SPLIT_VAL, read_parquet
from read.training.tracking import TRAIN_EXPERIMENT, MlflowRun
from read.training.tracking import val_metrics as val_metrics_for_tracking


class TextDataset(Dataset):
    def __init__(self, rows):
        self.texts = [r.text for r in rows]
        self.labels = [r.label for r in rows]

    def __len__(self) -> int:
        return len(self.texts)

    def __getitem__(self, i: int):
        return self.texts[i], self.labels[i]


class Collator:
    """Picklable collate so DataLoader workers can use it."""

    def __init__(self, tokenizer, max_length: int = 512):
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __call__(self, batch):
        texts, labels = zip(*batch)
        enc = self.tokenizer(list(texts), padding=True, truncation=True,
                             max_length=self.max_length, return_tensors="pt")
        return enc, torch.tensor(labels, dtype=torch.long)


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def freeze_encoder(model) -> list[str]:
    """Freeze everything except the classification head; returns trainable names."""
    trainable = []
    for name, param in model.named_parameters():
        if name.startswith(("classifier.", "pooler.")):
            param.requires_grad_(True)
            trainable.append(name)
        else:
            param.requires_grad_(False)
    return trainable


def _is_embedding_param(name: str) -> bool:
    return "embeddings" in name.split(".")


def freeze_embeddings(model) -> list[str]:
    """Freeze every ``*.embeddings.*`` parameter; returns the frozen names."""
    frozen = []
    for name, param in model.named_parameters():
        if _is_embedding_param(name):
            param.requires_grad_(False)
            frozen.append(name)
    return frozen


_LAYER_RE = re.compile(r"encoder\.layer\.(\d+)\.")


def _num_layers(model) -> int:
    cfg_layers = getattr(getattr(model, "config", None), "num_hidden_layers", None)
    if cfg_layers:
        return int(cfg_layers)
    found = []
    for name, _ in model.named_parameters():
        m = _LAYER_RE.search(name)
        if m:
            found.append(int(m.group(1)))
    return (max(found) + 1) if found else 0


def _no_decay(name: str) -> bool:
    return name.endswith(".bias") or name.endswith("LayerNorm.weight")


def build_param_groups(model, lr: float, llrd: float = 1.0,
                       weight_decay: float = 0.01) -> list[dict]:
    """Optimizer param groups with optional layer-wise LR decay.

    Classifier and pooler get ``lr``. Encoder layer ``i`` (0-based, ``L``
    layers) gets ``lr * llrd ** (L - i)``. Encoder-level shared params
    (``encoder.rel_embeddings``, ``encoder.LayerNorm``) get layer 0's rate;
    unfrozen embeddings get ``lr * llrd ** (L + 1)``. Biases and LayerNorm
    weights get no weight decay, everything else gets ``weight_decay``.
    With ``llrd == 1.0`` a single group is returned so the default recipe
    is exactly the pre-LLRD optimizer.
    """
    trainable = [(n, p) for n, p in model.named_parameters() if p.requires_grad]
    if llrd == 1.0:
        return [{"params": [p for _, p in trainable], "lr": lr,
                 "weight_decay": weight_decay}]
    n_layers = _num_layers(model)

    def lr_for(name: str) -> float:
        if name.startswith(("classifier.", "pooler.")) or ".classifier." in name \
                or ".pooler." in name:
            return lr
        m = _LAYER_RE.search(name)
        if m:
            return lr * llrd ** (n_layers - int(m.group(1)))
        if _is_embedding_param(name):
            return lr * llrd ** (n_layers + 1)
        if "encoder." in name:
            return lr * llrd ** n_layers
        return lr

    buckets: dict[tuple[float, float], list] = {}
    order: list[tuple[float, float]] = []
    for name, param in trainable:
        key = (lr_for(name), 0.0 if _no_decay(name) else weight_decay)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(param)
    order.sort(key=lambda k: (k[0], k[1]))
    return [{"params": buckets[k], "lr": k[0], "weight_decay": k[1]} for k in order]


def energy_loss(logits, labels, weight: float, margin: float) -> torch.Tensor:
    """Energy penalty on label-0 rows: ``weight * mean(relu(-E - margin)**2)``.

    ``E = -logsumexp(logits)`` so ``-E - margin = logsumexp(logits) - margin``.
    Returns zero when ``weight`` is 0 or the batch has no label-0 rows.
    """
    if weight == 0:
        return torch.zeros((), dtype=logits.dtype, device=logits.device)
    mask = labels == 0
    if not bool(mask.any()):
        return torch.zeros((), dtype=logits.dtype, device=logits.device)
    neg_e = torch.logsumexp(logits.float(), dim=-1)
    penalty = torch.relu(neg_e[mask] - float(margin)) ** 2
    return float(weight) * penalty.mean()


def class_weights(labels: list[int], device: str) -> torch.Tensor:
    counts = np.bincount(labels, minlength=2).astype(np.float64)
    weights = counts.sum() / (2.0 * np.maximum(counts, 1))
    weights /= weights.mean()          # keep the mean weight at 1
    return torch.tensor(weights, dtype=torch.float32, device=device)


@torch.no_grad()
def quick_val(model, loader, device) -> dict:
    from sklearn.metrics import average_precision_score

    model.eval()
    losses, all_scores, all_labels = [], [], []
    for enc, labels in loader:
        enc = {k: v.to(device) for k, v in enc.items()}
        labels = labels.to(device)
        out = model(**enc, labels=labels)
        losses.append(out.loss.item() * len(labels))
        probs = torch.softmax(out.logits.float(), dim=-1)[:, 1]
        all_scores.append(probs.cpu().numpy())
        all_labels.append(labels.cpu().numpy())
    scores = np.concatenate(all_scores)
    labels = np.concatenate(all_labels)
    pred = (scores >= 0.5).astype(int)
    tp = int(((pred == 1) & (labels == 1)).sum())
    fp = int(((pred == 1) & (labels == 0)).sum())
    fn = int(((pred == 0) & (labels == 1)).sum())
    return {
        "loss": sum(losses) / len(labels),
        "average_precision": float(average_precision_score(labels, scores)),
        "recall@0.5": tp / max(1, tp + fn),
        "precision@0.5": tp / max(1, tp + fp),
        "fpr@0.5": fp / max(1, int((labels == 0).sum())),
    }


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def train(data_dir: Path, base_model: Path, out_dir: Path,
          epochs: int = 3, batch_size: int = 32, lr: float | None = None,
          mode: str = "head", seed: int = 42, smoke_steps: int | None = None,
          num_workers: int = 2, grad_accum: int = 1,
          freeze_embeddings_flag: bool = False, llrd: float = 1.0,
          energy_weight: float = 0.0, energy_margin: float | None = None,
          label_smoothing: float = 0.0, grad_checkpointing: bool = False,
          tracker=None) -> dict:
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, \
        get_linear_schedule_with_warmup

    set_seed(seed)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    if mode == "head" and lr is None:
        lr = 5e-4
    if mode == "full" and lr is None:
        lr = 2e-5

    tokenizer = AutoTokenizer.from_pretrained(str(base_model))
    model = AutoModelForSequenceClassification.from_pretrained(
        str(base_model), dtype=torch.float32)
    # Label names are absent from Prompt Guard 2's config — pin them (tests
    # assert this mapping against the sanity strings).
    model.config.id2label = {0: "benign", 1: "injection"}
    model.config.label2id = {"benign": 0, "injection": 1}
    model.to(device)

    if energy_margin is None:
        energy_margin = 0.0
    trainable_names = [] if mode == "full" else freeze_encoder(model)
    if freeze_embeddings_flag:
        freeze_embeddings(model)
    if grad_checkpointing:
        model.gradient_checkpointing_enable()
    if mode == "full":
        trainable_names = [n for n, p in model.named_parameters() if p.requires_grad]
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    train_rows = read_parquet(Path(data_dir) / "train.parquet")
    val_rows = read_parquet(Path(data_dir) / "val.parquet")
    train_ds = TextDataset(train_rows)
    val_ds = TextDataset(val_rows)
    collate = Collator(tokenizer)
    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True,
                              collate_fn=collate, num_workers=num_workers,
                              drop_last=False, pin_memory=(device == "cuda"))
    val_loader = DataLoader(val_ds, batch_size=batch_size * 2, shuffle=False,
                            collate_fn=collate, num_workers=num_workers)

    weights = class_weights([r.label for r in train_rows], device)
    optimizer = torch.optim.AdamW(build_param_groups(model, lr, llrd), lr=lr)
    total_steps = (math.ceil(len(train_loader) / grad_accum) * epochs
                   if smoke_steps is None else smoke_steps)
    scheduler = get_linear_schedule_with_warmup(
        optimizer, num_warmup_steps=max(10, int(0.05 * total_steps)),
        num_training_steps=total_steps)
    loss_fn = torch.nn.CrossEntropyLoss(weight=weights, label_smoothing=label_smoothing)

    autocast_dtype = torch.bfloat16 if device == "cuda" else None
    history = []
    step = 0
    micro = 0
    started = time.time()
    model.train()
    done = False
    for epoch in range(epochs):
        running = 0.0
        optimizer.zero_grad(set_to_none=True)
        for enc, labels in train_loader:
            enc = {k: v.to(device, non_blocking=True) for k, v in enc.items()}
            labels = labels.to(device, non_blocking=True)
            with torch.autocast("cuda", dtype=autocast_dtype, enabled=autocast_dtype is not None):
                out = model(**enc)
                logits = out.logits.float()
                loss = (loss_fn(logits, labels)
                        + energy_loss(logits, labels, energy_weight,
                                      float(energy_margin))) / grad_accum
            loss.backward()
            running += loss.item() * grad_accum
            micro += 1
            if micro % grad_accum == 0:
                torch.nn.utils.clip_grad_norm_(
                    [p for p in model.parameters() if p.requires_grad], 1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad(set_to_none=True)
                step += 1
                if step % 50 == 0:
                    print(f"epoch {epoch + 1} step {step}/{total_steps} "
                          f"loss {running / (50 * grad_accum):.4f}", flush=True)
                    if tracker:
                        tracker.log_metrics({"train/loss": running / (50 * grad_accum),
                                             "lr": max(scheduler.get_last_lr()),
                                             "epoch": epoch + 1}, step=step)
                    running = 0.0
                if smoke_steps is not None and step >= smoke_steps:
                    done = True
                    break

        val_metrics = quick_val(model, val_loader, device) if val_rows else {}
        model.train()   # quick_val switched to eval mode; later epochs need dropout back
        history.append({"epoch": epoch + 1, "val": val_metrics})
        print(f"epoch {epoch + 1} done: {val_metrics}", flush=True)
        if tracker:
            tracker.log_metrics(val_metrics_for_tracking(val_metrics), step=step)
        epoch_dir = out_path / f"epoch{epoch + 1}"
        epoch_dir.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(epoch_dir)
        tokenizer.save_pretrained(epoch_dir)
        if done:
            break

    out_dir = out_path
    model.save_pretrained(out_dir)
    tokenizer.save_pretrained(out_dir)

    meta = {
        "base_model": str(base_model),
        "base_model_sha256": sha256_file(Path(base_model) / "model.safetensors"),
        "data_dir": str(data_dir),
        "data_manifest_sha256": (sha256_file(Path(data_dir) / "manifest.json")
                                 if (Path(data_dir) / "manifest.json").exists() else None),
        "mode": mode,
        "epochs": epoch + 1,
        "steps": step,
        "batch_size": batch_size,
        "grad_accum": grad_accum,
        "effective_batch": batch_size * grad_accum,
        "lr": lr,
        "seed": seed,
        "freeze_embeddings": bool(freeze_embeddings_flag),
        "llrd": llrd,
        "energy_weight": energy_weight,
        "energy_margin": float(energy_margin),
        "label_smoothing": label_smoothing,
        "grad_checkpointing": bool(grad_checkpointing),
        "peak_gpu_memory_allocated": (
            int(torch.cuda.max_memory_allocated()) if device == "cuda" else 0),
        "trainable_params": trainable_names,
        "class_weights": [round(float(w), 3) for w in weights.cpu()],
        "smoke": smoke_steps is not None,
        "history": history,
        "elapsed_s": round(time.time() - started, 1),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    (out_dir / "checkpoint_meta.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8")
    if tracker:
        tracker.log_metrics({"peak_gpu_memory_gib": meta["peak_gpu_memory_allocated"] / 2**30,
                             "elapsed_min": meta["elapsed_s"] / 60}, step=step)
    return meta


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="read.training.train")
    parser.add_argument("--data-dir",
                        default=str(Path.home() / ".local/share/baitwatch/data"))
    parser.add_argument("--base-model",
                        default=str(next(
                            (p for p in DEFAULT_MODEL_DIRS if p.exists()),
                            DEFAULT_MODEL_DIRS[0],
                        )))
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=None)
    parser.add_argument("--mode", choices=("head", "full"), default="head")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--smoke-steps", type=int, default=None,
                        help="stop after N steps (D2 20-batch smoke test)")
    parser.add_argument("--num-workers", type=int, default=0,
                        help="DataLoader workers; 0 is the robust default on "
                             "this machine (fork + CUDA broke mid-run once)")
    parser.add_argument("--grad-accum", type=int, default=1,
                        help="micro-batches per optimizer step (OOM relief)")
    parser.add_argument("--freeze-embeddings", action="store_true")
    parser.add_argument("--llrd", type=float, default=1.0)
    parser.add_argument("--energy-weight", type=float, default=0.0)
    parser.add_argument("--energy-margin", type=float, default=None)
    parser.add_argument("--label-smoothing", type=float, default=0.0)
    parser.add_argument("--grad-checkpointing", action="store_true")
    parser.add_argument("--mlflow-uri", default=None,
                        help="MLflow tracking server (default: $MLFLOW_TRACKING_URI; "
                             "unset = no MLflow logging)")
    parser.add_argument("--mlflow-experiment", default=TRAIN_EXPERIMENT)
    args = parser.parse_args(argv)
    tracker = MlflowRun.start(args.mlflow_uri, args.mlflow_experiment, Path(args.out_dir).name,
                              params={k: v for k, v in vars(args).items()
                                      if not k.startswith("mlflow")})
    try:
        meta = train(Path(args.data_dir), Path(args.base_model), Path(args.out_dir),
                     epochs=args.epochs, batch_size=args.batch_size, lr=args.lr,
                     mode=args.mode, seed=args.seed, smoke_steps=args.smoke_steps,
                     num_workers=args.num_workers, grad_accum=args.grad_accum,
                     freeze_embeddings_flag=args.freeze_embeddings, llrd=args.llrd,
                     energy_weight=args.energy_weight, energy_margin=args.energy_margin,
                     label_smoothing=args.label_smoothing,
                     grad_checkpointing=args.grad_checkpointing, tracker=tracker)
    except BaseException:
        if tracker:
            tracker.finish(ok=False)
        raise
    if tracker:
        tracker.finish()
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
