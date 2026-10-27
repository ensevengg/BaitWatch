"""Detector: fine-tuned Llama Prompt Guard 2, batched and warm.

The base model outputs label indices with no names; this wrapper maps them
explicitly — index 0 = benign, index 1 = injection — and returns P(injection).

Performance notes (demo machine, RTX 5060 8 GB):
- bf16 on CUDA, float32 on CPU (DeBERTa in bf16 on CPU is unusably slow).
- Chunks are batched largest-first so short chunks don't pad long ones; the
  model stays loaded across ``scores()`` calls, so a daemon/hook process pays
  the load cost once (roadmap: READ scan target < 3 s).
"""

from __future__ import annotations

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from read.config import LABEL_BENIGN, LABEL_INJECTION, MAX_POSITION_EMBEDDINGS


class Detector:
    def __init__(self, model_path, device: str | None = None,
                 batch_size: int = 64, max_length: int = 512,
                 dtype: torch.dtype | None = None):
        self.model_path = str(model_path)
        if device is None:
            device = "cuda" if torch.cuda.is_available() else "cpu"
        self.device = device
        self.batch_size = batch_size
        self.max_length = min(max_length, MAX_POSITION_EMBEDDINGS)
        if dtype is None:
            dtype = torch.bfloat16 if device == "cuda" else torch.float32
        self.dtype = dtype

        self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        model = AutoModelForSequenceClassification.from_pretrained(
            self.model_path, dtype=self.dtype)
        self.model = model.to(device).eval()
        # Prompt Guard 2 ships no label names in config.json — pin the mapping.
        self.model.config.id2label = {0: LABEL_BENIGN, 1: LABEL_INJECTION}
        self.model.config.label2id = {LABEL_BENIGN: 0, LABEL_INJECTION: 1}

    @property
    def label_map(self) -> dict[int, str]:
        return {0: LABEL_BENIGN, 1: LABEL_INJECTION}

    @torch.inference_mode()
    def scores(self, texts: list[str]) -> np.ndarray:
        """P(injection) per text, order preserved."""
        if not texts:
            return np.empty(0, dtype=np.float32)
        # No global padding: chunks are sorted longest-first and each batch is
        # padded to its own longest member, so short chunks cost what they are.
        enc = self.tokenizer(list(texts), padding=False, truncation=True,
                             max_length=self.max_length)
        lengths = [len(ids) for ids in enc["input_ids"]]
        order = sorted(range(len(texts)), key=lambda i: -lengths[i])

        scores = torch.empty(len(texts), dtype=torch.float32)
        for i in range(0, len(texts), self.batch_size):
            idx = order[i: i + self.batch_size]
            batch = self.tokenizer.pad(
                {k: [v[j] for j in idx] for k, v in enc.items()},
                padding=True, return_tensors="pt").to(self.device)
            logits = self.model(**batch).logits
            probs = torch.softmax(logits.float(), dim=-1)[:, 1]
            for pos, j in enumerate(idx):
                scores[j] = probs[pos]
        return scores.numpy()

    def score(self, text: str) -> float:
        return float(self.scores([text])[0])
