"""Finding — the record ``read.scan()`` hands to the verdict engine.

JSON contract (docs/verdict.schema.json consumes these via ``to_dict()``):

    file        str    repo-relative path
    chunk_id    int    chunk index within the file (across all decoded views)
    score       float  P(injection), max(model score, judge severity on escalation)
    layer       str    "model" | "judge" | "system"
    evidence    dict   {text, line, decoder?, model_score, note?}
    status      str    "flagged" | "reviewed"   (reviewed = judge cleared it)
    explanation str?   plain-English judge explanation, None when unavailable
    decoded     bool   chunk came from a decoded (hidden-payload) view
    decoder     str?   name of the decoder that produced the view
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

LAYER_MODEL = "model"
LAYER_JUDGE = "judge"
LAYER_SYSTEM = "system"

STATUS_FLAGGED = "flagged"
STATUS_REVIEWED = "reviewed"


@dataclass
class Finding:
    file: str
    chunk_id: int
    score: float
    layer: str
    evidence: dict[str, Any]
    status: str = STATUS_FLAGGED
    explanation: str | None = None
    decoded: bool = False
    decoder: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "chunk_id": self.chunk_id,
            "score": round(self.score, 4),
            "layer": self.layer,
            "evidence": self.evidence,
            "status": self.status,
            "explanation": self.explanation,
            "decoded": self.decoded,
            "decoder": self.decoder,
        }

    @property
    def is_flagged(self) -> bool:
        return self.status == STATUS_FLAGGED


def system_finding(file: str, note: str, chunk_id: int = 0, *,
                   evidence: dict[str, Any] | None = None,
                   decoder: str | None = None) -> Finding:
    """Fail-closed placeholder: something went wrong, so the file stays suspect.

    Used for unreadable files and for chunks whose score could not be produced
    (detector failure mid-scan). Layer "system" tells the verdict engine this
    flag came from BaitWatch itself, not the detector. When the failure is
    about a specific chunk, ``evidence`` keeps its text/line so the reader can
    see what went unchecked.
    """
    return Finding(
        file=file,
        chunk_id=chunk_id,
        score=1.0,
        layer=LAYER_SYSTEM,
        evidence={**(evidence or {"text": "", "line": None}), "note": note},
        status=STATUS_FLAGGED,
        decoded=decoder is not None,
        decoder=decoder,
    )
