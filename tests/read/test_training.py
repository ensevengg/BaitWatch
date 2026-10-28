"""Training-side guards: pin gates must not be derived from the model pinned."""

from __future__ import annotations

import json


def _make_checkpoint(tmp_path):
    ckpt = tmp_path / "ckpt"
    ckpt.mkdir()
    (ckpt / "model.safetensors").write_bytes(b"weights")
    (ckpt / "thresholds.json").write_text(json.dumps(
        {"flag_threshold": 0.85, "review_low": 0.5, "hard_high": 0.9}))
    (ckpt / "checkpoint_meta.json").write_text(json.dumps(
        {"base_model": "base", "mode": "full", "finished_at": "now"}))
    results = tmp_path / "results.json"
    results.write_text(json.dumps({
        "injecagent": {"overall": {"recall_injected_response": 0.61}},
        "benign_corpus": {"file_fpr": 0.057},
    }))
    return ckpt, results


def _write_previous_pin(tmp_path, recall=0.70, fpr=0.04):
    prev = tmp_path / "model_config.json"
    prev.write_text(json.dumps({
        "tag": "prev",
        "checkpoint_path": "/old",
        "quality_gates": {
            "measured": {"recall_injected_response": recall, "file_fpr": fpr},
            "min_recall_injected_response": 0.5,
            "max_benign_file_fpr": 0.9,
        },
    }))
    return prev


def test_pin_gates_come_from_previous_pin_not_new_model(tmp_path, monkeypatch):
    import read.training.pin as pin_mod

    ckpt, results = _make_checkpoint(tmp_path)
    out = _write_previous_pin(tmp_path, recall=0.70, fpr=0.04)
    monkeypatch.setattr(pin_mod, "MODEL_CONFIG_PATH", out)

    doc = pin_mod.pin(ckpt, "vX", results_path=results)
    gates = doc["quality_gates"]
    # New model's own numbers are recorded only.
    assert gates["measured"] == {"recall_injected_response": 0.61, "file_fpr": 0.057}
    # No drop vs the previous checkpoint: gates are its measured numbers,
    # not 0.61-0.02 / 0.057+0.005, and not the 85% roadmap bar.
    assert gates["min_recall_injected_response"] == 0.70
    assert gates["max_benign_file_fpr"] == 0.04


def test_pin_hard_fpr_ceiling_only_when_requested(tmp_path, monkeypatch):
    import read.training.pin as pin_mod

    ckpt, results = _make_checkpoint(tmp_path)
    out = _write_previous_pin(tmp_path, recall=0.70, fpr=0.04)
    monkeypatch.setattr(pin_mod, "MODEL_CONFIG_PATH", out)

    doc = pin_mod.pin(ckpt, "vX", results_path=results, hard_fpr_ceiling=True)
    assert doc["quality_gates"]["max_benign_file_fpr"] == pin_mod.HARD_MAX_FILE_FPR == 0.02
    assert doc["quality_gates"]["min_recall_injected_response"] == 0.70


def test_pin_explicit_gates_override_previous_and_ceiling(tmp_path, monkeypatch):
    import read.training.pin as pin_mod

    ckpt, results = _make_checkpoint(tmp_path)
    out = _write_previous_pin(tmp_path)
    monkeypatch.setattr(pin_mod, "MODEL_CONFIG_PATH", out)

    doc = pin_mod.pin(ckpt, "vX", min_recall=0.9, max_fpr=0.5,
                      results_path=results, hard_fpr_ceiling=True)
    assert doc["quality_gates"]["min_recall_injected_response"] == 0.9
    assert doc["quality_gates"]["max_benign_file_fpr"] == 0.5


def test_pin_without_previous_pin_sets_no_derived_gates(tmp_path, monkeypatch):
    import read.training.pin as pin_mod

    ckpt, results = _make_checkpoint(tmp_path)
    out = tmp_path / "model_config.json"   # does not exist yet
    monkeypatch.setattr(pin_mod, "MODEL_CONFIG_PATH", out)

    doc = pin_mod.pin(ckpt, "vX", results_path=results)
    gates = doc["quality_gates"]
    assert gates["measured"] == {"recall_injected_response": 0.61, "file_fpr": 0.057}
    assert "min_recall_injected_response" not in gates
    assert "max_benign_file_fpr" not in gates
