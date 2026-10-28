"""Config: model resolution order and pinned-threshold loading."""

from __future__ import annotations

import json

from read import config as rc


def test_resolve_order_explicit_first(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    assert rc.resolve_model_path(real) == real
    import pytest
    with pytest.raises(FileNotFoundError):
        rc.resolve_model_path(tmp_path / "missing")


def test_resolve_env_overrides(monkeypatch, tmp_path):
    fake = tmp_path / "env-model"
    fake.mkdir()
    monkeypatch.setenv("BAITWATCH_MODEL_PATH", str(fake))
    assert rc.resolve_model_path() == fake
    monkeypatch.delenv("BAITWATCH_MODEL_PATH")


def test_resolve_pinned_config(monkeypatch, tmp_path):
    fake = tmp_path / "pinned-model"
    fake.mkdir()
    pin = {"checkpoint_path": str(fake)}
    monkeypatch.setattr(rc, "MODEL_CONFIG_PATH", tmp_path / "model_config.json")
    (tmp_path / "model_config.json").write_text(json.dumps(pin))
    monkeypatch.delenv("BAITWATCH_MODEL_PATH", raising=False)
    monkeypatch.setattr(rc, "DEFAULT_MODEL_DIRS", ())
    assert rc.resolve_model_path() == fake


def test_config_from_pinned_thresholds(monkeypatch, tmp_path):
    pin = {"checkpoint_path": "/nowhere", "thresholds": {
        "flag_threshold": 0.62, "review_low": 0.21, "hard_high": 0.88}}
    monkeypatch.setattr(rc, "MODEL_CONFIG_PATH", tmp_path / "model_config.json")
    (tmp_path / "model_config.json").write_text(json.dumps(pin))
    cfg = rc.config_from_model_config()
    assert (cfg.flag_threshold, cfg.review_low, cfg.hard_high) == (0.62, 0.21, 0.88)


def test_defaults_without_pin(monkeypatch, tmp_path):
    monkeypatch.setattr(rc, "MODEL_CONFIG_PATH", tmp_path / "absent.json")
    cfg = rc.config_from_model_config()
    assert (cfg.flag_threshold, cfg.review_low, cfg.hard_high) == (0.8, 0.3, 0.9)
    assert cfg.walker.max_file_bytes > 0


def test_quick_preset_uses_pinned_thresholds(monkeypatch, tmp_path):
    pin = {"checkpoint_path": "/nowhere", "thresholds": {
        "flag_threshold": 0.85, "review_low": 0.521, "hard_high": 0.9}}
    monkeypatch.setattr(rc, "MODEL_CONFIG_PATH", tmp_path / "model_config.json")
    (tmp_path / "model_config.json").write_text(json.dumps(pin))
    cfg = rc.ReadConfig.quick()
    assert (cfg.flag_threshold, cfg.review_low) == (0.85, 0.521)
    assert cfg.walker.max_files == 400


def test_quick_preset_disables_judge():
    cfg = rc.ReadConfig.quick()
    assert cfg.judge.enabled is False, "the inline hook must not block on judge calls"


def test_windows_pin_reports_the_posix_path(monkeypatch, tmp_path):
    import pytest

    pin = {
        "checkpoint_path": "/home/enseven/.local/share/baitwatch/models/v15f_22m",
        "tag": "v1.5f",
    }
    monkeypatch.setattr(rc, "MODEL_CONFIG_PATH", tmp_path / "model_config.json")
    (tmp_path / "model_config.json").write_text(json.dumps(pin))
    monkeypatch.delenv("BAITWATCH_MODEL_PATH", raising=False)
    monkeypatch.setattr(rc, "_IS_WINDOWS", True)
    with pytest.raises(FileNotFoundError) as exc:
        rc.resolve_model_path()
    message = str(exc.value)
    assert "/home/enseven" in message
    assert "POSIX" in message
    assert "BAITWATCH_MODEL_PATH" in message


def test_missing_pinned_checkpoint_fails_loudly(monkeypatch, tmp_path):
    import pytest

    pin = {"tag": "v9", "checkpoint_path": str(tmp_path / "gone")}
    monkeypatch.setattr(rc, "MODEL_CONFIG_PATH", tmp_path / "model_config.json")
    (tmp_path / "model_config.json").write_text(json.dumps(pin))
    monkeypatch.delenv("BAITWATCH_MODEL_PATH", raising=False)
    base = tmp_path / "base-model"
    base.mkdir()
    monkeypatch.setattr(rc, "DEFAULT_MODEL_DIRS", (base,))
    with pytest.raises(FileNotFoundError, match="pinned checkpoint missing"):
        rc.resolve_model_path()
    monkeypatch.setenv("BAITWATCH_MODEL_PATH", str(base))   # explicit override still works
    assert rc.resolve_model_path() == base
