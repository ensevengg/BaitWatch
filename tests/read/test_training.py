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


def _tiny_model(num_layers=4):
    import torch
    from transformers import DebertaV2Config, DebertaV2ForSequenceClassification

    torch.manual_seed(0)
    cfg = DebertaV2Config(
        vocab_size=99, hidden_size=32, num_hidden_layers=num_layers,
        num_attention_heads=4, intermediate_size=64, type_vocab_size=0,
        max_position_embeddings=64, num_labels=2)
    return DebertaV2ForSequenceClassification(cfg)


def _tiny_tokenizer():
    from tokenizers import Tokenizer, models, pre_tokenizers
    from transformers import PreTrainedTokenizerFast

    vocab = {"[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3, "hello": 4, "world": 5}
    tok = Tokenizer(models.WordLevel(vocab=vocab, unk_token="[UNK]"))
    tok.pre_tokenizer = pre_tokenizers.Whitespace()
    fast = PreTrainedTokenizerFast(
        tokenizer_object=tok, unk_token="[UNK]", pad_token="[PAD]",
        cls_token="[CLS]", sep_token="[SEP]")
    return fast


def test_llrd_lrs_rise_bottom_to_top_and_head_gets_base():
    from read.training.train import build_param_groups

    model = _tiny_model(num_layers=4)
    base_lr, llrd = 0.01, 0.9
    groups = build_param_groups(model, base_lr, llrd)
    lr_by_id = {}
    for g in groups:
        for p in g["params"]:
            lr_by_id[id(p)] = g["lr"]
    lr_by_name = {n: lr_by_id[id(p)] for n, p in model.named_parameters()
                  if p.requires_grad}
    layer_lrs = []
    for i in range(4):
        vals = {v for n, v in lr_by_name.items() if f"encoder.layer.{i}." in n}
        assert len(vals) == 1
        layer_lrs.append(vals.pop())
    assert layer_lrs == sorted(layer_lrs)
    assert layer_lrs[0] < layer_lrs[-1]
    for i, v in enumerate(layer_lrs):
        assert abs(v - base_lr * llrd ** (4 - i)) < 1e-12
    assert lr_by_name["classifier.weight"] == base_lr
    assert lr_by_name["pooler.dense.weight"] == base_lr
    emb_lrs = {v for n, v in lr_by_name.items() if "embeddings" in n.split(".")}
    assert emb_lrs == {base_lr * llrd ** 5}


def test_freeze_embeddings_freezes_exactly_embedding_params():
    from read.training.train import freeze_embeddings

    model = _tiny_model()
    expected = {n for n, _ in model.named_parameters() if "embeddings" in n.split(".")}
    assert expected
    frozen = set(freeze_embeddings(model))
    assert frozen == expected
    for name, param in model.named_parameters():
        assert param.requires_grad == (name not in expected)


def test_energy_loss_weight_zero_past_margin_and_label1():
    import torch

    from read.training.train import energy_loss

    logits = torch.tensor([[5.0, 5.0], [5.0, 5.0]])
    assert float(energy_loss(logits, torch.tensor([0, 0]), 0.0, 0.0)) == 0.0
    assert float(energy_loss(logits, torch.tensor([0, 1]), 0.1, 1.0)) > 0.0
    assert float(energy_loss(logits, torch.tensor([1, 1]), 0.1, 1.0)) == 0.0
    small = torch.tensor([[0.0, 0.0]])
    assert float(energy_loss(small, torch.tensor([0]), 0.1, 10.0)) == 0.0


def test_soup_identical_equals_input_and_mismatched_refused(tmp_path):
    import pytest
    import torch
    from safetensors.torch import load_file

    from read.training.soup import make_soup

    model = _tiny_model()
    tokenizer = _tiny_tokenizer()
    ckpts = []
    for name in ("a", "b"):
        ckpt = tmp_path / name
        model.save_pretrained(ckpt)
        tokenizer.save_pretrained(ckpt)
        ckpts.append(ckpt)
    out = make_soup(ckpts, tmp_path / "soup")
    ref = load_file(str(ckpts[0] / "model.safetensors"))
    avg = load_file(str(out / "model.safetensors"))
    assert set(ref) == set(avg)
    for key in ref:
        assert torch.allclose(ref[key].float(), avg[key].float(), atol=1e-6)
    meta = json.loads((out / "soup_meta.json").read_text())
    assert meta["count"] == 2
    assert meta["inputs"] == [str(c) for c in ckpts]

    other = _tiny_model(num_layers=5)
    bad = tmp_path / "bad"
    other.save_pretrained(bad)
    tokenizer.save_pretrained(bad)
    with pytest.raises(ValueError):
        make_soup([ckpts[0], bad], tmp_path / "soup_bad")


def _fake_mlflow():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    calls = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _reply(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            calls.append(("GET", self.path, None))
            self._reply(404, {"error_code": "RESOURCE_DOES_NOT_EXIST"})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(("POST", self.path, body))
            if self.path.endswith("experiments/create"):
                self._reply(200, {"experiment_id": "7"})
            elif self.path.endswith("runs/create"):
                self._reply(200, {"run": {"info": {"run_id": "r1"}}})
            else:
                self._reply(200, {})

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, calls


def test_mlflow_run_logs_over_rest_and_sanitises_keys():
    from read.training.tracking import MlflowRun, val_metrics

    srv, calls = _fake_mlflow()
    try:
        uri = f"http://127.0.0.1:{srv.server_port}"
        run = MlflowRun.start(uri, "exp", "v17c", params={"lr": 2e-5})
        run.log_metrics(val_metrics({"recall@0.5": 0.9, "loss": float("nan")}), step=50)
        run.finish()
    finally:
        srv.shutdown()
    posts = {path.rsplit("/", 2)[-2] + "/" + path.rsplit("/", 1)[-1]: body
             for method, path, body in calls if method == "POST"}
    assert posts["runs/create"]["run_name"] == "v17c"
    batches = [b for m, p, b in calls if p.endswith("log-batch")]
    assert batches[0]["params"] == [{"key": "lr", "value": "2e-05"}]
    assert [(x["key"], x["step"]) for x in batches[1]["metrics"]] == [("val/recall_0.5", 50)]
    assert posts["runs/update"]["status"] == "FINISHED"


def test_mlflow_off_without_uri_and_soft_fails_when_unreachable(monkeypatch, capsys):
    from read.training.tracking import MlflowRun

    monkeypatch.delenv("MLFLOW_TRACKING_URI", raising=False)
    assert MlflowRun.start(None, "exp", "x") is None
    assert MlflowRun.start("http://127.0.0.1:9", "exp", "x") is None
    assert "logging off" in capsys.readouterr().err
