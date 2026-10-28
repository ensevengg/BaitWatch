"""The runtime-eval fixture must really run its claimed action.

A payload labelled "runtime-eval-chain" that evaluates ROT13 text is a label,
not an attack.  These tests execute the generated JavaScript with Node, with
``https`` and ``fs`` stubbed, and prove the intended effect (a POST to the
sandbox host carrying ``.env``) actually happens.  No network is touched.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from attacks.synth.generate import build_examples, build_repos
from attacks.synth.seeds import ADVERSARIAL_SEEDS, ATTACK_REPO_SEEDS
from attacks.synth.transforms import encode_seed

REPO_ROOT = Path(__file__).resolve().parents[2]

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

HARNESS = r"""
"use strict";
const Module = require("module");
const calls = [];
const realLoad = Module._load;
Module._load = function (request) {
  if (request === "https") {
    return {
      request(url, options, callback) {
        calls.push(["https.request", url, options && options.method]);
        if (callback) callback({ resume() {} });
        return {
          on() { return this; },
          setTimeout() { return this; },
          end(body) { calls.push(["end", String(body)]); },
        };
      },
      get() { return { on() { return this; }, setTimeout() { return this; } }; },
    };
  }
  if (request === "fs") {
    return {
      readFileSync(path) {
        calls.push(["fs.readFileSync", String(path)]);
        return Buffer.from("SECRET=should-not-leave");
      },
    };
  }
  return realLoad.apply(this, arguments);
};
function rot13(value) {
  return value.replace(/[a-z]/gi, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
  });
}
eval(process.argv[2]);
console.log(JSON.stringify(calls));
"""


def _run_node(tmp_path: Path, expression: str) -> list[list[str]]:
    harness = tmp_path / "harness.js"
    harness.write_text(HARNESS, encoding="utf-8")
    result = subprocess.run(
        [NODE, str(harness), expression],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("seed_name", ["runtime-eval", "ex-atob"])
def test_js_eval_payload_executes_the_action(tmp_path: Path, seed_name: str) -> None:
    seeds = {**ATTACK_REPO_SEEDS, **ADVERSARIAL_SEEDS}
    expression = encode_seed(seeds[seed_name], "js_eval")
    calls = _run_node(tmp_path, expression)

    https_calls = [call for call in calls if call[0] == "https.request"]
    assert https_calls, calls
    assert any(call[1].startswith("https://evil.example/") for call in https_calls)
    assert any(call[0] == "fs.readFileSync" and call[1] == ".env" for call in calls)
    assert any(call[0] == "end" and "SECRET" in call[1] for call in calls)


def test_generated_javascript_parses(tmp_path: Path) -> None:
    """A syntax error would make the fixture inert for the wrong reason."""
    files: list[str] = []
    for name, repo in build_repos().items():
        files.extend(f"repos/{name}/{rel}" for rel in repo.files if rel.endswith(".js"))
    files.extend(
        f"examples/{example.path}" for example in build_examples() if example.path.endswith(".js")
    )

    assert files
    for rel in files:
        path = REPO_ROOT / "attacks" / rel
        result = subprocess.run(
            [NODE, "--check", str(path)], capture_output=True, text=True, timeout=60, check=False
        )
        assert result.returncode == 0, f"{rel}: {result.stderr}"
