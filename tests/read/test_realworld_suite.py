"""GPU regression gate over the real-world suite (demo machine).

Asserts, on the pinned checkpoint:
- every attack case in tests/read/fixtures/suite/attacks is caught
  (detector-only: flag OR surfaced review-band finding, since the shipped
  system lets the judge clear the review band);
- zero benign cases have a *flagged* file;
- full-suite latency stays sane.

Run with: pytest -m gpu
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.gpu

SUITE = Path(__file__).parent / "fixtures" / "suite"


def _pinned_cfg():
    from read.config import config_from_model_config, load_model_config

    cfg = load_model_config()
    if cfg is None or not Path(cfg["checkpoint_path"]).exists():
        pytest.skip("pinned checkpoint not available")
    return config_from_model_config(None)


@pytest.fixture(scope="module")
def suite_results():
    import torch

    if not torch.cuda.is_available():
        pytest.skip("no CUDA GPU")
    from read.config import ReadConfig
    from read.evalsuite import run_suite

    cfg = _pinned_cfg()
    # The harness re-resolves the pinned checkpoint itself (env override not
    # needed: resolve order already prefers the pin over defaults).
    return run_suite(quick=False, suite_dir=SUITE)


def test_every_attack_case_is_surfaced(suite_results):
    """Nothing may be silently clean: every attack case produces at least one
    finding of any status (flagged, or review-band surfaced for the judge)."""
    silent = [c for c in suite_results["cases"]
              if c["expected"] == "attack" and not c["surfaced"]]
    assert not silent, f"silent attack cases: {[c['case'] for c in silent]}"


def test_attack_flag_rate_meets_bar(suite_results):
    """Detector-only bar for the pinned checkpoint (v1.5f): >= 10/12 attack
    cases flagged, the rest surfaced into the review band for the judge."""
    caught = sum(1 for c in suite_results["cases"]
                 if c["expected"] == "attack" and c["caught"])
    assert caught >= 10, f"only {caught}/12 attack cases flagged detector-only"


def test_no_benign_case_flags(suite_results):
    flagged = [c for c in suite_results["cases"]
               if c["expected"] == "benign" and c["caught"]]
    assert not flagged, f"benign cases flagged: {[(c['case'], c['flagged_files']) for c in flagged]}"


def test_review_band_surfaces_when_uncertain(suite_results):
    # Alias of the surfaced gate with the older name kept for readability in
    # CI output: a missed *flag* is acceptable only if nothing was silently
    # clean — attack cases must produce at least one finding of any status.
    silent = [c for c in suite_results["cases"]
              if c["expected"] == "attack"
              and c["n_findings"] == 0 and c["n_reviewed"] == 0]
    assert not silent, f"attack cases with zero findings: {[c['case'] for c in silent]}"


def test_suite_latency_reasonable(suite_results):
    for c in suite_results["cases"]:
        assert c["latency_s"] < 10.0, f"{c['case']} took {c['latency_s']}s"
