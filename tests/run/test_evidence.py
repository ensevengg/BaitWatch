import json
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

from run.evidence import HoneytokenHit, RunComponents, RunEvidence, State, VerdictReport
from run.schemas import verdict_schema


def complete_run() -> RunEvidence:
    return RunEvidence(
        status="complete",
        components=RunComponents(**{key: State.COMPLETE for key in RunComponents.model_fields}),
    )


def test_generated_contract_is_current():
    path = Path(__file__).resolve().parents[2] / "docs/verdict.schema.json"
    assert json.loads(path.read_text()) == verdict_schema()
    jsonschema.Draft202012Validator.check_schema(verdict_schema())


def test_default_report_is_flag_and_valid():
    report = VerdictReport(reason="READ and RUN are not complete")
    assert report.verdict == "FLAG"
    jsonschema.validate(report.model_dump(mode="json"), verdict_schema())


def test_incomplete_cannot_be_allow_in_python_or_json():
    with pytest.raises(ValidationError, match="ALLOW requires"):
        VerdictReport(verdict="ALLOW", reason="unsafe default")
    data = VerdictReport(reason="incomplete").model_dump(mode="json")
    data["verdict"] = "ALLOW"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, verdict_schema())


def test_empty_run_cannot_claim_completion():
    with pytest.raises(ValidationError, match="every component"):
        RunEvidence(status="complete")
    data = VerdictReport(reason="incomplete").model_dump(mode="json")
    data["run"]["status"] = "complete"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, verdict_schema())


def test_complete_clean_contract_can_be_allowed():
    report = VerdictReport(
        verdict="ALLOW",
        reason="synthetic complete contract fixture",
        read={"status": "complete"},
        run=complete_run(),
    )
    jsonschema.validate(report.model_dump(mode="json"), verdict_schema())


def test_honeytoken_cannot_be_allowed():
    evidence = complete_run()
    evidence.honeytoken_hits.append(HoneytokenHit(token_id="fixture", source="transcript"))
    with pytest.raises(ValidationError, match="ALLOW requires"):
        VerdictReport(verdict="ALLOW", reason="bad", read={"status": "complete"}, run=evidence)
    data = VerdictReport(reason="flag", read={"status": "complete"}, run=evidence).model_dump(
        mode="json"
    )
    data["verdict"] = "ALLOW"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, verdict_schema())


def test_unknown_fields_do_not_disappear():
    with pytest.raises(ValidationError, match="Extra inputs"):
        RunEvidence.model_validate({"silently_truncated": True})


def test_evidence_lists_are_per_scan():
    first, second = RunEvidence(), RunEvidence()
    first.dns_hits.append({"source_ip": "fixture"})
    assert not second.dns_hits
    assert first.scan_id != second.scan_id


def test_unencodable_cage_text_cannot_suppress_a_report():
    from run.evidence import (
        CommandResult,
        FileDiff,
        NetworkHit,
        RunError,
        RunEvidence,
        VerdictReport,
    )

    run = RunEvidence(
        file_diffs=[FileDiff(path="bad\udcff", change="added")],
        staging_exclusions=["bad\udcff/.env"],
        tool_log=[CommandResult(command=["run_cmd", "bad\udcff"], stdout="bad\udcff")],
        errors=[RunError(code="TRACE_INCOMPLETE", message="bad\udcff")],
        dns_hits=[NetworkHit(source_ip="192.0.2.20", destination="evil.example")],
    )
    report = VerdictReport(verdict="BLOCK", reason="bad\udcff", run=run)
    payload = report.model_dump_json()
    assert "evil.example" in payload
    assert "\udcff" not in payload
    assert report.run.file_diffs[0].path == r"bad\udcff"
