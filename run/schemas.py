"""JSON Schema for VerdictReport, with the no-incomplete-ALLOW rules that pydantic cannot export."""

import json
from pathlib import Path

from run.evidence import RunComponents, VerdictReport


def verdict_schema() -> dict:
    schema = VerdictReport.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    complete_components = {
        "type": "object",
        "required": list(RunComponents.model_fields),
        "properties": {key: {"const": "complete"} for key in RunComponents.model_fields},
    }
    completed_run = {
        "type": "object",
        "required": ["status", "components", "errors"],
        "properties": {
            "status": {"const": "complete"},
            "components": complete_components,
            "errors": {"maxItems": 0},
        },
    }
    schema["$defs"]["RunEvidence"]["allOf"] = [
        {
            "if": {"required": ["status"], "properties": {"status": {"const": "complete"}}},
            "then": completed_run,
        }
    ]
    schema["allOf"] = [
        {
            "if": {"required": ["verdict"], "properties": {"verdict": {"const": "ALLOW"}}},
            "then": {
                "required": ["read", "run"],
                "properties": {
                    "read": {
                        "required": ["status"],
                        "properties": {"status": {"const": "complete"}},
                    },
                    "run": {
                        **completed_run,
                        "required": ["status", "components", "errors", "honeytoken_hits"],
                        "properties": {
                            **completed_run["properties"],
                            "honeytoken_hits": {"maxItems": 0},
                        },
                    },
                },
            },
        }
    ]
    return schema


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "docs/verdict.schema.json"
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(verdict_schema(), indent=2) + "\n", encoding="utf-8")
