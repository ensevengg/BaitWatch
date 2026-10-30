"""Typed evidence; unknown or missing checks cannot become an ALLOW."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def safe_text(value: str) -> str:
    return value.encode("utf-8", errors="backslashreplace").decode("utf-8")


def _serializable_text(value):
    if isinstance(value, str):
        return safe_text(value)
    if isinstance(value, list):
        return [_serializable_text(item) for item in value]
    if isinstance(value, dict):
        return {_serializable_text(key): _serializable_text(item) for key, item in value.items()}
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @field_validator("*", mode="before")
    @classmethod
    def serializable_text(cls, value):
        return _serializable_text(value)


class State(StrEnum):
    NOT_RUN = "not_run"
    COMPLETE = "complete"
    ERROR = "error"


class RunError(StrictModel):
    code: str = Field(min_length=1)
    message: str = Field(min_length=1)


class NetworkHit(StrictModel):
    source_ip: str
    scan_token: str | None = None
    destination: str
    detail: str = ""


class HoneytokenHit(StrictModel):
    token_id: str
    source: Literal["dns", "http", "tls", "tool_log", "transcript"]
    source_ip: str | None = None


class FileDiff(StrictModel):
    is_repo_file: bool = False
    path: str
    change: Literal["added", "modified", "deleted"]


class CommandResult(StrictModel):
    command: list[str] = Field(min_length=1)
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    output_truncated: bool = False
    duration_seconds: float = Field(default=0, ge=0)


class RunComponents(StrictModel):
    sandbox: State = State.NOT_RUN
    dns_sink: State = State.NOT_RUN
    http_sink: State = State.NOT_RUN
    tls_sink: State = State.NOT_RUN
    decoy: State = State.NOT_RUN
    trace: State = State.NOT_RUN

    def complete(self) -> bool:
        return all(value == State.COMPLETE for value in self.model_dump().values())


class RunEvidence(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: UUID = Field(default_factory=uuid4)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: Literal["incomplete", "complete", "error"] = "incomplete"
    components: RunComponents = Field(default_factory=RunComponents)
    staged_file_count: int = Field(default=0, ge=0)
    staging_exclusions: list[str] = Field(default_factory=list)
    dns_hits: list[NetworkHit] = Field(default_factory=list)
    http_hits: list[NetworkHit] = Field(default_factory=list)
    tls_hits: list[NetworkHit] = Field(default_factory=list)
    honeytoken_hits: list[HoneytokenHit] = Field(default_factory=list)
    file_diffs: list[FileDiff] = Field(default_factory=list)
    tool_log: list[CommandResult] = Field(default_factory=list)
    errors: list[RunError] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_completion(self) -> Self:
        if self.status == "complete" and (self.errors or not self.components.complete()):
            raise ValueError("complete RUN evidence requires every component and no errors")
        return self


class ReadEvidence(StrictModel):
    status: State = State.NOT_RUN
    # Finding fields are left to the READ owner.


class VerdictReport(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    verdict: Literal["ALLOW", "FLAG", "BLOCK"] = "FLAG"
    reason: str = Field(min_length=1)
    read: ReadEvidence = Field(default_factory=ReadEvidence)
    run: RunEvidence = Field(default_factory=RunEvidence)

    @model_validator(mode="after")
    def validate_allow(self) -> Self:
        if self.verdict == "ALLOW" and (
            self.read.status != State.COMPLETE
            or self.run.status != "complete"
            or not self.run.components.complete()
            or self.run.errors
            or self.run.honeytoken_hits
        ):
            raise ValueError(
                "ALLOW requires complete READ/RUN checks and no errors or honeytoken hits"
            )
        return self
