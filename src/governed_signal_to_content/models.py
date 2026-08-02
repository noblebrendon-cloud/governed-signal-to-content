"""Validated records crossing the governed workflow boundary."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class WorkflowState(str, Enum):
    DISCOVERED = "DISCOVERED"
    EVIDENCE_PRESERVED = "EVIDENCE_PRESERVED"
    NORMALIZED = "NORMALIZED"
    DUPLICATE_CHECKED = "DUPLICATE_CHECKED"
    QUALIFIED = "QUALIFIED"
    PACKET_GENERATED = "PACKET_GENERATED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    RELEASED = "RELEASED"
    SUPPRESSED = "SUPPRESSED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceRecord(StrictModel):
    schema_version: str = "1.0"
    evidence_id: str
    candidate_id: str
    source_url: HttpUrl
    original_filename: str | None = None
    preserved_path: str | None = None
    sha256: str
    byte_size: int | None = Field(default=None, ge=0)
    ingested_at_utc: str
    content_preserved: bool


class CandidateRecord(StrictModel):
    schema_version: str = "1.0"
    candidate_id: str
    title: str = Field(min_length=1)
    source_url: HttpUrl
    normalized_url: str | None = None
    source_identity: str
    development_identifiers: list[str] = Field(default_factory=list)
    state: WorkflowState
    created_at_utc: str


class Classification(StrictModel):
    schema_version: str = "1.0"
    documented_facts: list[str] = Field(min_length=1)
    reasonable_inferences: list[str]
    direct_similarities: list[str]
    broader_industry_trends: list[str]
    primary_sources: list[HttpUrl] = Field(min_length=1)
    structural_overlap_dimensions: list[str] = Field(min_length=1)
    qualification_decision: bool
    qualification_reason: str = Field(min_length=1)


class ContentInputs(StrictModel):
    schema_version: str = "1.0"
    linkedin_analysis: str = Field(min_length=1)
    csg_facebook_post: str = Field(min_length=1)
    mermaid_diagram: str = Field(min_length=1)
    governed_operating_layers_essay: str = Field(min_length=1)
    repository_note: str = Field(min_length=1)
    sources: list[HttpUrl] = Field(min_length=1)


class RunReceipt(StrictModel):
    schema_version: str = "1.0"
    run_id: str
    command: str
    timestamp_utc: str
    actor: str
    input_identifiers: dict[str, Any]
    prior_state: str | None
    requested_transition: str | None
    resulting_state: str | None
    outcome: str
    reason: str
    file_hashes: dict[str, str] = Field(default_factory=dict)
    application_version: str
