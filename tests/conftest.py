from __future__ import annotations

import json
from pathlib import Path

import pytest

from governed_signal_to_content import database
from governed_signal_to_content.config import WorkspacePaths, workspace_paths
from governed_signal_to_content.deduplication import (
    deduplicate_candidate,
    normalize_candidate,
)
from governed_signal_to_content.evidence import ingest_signal
from governed_signal_to_content.qualification import qualify_candidate


@pytest.fixture()
def workspace(tmp_path: Path) -> WorkspacePaths:
    paths = workspace_paths(tmp_path / "workspace")
    database.initialize_workspace(paths)
    return paths


@pytest.fixture()
def qualified_candidate(workspace: WorkspacePaths, tmp_path: Path) -> tuple[WorkspacePaths, str]:
    candidate, _, _ = ingest_signal(
        paths=workspace,
        title="A governed capability",
        source_url="https://example.com/docs/capability",
        source_file=None,
    )
    normalize_candidate(workspace, candidate.candidate_id)
    _, duplicate, _ = deduplicate_candidate(workspace, candidate.candidate_id)
    assert not duplicate
    classification = {
        "schema_version": "1.0",
        "documented_facts": ["The primary source documents a capability."],
        "reasonable_inferences": ["Durable identity may aid reuse."],
        "direct_similarities": ["Both use durable identity."],
        "broader_industry_trends": ["Capabilities are becoming managed resources."],
        "primary_sources": ["https://example.com/docs/capability"],
        "structural_overlap_dimensions": ["durable operational identity"],
        "qualification_decision": True,
        "qualification_reason": "The bounded structural overlap is substantive.",
    }
    path = tmp_path / "classification.json"
    path.write_text(json.dumps(classification), encoding="utf-8", newline="\n")
    _, qualified, _ = qualify_candidate(workspace, candidate.candidate_id, path)
    assert qualified
    return workspace, candidate.candidate_id


@pytest.fixture()
def content_inputs_path(tmp_path: Path) -> Path:
    value = {
        "schema_version": "1.0",
        "linkedin_analysis": "A governed analysis draft with explicit evidence boundaries.",
        "csg_facebook_post": "A governed social draft with explicit approval boundaries.",
        "mermaid_diagram": "flowchart LR\nA[prompt] --> B[approval]",
        "governed_operating_layers_essay": "A governed essay draft that remains reviewable.",
        "repository_note": "See `src/governed_signal_to_content/state_machine.py`.",
        "sources": ["https://example.com/docs/capability"],
    }
    path = tmp_path / "content-inputs.json"
    path.write_text(json.dumps(value), encoding="utf-8", newline="\n")
    return path
