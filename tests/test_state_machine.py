from __future__ import annotations

import json

import pytest

from governed_signal_to_content import database
from governed_signal_to_content.config import WorkspacePaths
from governed_signal_to_content.evidence import ingest_signal
from governed_signal_to_content.models import WorkflowState
from governed_signal_to_content.state_machine import (
    InvalidTransition,
    transition_candidate,
    validate_transition,
)


def test_valid_state_transitions() -> None:
    validate_transition(WorkflowState.DISCOVERED, WorkflowState.EVIDENCE_PRESERVED)
    validate_transition(WorkflowState.AWAITING_APPROVAL, WorkflowState.APPROVED)
    validate_transition(WorkflowState.APPROVED, WorkflowState.RELEASED)


@pytest.mark.parametrize(
    ("prior", "requested"),
    [
        (WorkflowState.DISCOVERED, WorkflowState.APPROVED),
        (WorkflowState.QUALIFIED, WorkflowState.RELEASED),
        (WorkflowState.AWAITING_APPROVAL, WorkflowState.RELEASED),
    ],
)
def test_rejected_invalid_state_transitions(
    prior: WorkflowState, requested: WorkflowState
) -> None:
    with pytest.raises(InvalidTransition):
        validate_transition(prior, requested)


def test_rejected_attempt_produces_receipt_and_keeps_state(workspace: WorkspacePaths) -> None:
    candidate, _, _ = ingest_signal(
        paths=workspace,
        title="Signal",
        source_url="https://example.com/signal",
        source_file=None,
    )
    with pytest.raises(InvalidTransition):
        transition_candidate(
            database_path=workspace.database,
            receipt_log=workspace.receipt_log,
            candidate_id=candidate.candidate_id,
            requested=WorkflowState.APPROVED,
            command="test-invalid",
            actor="tester",
            reason="should never be accepted",
        )
    current = database.get_candidate(workspace.database, candidate.candidate_id)
    assert current is not None
    assert current["state"] == WorkflowState.EVIDENCE_PRESERVED.value
    receipts = [json.loads(line) for line in workspace.receipt_log.read_text(encoding="utf-8").splitlines()]
    assert receipts[-1]["outcome"] == "rejected"
    assert receipts[-1]["resulting_state"] == WorkflowState.EVIDENCE_PRESERVED.value
