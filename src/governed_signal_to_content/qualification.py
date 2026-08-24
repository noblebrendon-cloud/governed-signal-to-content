"""Validate proposed classifications; deterministic code owns the transition."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from . import database
from .config import WorkspacePaths
from .models import Classification, WorkflowState
from .receipts import execution_identity
from .state_machine import record_rejected_transition, transition_candidate


def load_classification(path: Path) -> Classification:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
        return Classification.model_validate(value)
    except (json.JSONDecodeError, ValidationError) as error:
        raise ValueError(f"Invalid classification JSON: {error}") from error


def qualify_candidate(
    paths: WorkspacePaths, candidate_id: str, classification_path: Path
) -> tuple[str, bool, str]:
    candidate = database.get_candidate(paths.database, candidate_id)
    if candidate is None:
        raise KeyError(f"Unknown candidate: {candidate_id}")
    classification = load_classification(classification_path)
    prior = WorkflowState(str(candidate["state"]))
    if prior is not WorkflowState.DUPLICATE_CHECKED:
        return (
            record_rejected_transition(
                database_path=paths.database,
                receipt_log=paths.receipt_log,
                command="qualify",
                actor=execution_identity(),
                input_identifiers={"candidate_id": candidate_id},
                prior_state=prior,
                requested=WorkflowState.QUALIFIED,
                reason=f"Qualification requires DUPLICATE_CHECKED; current state is {prior.value}.",
            ).run_id,
            False,
            "Candidate is not ready for qualification.",
        )
    database.update_candidate_fields(
        paths.database,
        candidate_id,
        classification_json=json.dumps(
            classification.model_dump(mode="json"), ensure_ascii=False, sort_keys=True
        ),
    )
    if not classification.qualification_decision:
        reason = (
            "Classification proposed qualification_decision=false; deterministic application "
            "left authoritative state unchanged. "
            + classification.qualification_reason
        )
        receipt = record_rejected_transition(
            database_path=paths.database,
            receipt_log=paths.receipt_log,
            command="qualify",
            actor=execution_identity(),
            input_identifiers={"candidate_id": candidate_id},
            prior_state=prior,
            requested=WorkflowState.QUALIFIED,
            reason=reason,
        )
        return receipt.run_id, False, reason
    receipt = transition_candidate(
        database_path=paths.database,
        receipt_log=paths.receipt_log,
        candidate_id=candidate_id,
        requested=WorkflowState.QUALIFIED,
        command="qualify",
        actor=execution_identity(),
        reason=classification.qualification_reason,
    )
    return receipt.run_id, True, classification.qualification_reason
