"""The only module authorized to apply workflow state transitions."""

from __future__ import annotations

from pathlib import Path

from . import database
from .models import RunReceipt, WorkflowState
from .receipts import append_receipt, new_receipt


TRANSITIONS: dict[WorkflowState, frozenset[WorkflowState]] = {
    WorkflowState.DISCOVERED: frozenset(
        {WorkflowState.EVIDENCE_PRESERVED, WorkflowState.FAILED}
    ),
    WorkflowState.EVIDENCE_PRESERVED: frozenset(
        {WorkflowState.NORMALIZED, WorkflowState.FAILED}
    ),
    WorkflowState.NORMALIZED: frozenset(
        {
            WorkflowState.DUPLICATE_CHECKED,
            WorkflowState.SUPPRESSED,
            WorkflowState.FAILED,
        }
    ),
    WorkflowState.DUPLICATE_CHECKED: frozenset(
        {WorkflowState.QUALIFIED, WorkflowState.SUPPRESSED, WorkflowState.FAILED}
    ),
    WorkflowState.QUALIFIED: frozenset(
        {WorkflowState.PACKET_GENERATED, WorkflowState.FAILED}
    ),
    WorkflowState.PACKET_GENERATED: frozenset(
        {WorkflowState.AWAITING_APPROVAL, WorkflowState.FAILED}
    ),
    WorkflowState.AWAITING_APPROVAL: frozenset(
        {WorkflowState.APPROVED, WorkflowState.REJECTED, WorkflowState.FAILED}
    ),
    WorkflowState.APPROVED: frozenset(
        {WorkflowState.RELEASED, WorkflowState.FAILED}
    ),
    WorkflowState.RELEASED: frozenset(),
    WorkflowState.SUPPRESSED: frozenset(),
    WorkflowState.REJECTED: frozenset(),
    WorkflowState.FAILED: frozenset(),
}


class InvalidTransition(ValueError):
    pass


def validate_transition(prior: WorkflowState, requested: WorkflowState) -> None:
    if requested not in TRANSITIONS[prior]:
        raise InvalidTransition(f"Invalid transition: {prior.value} -> {requested.value}")


def transition_candidate(
    *,
    database_path: Path,
    receipt_log: Path,
    candidate_id: str,
    requested: WorkflowState,
    command: str,
    actor: str,
    reason: str,
    file_hashes: dict[str, str] | None = None,
) -> RunReceipt:
    candidate = database.get_candidate(database_path, candidate_id)
    if candidate is None:
        raise KeyError(f"Unknown candidate: {candidate_id}")
    prior = WorkflowState(str(candidate["state"]))
    try:
        validate_transition(prior, requested)
    except InvalidTransition as error:
        receipt = new_receipt(
            command=command,
            actor=actor,
            input_identifiers={"candidate_id": candidate_id},
            prior_state=prior.value,
            requested_transition=requested.value,
            resulting_state=prior.value,
            outcome="rejected",
            reason=str(error),
            file_hashes=file_hashes,
        )
        append_receipt(receipt_log, receipt)
        raise
    database.update_candidate_fields(database_path, candidate_id, state=requested.value)
    receipt = new_receipt(
        command=command,
        actor=actor,
        input_identifiers={"candidate_id": candidate_id},
        prior_state=prior.value,
        requested_transition=requested.value,
        resulting_state=requested.value,
        outcome="accepted",
        reason=reason,
        file_hashes=file_hashes,
    )
    append_receipt(receipt_log, receipt)
    return receipt


def transition_packet(
    *,
    database_path: Path,
    receipt_log: Path,
    packet_id: str,
    requested: WorkflowState,
    command: str,
    actor: str,
    reason: str,
    file_hashes: dict[str, str] | None = None,
) -> RunReceipt:
    packet = database.get_packet(database_path, packet_id)
    if packet is None:
        raise KeyError(f"Unknown packet: {packet_id}")
    prior = WorkflowState(str(packet["state"]))
    try:
        validate_transition(prior, requested)
    except InvalidTransition as error:
        receipt = new_receipt(
            command=command,
            actor=actor,
            input_identifiers={"packet_id": packet_id},
            prior_state=prior.value,
            requested_transition=requested.value,
            resulting_state=prior.value,
            outcome="rejected",
            reason=str(error),
            file_hashes=file_hashes,
        )
        append_receipt(receipt_log, receipt)
        raise
    database.update_packet_and_candidate_state(
        database_path, packet_id, str(packet["candidate_id"]), requested.value
    )
    receipt = new_receipt(
        command=command,
        actor=actor,
        input_identifiers={
            "packet_id": packet_id,
            "candidate_id": str(packet["candidate_id"]),
        },
        prior_state=prior.value,
        requested_transition=requested.value,
        resulting_state=requested.value,
        outcome="accepted",
        reason=reason,
        file_hashes=file_hashes,
    )
    append_receipt(receipt_log, receipt)
    return receipt


def record_rejected_transition(
    *,
    receipt_log: Path,
    command: str,
    actor: str,
    input_identifiers: dict[str, str],
    prior_state: WorkflowState,
    requested: WorkflowState,
    reason: str,
) -> RunReceipt:
    receipt = new_receipt(
        command=command,
        actor=actor,
        input_identifiers=input_identifiers,
        prior_state=prior_state.value,
        requested_transition=requested.value,
        resulting_state=prior_state.value,
        outcome="rejected",
        reason=reason,
    )
    append_receipt(receipt_log, receipt)
    return receipt
