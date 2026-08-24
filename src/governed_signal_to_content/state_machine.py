"""Deterministic state-map validation and non-authority workflow transitions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import database
from .models import (
    AuthenticationEvidence,
    AuthorizationDecision,
    RunReceipt,
    WorkflowState,
)
from .receipts import (
    new_receipt,
    project_transition_event,
    transition_event_from_receipt,
)


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


class MediatedTransitionRequired(PermissionError):
    pass


def _scope_identifiers(packet: dict[str, object]) -> dict[str, str]:
    if packet.get("scope_version") != "1.0":
        return {}
    return {
        "scope_version": "1.0",
        "brand_id": str(packet["brand_id"]),
        "channel_id": str(packet["channel_id"]),
        "destination_id": str(packet["destination_id"]),
    }


def validate_transition(prior: WorkflowState, requested: WorkflowState) -> None:
    if requested not in TRANSITIONS[prior]:
        raise InvalidTransition(f"Invalid transition: {prior.value} -> {requested.value}")


def _governed_hash(
    governed_hash: str | None, file_hashes: dict[str, str] | None
) -> str | None:
    if governed_hash is not None:
        return governed_hash
    if file_hashes is not None:
        return file_hashes.get("packet_manifest")
    return None


def _persist_rejected_event(
    *,
    database_path: Path,
    receipt_log: Path,
    receipt: RunReceipt,
    target_type: str,
    target_id: str,
    governed_hash: str | None,
    authenticated_operation: dict[str, object] | None = None,
) -> RunReceipt:
    event = transition_event_from_receipt(
        receipt,
        target_type=target_type,
        target_id=target_id,
        governed_hash=governed_hash,
    )
    database.record_transition_event(
        database_path, event, authenticated_operation=authenticated_operation
    )
    return project_transition_event(database_path, receipt_log, receipt.run_id)


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
    governed_hash: str | None = None,
    packet: dict[str, object] | None = None,
) -> RunReceipt:
    database.migrate_database(database_path)
    if packet is not None and (
        requested is not WorkflowState.PACKET_GENERATED
        or str(packet.get("candidate_id")) != candidate_id
    ):
        raise ValueError("A generated packet can only accompany its PACKET_GENERATED transition")
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
        _persist_rejected_event(
            database_path=database_path,
            receipt_log=receipt_log,
            receipt=receipt,
            target_type="candidate",
            target_id=candidate_id,
            governed_hash=_governed_hash(governed_hash, file_hashes),
        )
        raise
    identifiers: dict[str, Any] = {"candidate_id": candidate_id}
    if packet is not None:
        identifiers.update(
            {
                "packet_id": str(packet["packet_id"]),
                **_scope_identifiers(packet),
            }
        )
    receipt = new_receipt(
        command=command,
        actor=actor,
        input_identifiers=identifiers,
        prior_state=prior.value,
        requested_transition=requested.value,
        resulting_state=requested.value,
        outcome="accepted",
        reason=reason,
        file_hashes=file_hashes,
    )
    event = transition_event_from_receipt(
        receipt,
        target_type="candidate",
        target_id=candidate_id,
        governed_hash=_governed_hash(governed_hash, file_hashes),
    )
    database.apply_candidate_transition(
        database_path,
        candidate_id=candidate_id,
        prior_state=prior.value,
        resulting_state=requested.value,
        event=event,
        packet=packet,
    )
    return project_transition_event(database_path, receipt_log, receipt.run_id)


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
    governed_hash: str | None = None,
) -> RunReceipt:
    database.migrate_database(database_path)
    packet = database.get_packet(database_path, packet_id)
    if packet is None:
        raise KeyError(f"Unknown packet: {packet_id}")
    prior = WorkflowState(str(packet["state"]))
    authority_sensitive = (prior.value, requested.value) in (
        database.AUTHORITY_SENSITIVE_STATE_PAIRS
    )
    if authority_sensitive:
        error = MediatedTransitionRequired(
            "Authority-sensitive transition requires the TransitionMediator"
        )
        failed = AuthenticationEvidence(verification_status="failed")
        receipt = new_receipt(
            command=command,
            actor=actor,
            input_identifiers={
                "packet_id": packet_id,
                "candidate_id": str(packet["candidate_id"]),
                **_scope_identifiers(packet),
            },
            prior_state=prior.value,
            requested_transition=requested.value,
            resulting_state=prior.value,
            outcome="rejected",
            reason=str(error),
            file_hashes=file_hashes,
            authentication=failed,
        )
        _persist_rejected_event(
            database_path=database_path,
            receipt_log=receipt_log,
            receipt=receipt,
            target_type="packet",
            target_id=packet_id,
            governed_hash=_governed_hash(governed_hash, file_hashes),
        )
        raise error
    try:
        validate_transition(prior, requested)
    except InvalidTransition as error:
        receipt = new_receipt(
            command=command,
            actor=actor,
            input_identifiers={
                "packet_id": packet_id,
                **_scope_identifiers(packet),
            },
            prior_state=prior.value,
            requested_transition=requested.value,
            resulting_state=prior.value,
            outcome="rejected",
            reason=str(error),
            file_hashes=file_hashes,
        )
        _persist_rejected_event(
            database_path=database_path,
            receipt_log=receipt_log,
            receipt=receipt,
            target_type="packet",
            target_id=packet_id,
            governed_hash=_governed_hash(governed_hash, file_hashes),
        )
        raise
    receipt = new_receipt(
        command=command,
        actor=actor,
        input_identifiers={
            "packet_id": packet_id,
            "candidate_id": str(packet["candidate_id"]),
            **_scope_identifiers(packet),
        },
        prior_state=prior.value,
        requested_transition=requested.value,
        resulting_state=requested.value,
        outcome="accepted",
        reason=reason,
        file_hashes=file_hashes,
    )
    event = transition_event_from_receipt(
        receipt,
        target_type="packet",
        target_id=packet_id,
        governed_hash=_governed_hash(governed_hash, file_hashes),
    )
    database.apply_packet_transition(
        database_path,
        packet_id=packet_id,
        candidate_id=str(packet["candidate_id"]),
        prior_state=prior.value,
        resulting_state=requested.value,
        event=event,
    )
    return project_transition_event(database_path, receipt_log, receipt.run_id)


def record_rejected_transition(
    *,
    database_path: Path,
    receipt_log: Path,
    command: str,
    actor: str,
    input_identifiers: dict[str, Any],
    prior_state: WorkflowState,
    requested: WorkflowState,
    reason: str,
    file_hashes: dict[str, str] | None = None,
    governed_hash: str | None = None,
    authentication: AuthenticationEvidence | None = None,
    authorization: AuthorizationDecision | None = None,
    authenticated_operation: dict[str, object] | None = None,
) -> RunReceipt:
    database.migrate_database(database_path)
    receipt = new_receipt(
        command=command,
        actor=actor,
        input_identifiers=input_identifiers,
        prior_state=prior_state.value,
        requested_transition=requested.value,
        resulting_state=prior_state.value,
        outcome="rejected",
        reason=reason,
        file_hashes=file_hashes,
        authentication=authentication,
        authorization=authorization,
    )
    packet_id = input_identifiers.get("packet_id")
    candidate_id = input_identifiers.get("candidate_id")
    target_type = "packet" if packet_id is not None else "candidate"
    target_id = packet_id if packet_id is not None else candidate_id
    if target_id is None:
        raise ValueError("Rejected transition evidence requires a packet or candidate ID")
    canonical_receipt = _persist_rejected_event(
        database_path=database_path,
        receipt_log=receipt_log,
        receipt=receipt,
        target_type=target_type,
        target_id=target_id,
        governed_hash=_governed_hash(governed_hash, file_hashes),
        authenticated_operation=authenticated_operation,
    )
    return canonical_receipt
