"""Append-only JSONL execution receipts."""

from __future__ import annotations

import getpass
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from . import __version__
from . import database
from .hashing import canonical_json
from .integrity import canonical_receipt_from_event
from .models import AuthenticationEvidence, AuthorizationDecision, RunReceipt


SENSITIVE_KEY_FRAGMENTS = (
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
)
SAFE_OPAQUE_REFERENCE_KEYS = frozenset({"credential_ref"})


class ReceiptProjectionError(OSError):
    """The canonical event committed, but its JSONL projection is still pending."""

    def __init__(self, event_id: str, error: Exception) -> None:
        self.event_id = event_id
        super().__init__(
            f"Canonical transition event {event_id} committed; "
            f"JSONL receipt projection remains pending: {error}"
        )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def execution_identity() -> str:
    return f"local:{getpass.getuser()}"


def sanitize_for_receipt(value: Any) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in SAFE_OPAQUE_REFERENCE_KEYS:
                clean[str(key)] = sanitize_for_receipt(item)
            elif any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS):
                clean[str(key)] = "[REDACTED]"
            else:
                clean[str(key)] = sanitize_for_receipt(item)
        return clean
    if isinstance(value, list):
        return [sanitize_for_receipt(item) for item in value]
    return value


def new_receipt(
    *,
    command: str,
    actor: str,
    input_identifiers: dict[str, Any],
    prior_state: str | None,
    requested_transition: str | None,
    resulting_state: str | None,
    outcome: str,
    reason: str,
    file_hashes: dict[str, str] | None = None,
    authentication: AuthenticationEvidence | None = None,
    authorization: AuthorizationDecision | None = None,
    timestamp_utc: str | None = None,
) -> RunReceipt:
    return RunReceipt(
        run_id=str(uuid4()),
        command=command,
        timestamp_utc=timestamp_utc or utc_now(),
        actor=actor,
        input_identifiers=sanitize_for_receipt(input_identifiers),
        prior_state=prior_state,
        requested_transition=requested_transition,
        resulting_state=resulting_state,
        outcome=outcome,
        reason=reason,
        file_hashes=file_hashes or {},
        application_version=__version__,
        authentication_status=(
            None if authentication is None else authentication.verification_status
        ),
        authenticated_principal_id=(
            None if authentication is None else authentication.authenticated_principal_id
        ),
        authentication_scheme=(
            None if authentication is None else authentication.authentication_scheme
        ),
        authentication_key_id=(
            None if authentication is None else authentication.authentication_key_id
        ),
        authentication_verifier_fingerprint=(
            None if authentication is None else authentication.verifier_fingerprint
        ),
        authentication_operation_id=(
            None if authentication is None else authentication.authentication_operation_id
        ),
        authentication_envelope_hash=(
            None if authentication is None else authentication.authentication_envelope_hash
        ),
        authentication_proof_hash=(
            None if authentication is None else authentication.authentication_proof_hash
        ),
        authenticated_at_utc=(
            None if authentication is None else authentication.authenticated_at_utc
        ),
        authorization_status=(
            None if authorization is None else authorization.status.value
        ),
        authorization_principal_id=(
            None if authorization is None else authorization.principal_id
        ),
        authorization_required_capability=(
            None if authorization is None else authorization.required_capability
        ),
        authorization_prior_state=(
            None
            if authorization is None or authorization.actual_prior_state is None
            else authorization.actual_prior_state.value
        ),
        authorization_requested_state=(
            None
            if authorization is None or authorization.requested_state is None
            else authorization.requested_state.value
        ),
        authorization_scope_version=(
            None if authorization is None else authorization.scope_version
        ),
        authorization_brand_id=(
            None if authorization is None else authorization.brand_id
        ),
        authorization_channel_id=(
            None if authorization is None else authorization.channel_id
        ),
        authorization_destination_id=(
            None if authorization is None else authorization.destination_id
        ),
        authorization_matching_grant_id=(
            None if authorization is None else authorization.matching_grant_id
        ),
        authorization_reason_code=(
            None if authorization is None else authorization.reason.value
        ),
    )


def append_receipt(receipt_log: Path, receipt: RunReceipt) -> None:
    if find_receipt(receipt_log, receipt.run_id) is not None:
        raise ValueError(f"Receipt already exists and is immutable: {receipt.run_id}")
    line = canonical_json(receipt.model_dump(mode="json", exclude_none=True)) + "\n"
    with receipt_log.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(line)
        stream.flush()


def transition_event_from_receipt(
    receipt: RunReceipt,
    *,
    target_type: str,
    target_id: str,
    governed_hash: str | None = None,
) -> dict[str, object]:
    """Build the canonical database event and exact outward receipt payload."""
    identifiers = receipt.input_identifiers
    receipt_payload = receipt.model_dump(mode="json", exclude_none=True)
    for required_nullable in (
        "prior_state",
        "requested_transition",
        "resulting_state",
    ):
        receipt_payload.setdefault(required_nullable, None)
    return {
        "event_id": receipt.run_id,
        "command": receipt.command,
        "asserted_actor": receipt.actor,
        "target_type": target_type,
        "target_id": target_id,
        "candidate_id": identifiers.get("candidate_id"),
        "packet_id": identifiers.get("packet_id"),
        "prior_state": receipt.prior_state,
        "requested_state": receipt.requested_transition,
        "resulting_state": receipt.resulting_state,
        "outcome": receipt.outcome,
        "reason": receipt.reason,
        "governed_hash": governed_hash,
        "input_identifiers_json": canonical_json(identifiers),
        "file_hashes_json": canonical_json(receipt.file_hashes),
        "occurred_at_utc": receipt.timestamp_utc,
        "application_version": receipt.application_version,
        "receipt_json": canonical_json(receipt_payload),
        "authentication_status": receipt.authentication_status,
        "authenticated_principal_id": receipt.authenticated_principal_id,
        "authentication_scheme": receipt.authentication_scheme,
        "authentication_key_id": receipt.authentication_key_id,
        "authentication_verifier_fingerprint": (
            receipt.authentication_verifier_fingerprint
        ),
        "authentication_operation_id": receipt.authentication_operation_id,
        "authentication_envelope_hash": receipt.authentication_envelope_hash,
        "authentication_proof_hash": receipt.authentication_proof_hash,
        "authenticated_at_utc": receipt.authenticated_at_utc,
        "authorization_status": receipt.authorization_status,
        "authorization_principal_id": receipt.authorization_principal_id,
        "authorization_required_capability": (
            receipt.authorization_required_capability
        ),
        "authorization_prior_state": receipt.authorization_prior_state,
        "authorization_requested_state": receipt.authorization_requested_state,
        "authorization_scope_version": receipt.authorization_scope_version,
        "authorization_brand_id": receipt.authorization_brand_id,
        "authorization_channel_id": receipt.authorization_channel_id,
        "authorization_destination_id": receipt.authorization_destination_id,
        "authorization_matching_grant_id": (
            receipt.authorization_matching_grant_id
        ),
        "authorization_reason_code": receipt.authorization_reason_code,
    }


def append_canonical_receipt(receipt_log: Path, receipt_json: str) -> None:
    """Append the exact canonical payload already committed with an event."""
    with receipt_log.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(receipt_json + "\n")
        stream.flush()


def project_transition_event(
    database_path: Path, receipt_log: Path, event_id: str
) -> RunReceipt:
    """Append one canonical event payload, safely recovering an interrupted mark."""
    event = database.get_transition_event(database_path, event_id)
    if event is None:
        raise KeyError(f"Unknown transition event: {event_id}")
    receipt = canonical_receipt_from_event(event)
    try:
        existing = find_receipt(receipt_log, event_id)
        if existing is None:
            append_canonical_receipt(receipt_log, str(event["receipt_json"]))
        elif canonical_json(existing) != str(event["receipt_json"]):
            raise ValueError(
                f"Receipt run ID collision has different content: {event_id}"
            )
        database.mark_transition_event_projected(database_path, event_id, utc_now())
    except Exception as error:
        raise ReceiptProjectionError(event_id, error) from error
    return receipt


def reconcile_pending_receipts(database_path: Path, receipt_log: Path) -> int:
    """Project every pending canonical event without rewriting prior JSONL lines."""
    database.migrate_database(database_path)
    pending = database.pending_transition_events(database_path)
    for event in pending:
        project_transition_event(database_path, receipt_log, str(event["event_id"]))
    return len(pending)


def find_receipt(receipt_log: Path, run_id: str) -> dict[str, Any] | None:
    if not receipt_log.exists():
        return None
    with receipt_log.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("run_id") == run_id:
                return record
    return None
