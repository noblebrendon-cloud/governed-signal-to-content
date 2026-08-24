"""Tamper-evident chaining and read-only integrity verification."""

from __future__ import annotations

import json
import sqlite3
import base64
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import quote

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .hashing import canonical_json, canonical_json_hash
from .models import (
    AuthorizationReason,
    IntegrityFailure,
    IntegrityVerificationResult,
    PacketScope,
    RunReceipt,
)


CHAIN_VERSION = "1.0"
CHAIN_ORIGIN = "native"
CHAIN_HASH_ALGORITHM = "sha256"
CHAIN_DOMAIN = "GS2C_TRANSITION_EVENT_CHAIN_V1"
CHAIN_ACTIVATION_DOMAIN = "GS2C_TRANSITION_EVENT_CHAIN_ACTIVATION_V1"
LEGACY_ORDERING = "occurred_at_utc,event_id"

CHAIN_RECEIPT_FIELDS = (
    "chain_version",
    "chain_origin",
    "event_sequence",
    "previous_event_hash",
    "event_hash",
)

IMMUTABLE_EVENT_FIELDS = (
    "event_id",
    "command",
    "asserted_actor",
    "target_type",
    "target_id",
    "candidate_id",
    "packet_id",
    "prior_state",
    "requested_state",
    "resulting_state",
    "outcome",
    "reason",
    "governed_hash",
    "occurred_at_utc",
    "application_version",
    "authentication_status",
    "authenticated_principal_id",
    "authentication_scheme",
    "authentication_key_id",
    "authentication_verifier_fingerprint",
    "authentication_operation_id",
    "authentication_envelope_hash",
    "authentication_proof_hash",
    "authenticated_at_utc",
)

LEGACY_IMMUTABLE_EVENT_FIELDS = (
    *IMMUTABLE_EVENT_FIELDS,
    "input_identifiers_json",
    "file_hashes_json",
    "receipt_json",
)


class CanonicalChainError(RuntimeError):
    """Canonical event evidence cannot be safely verified or extended."""


@dataclass(frozen=True, slots=True)
class PreparedChainedEvent:
    receipt_json: str
    chain_version: str
    chain_origin: str
    event_sequence: int
    previous_event_hash: str
    event_hash: str


def _json_object(value: object, *, field: str) -> dict[str, Any]:
    try:
        decoded = json.loads(str(value))
    except (TypeError, json.JSONDecodeError) as error:
        raise CanonicalChainError(f"Canonical event {field} is not valid JSON") from error
    if not isinstance(decoded, dict):
        raise CanonicalChainError(f"Canonical event {field} must be a JSON object")
    return decoded


def _legacy_event_material(event: Mapping[str, object]) -> dict[str, object]:
    return {field: event.get(field) for field in LEGACY_IMMUTABLE_EVENT_FIELDS}


def calculate_activation_hash(events: Sequence[Mapping[str, object]]) -> str:
    """Hash an honest retrospective snapshot of all unchained legacy events."""
    ordered = sorted(
        events,
        key=lambda event: (
            str(event.get("occurred_at_utc") or ""),
            str(event.get("event_id") or ""),
        ),
    )
    material = {
        "domain": CHAIN_ACTIVATION_DOMAIN,
        "chain_version": CHAIN_VERSION,
        "ordering": LEGACY_ORDERING,
        "legacy_event_count": len(ordered),
        "events": [_legacy_event_material(event) for event in ordered],
    }
    return canonical_json_hash(material)


def _native_event_material(
    event: Mapping[str, object], receipt_without_event_hash: Mapping[str, object]
) -> dict[str, object]:
    material = {field: event.get(field) for field in IMMUTABLE_EVENT_FIELDS}
    material["input_identifiers"] = _json_object(
        event.get("input_identifiers_json"), field="input_identifiers_json"
    )
    material["file_hashes"] = _json_object(
        event.get("file_hashes_json"), field="file_hashes_json"
    )
    material["receipt"] = dict(receipt_without_event_hash)
    return material


def calculate_event_hash(
    event: Mapping[str, object],
    *,
    event_sequence: int,
    previous_event_hash: str,
    receipt_without_event_hash: Mapping[str, object],
    chain_version: str = CHAIN_VERSION,
    chain_origin: str = CHAIN_ORIGIN,
    domain: str = CHAIN_DOMAIN,
) -> str:
    """Calculate one domain-separated native event-chain hash."""
    material = {
        "domain": domain,
        "chain_version": chain_version,
        "chain_origin": chain_origin,
        "event_sequence": event_sequence,
        "previous_event_hash": previous_event_hash,
        "event": _native_event_material(event, receipt_without_event_hash),
    }
    return canonical_json_hash(material)


def _validate_event_receipt_alignment(
    event: Mapping[str, object], receipt: RunReceipt
) -> None:
    expected = {
        "event_id": receipt.run_id,
        "command": receipt.command,
        "asserted_actor": receipt.actor,
        "prior_state": receipt.prior_state,
        "requested_state": receipt.requested_transition,
        "resulting_state": receipt.resulting_state,
        "outcome": receipt.outcome,
        "reason": receipt.reason,
        "occurred_at_utc": receipt.timestamp_utc,
        "application_version": receipt.application_version,
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
    mismatches = [field for field, value in expected.items() if event.get(field) != value]
    if _json_object(
        event.get("input_identifiers_json"), field="input_identifiers_json"
    ) != receipt.input_identifiers:
        mismatches.append("input_identifiers")
    if _json_object(event.get("file_hashes_json"), field="file_hashes_json") != (
        receipt.file_hashes
    ):
        mismatches.append("file_hashes")
    if mismatches:
        raise CanonicalChainError(
            "Canonical event and receipt evidence disagree: "
            + ", ".join(sorted(mismatches))
        )


def prepare_chained_event(
    event: Mapping[str, object], *, event_sequence: int, previous_event_hash: str
) -> PreparedChainedEvent:
    """Enrich a pre-commit event receipt and calculate its native chain identity."""
    receipt_payload = _json_object(event.get("receipt_json"), field="receipt_json")
    for field in CHAIN_RECEIPT_FIELDS:
        receipt_payload.pop(field, None)
    RunReceipt.model_validate(receipt_payload)
    receipt_payload.update(
        {
            "chain_version": CHAIN_VERSION,
            "chain_origin": CHAIN_ORIGIN,
            "event_sequence": event_sequence,
            "previous_event_hash": previous_event_hash,
        }
    )
    event_hash = calculate_event_hash(
        event,
        event_sequence=event_sequence,
        previous_event_hash=previous_event_hash,
        receipt_without_event_hash=receipt_payload,
    )
    receipt_payload["event_hash"] = event_hash
    receipt = RunReceipt.model_validate(receipt_payload)
    _validate_event_receipt_alignment(event, receipt)
    return PreparedChainedEvent(
        receipt_json=canonical_json(receipt_payload),
        chain_version=CHAIN_VERSION,
        chain_origin=CHAIN_ORIGIN,
        event_sequence=event_sequence,
        previous_event_hash=previous_event_hash,
        event_hash=event_hash,
    )


def canonical_receipt_from_event(event: Mapping[str, object]) -> RunReceipt:
    """Validate and return the exact receipt stored on a canonical event."""
    receipt_payload = _json_object(event.get("receipt_json"), field="receipt_json")
    receipt = RunReceipt.model_validate(receipt_payload)
    event_sequence = event.get("event_sequence")
    if event_sequence is None:
        if receipt.chain_version is not None:
            raise CanonicalChainError(
                "Unchained legacy event claims a native receipt chain identity"
            )
        return receipt

    if canonical_json(receipt_payload) != str(event.get("receipt_json")):
        raise CanonicalChainError("Native canonical receipt JSON is not canonical")
    expected_metadata = {
        "chain_version": event.get("chain_version"),
        "chain_origin": event.get("chain_origin"),
        "event_sequence": int(event_sequence),
        "previous_event_hash": event.get("previous_event_hash"),
        "event_hash": event.get("event_hash"),
    }
    actual_metadata = {field: receipt_payload.get(field) for field in expected_metadata}
    if actual_metadata != expected_metadata:
        raise CanonicalChainError("Canonical event and receipt chain metadata disagree")
    receipt_without_hash = dict(receipt_payload)
    receipt_without_hash.pop("event_hash", None)
    recomputed = calculate_event_hash(
        event,
        event_sequence=int(event_sequence),
        previous_event_hash=str(event.get("previous_event_hash")),
        receipt_without_event_hash=receipt_without_hash,
        chain_version=str(event.get("chain_version")),
        chain_origin=str(event.get("chain_origin")),
    )
    if recomputed != event.get("event_hash"):
        raise CanonicalChainError(
            f"Canonical event hash mismatch: {event.get('event_id')}"
        )
    _validate_event_receipt_alignment(event, receipt)
    return receipt


def _read_only_connection(database_path: Path) -> sqlite3.Connection:
    resolved = database_path.resolve().as_posix()
    uri = f"file:{quote(resolved, safe='/:')}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
        ).fetchone()
        is not None
    )


def _failure(
    scope: str,
    code: str,
    message: str,
    *,
    event_id: object = None,
    event_sequence: object = None,
    receipt_line: int | None = None,
) -> IntegrityFailure:
    try:
        normalized_sequence = None if event_sequence is None else int(event_sequence)
    except (TypeError, ValueError):
        normalized_sequence = None
    return IntegrityFailure(
        scope=scope,  # type: ignore[arg-type]
        code=code,
        message=message,
        event_id=None if event_id is None else str(event_id),
        event_sequence=normalized_sequence,
        receipt_line=receipt_line,
    )


def _sorted_failures(failures: list[IntegrityFailure]) -> tuple[IntegrityFailure, ...]:
    return tuple(
        sorted(
            failures,
            key=lambda failure: (
                failure.scope,
                failure.event_sequence if failure.event_sequence is not None else 2**63,
                failure.event_id or "",
                failure.receipt_line or 0,
                failure.code,
            ),
        )
    )


def _verify_authorization_event_bindings(
    rows: Sequence[Mapping[str, object]],
    *,
    policy_start_sequence: int | None,
    grant_by_id: Mapping[str, Mapping[str, object]],
    failures: list[IntegrityFailure],
) -> None:
    """Validate canonical authorization vocabulary and exact prior active grants."""
    scopes = {
        "approve": ("packet.approve", "AWAITING_APPROVAL", "APPROVED"),
        "reject": ("packet.reject", "AWAITING_APPROVAL", "REJECTED"),
        "release": ("packet.release", "APPROVED", "RELEASED"),
        "bootstrap-capability-policy": ("policy.manage_capabilities", None, None),
        "grant-capability": ("policy.manage_capabilities", None, None),
        "revoke-capability": ("policy.manage_capabilities", None, None),
        "register-destination-binding": ("effect.manage_bindings", None, None),
        "register-effect-executor": ("effect.manage_bindings", None, None),
    }
    authority_commands = set(scopes)
    for event in rows:
        status = event.get("authorization_status")
        sequence = event.get("event_sequence")
        if (
            policy_start_sequence is not None
            and isinstance(sequence, int)
            and sequence >= policy_start_sequence
            and event.get("authentication_status") in {"verified", "replay_rejected"}
            and event.get("command") in authority_commands
            and status is None
        ):
            failures.append(
                _failure(
                    "canonical_policy",
                    "missing_authorization_evidence",
                    "Post-bootstrap authenticated authority event lacks authorization evidence",
                    event_id=event.get("event_id"),
                    event_sequence=sequence,
                )
            )
        if status is None:
            continue
        expected = scopes.get(str(event.get("command")))
        actual = (
            event.get("authorization_required_capability"),
            event.get("authorization_prior_state"),
            event.get("authorization_requested_state"),
        )
        if expected != actual:
            failures.append(
                _failure(
                    "canonical_policy",
                    "invalid_authorization_scope",
                    "Authorization evidence uses a noncanonical capability/state scope",
                    event_id=event.get("event_id"),
                    event_sequence=sequence,
                )
            )
        scope_values = (
            event.get("authorization_brand_id"),
            event.get("authorization_channel_id"),
            event.get("authorization_destination_id"),
        )
        scope_version = event.get("authorization_scope_version")
        if scope_version is None:
            scope_valid = scope_values == (None, None, None)
        elif scope_values == (None, None, None):
            scope_valid = event.get("authorization_required_capability") in {
                "policy.manage_capabilities",
                "effect.manage_bindings",
            } or event.get("authorization_reason_code") == "SCOPE_REQUIRED"
        else:
            try:
                PacketScope(
                    brand_id=scope_values[0],
                    channel_id=scope_values[1],
                    destination_id=scope_values[2],
                )
            except Exception:
                scope_valid = False
            else:
                scope_valid = scope_version == "1.0"
        if not scope_valid:
            failures.append(
                _failure(
                    "canonical_policy",
                    "invalid_authorization_packet_scope",
                    "Authorization evidence has malformed or inapplicable packet scope",
                    event_id=event.get("event_id"),
                    event_sequence=sequence,
                )
            )
        if sequence is None:
            failures.append(
                _failure(
                    "canonical_policy",
                    "fabricated_historical_authorization",
                    "Unchained historical event claims authorization evidence",
                    event_id=event.get("event_id"),
                )
            )
        if event.get("authorization_principal_id") != event.get(
            "authenticated_principal_id"
        ):
            failures.append(
                _failure(
                    "canonical_policy",
                    "authorization_principal_mismatch",
                    "Authorization principal differs from authenticated principal",
                    event_id=event.get("event_id"),
                    event_sequence=sequence,
                )
            )
        matching_id = event.get("authorization_matching_grant_id")
        if (
            status == "allowed"
            and not matching_id
            and event.get("authorization_reason_code") != "BOOTSTRAP_ALLOWED"
        ):
            failures.append(
                _failure(
                    "canonical_policy",
                    "missing_authorizing_grant",
                    "Allowed authorization lacks its exact canonical grant",
                    event_id=event.get("event_id"),
                    event_sequence=sequence,
                )
            )
        if status != "allowed" or not matching_id:
            continue
        grant = grant_by_id.get(str(matching_id))
        nonpacket = event.get("authorization_required_capability") in {
            "policy.manage_capabilities",
            "effect.manage_bindings",
        }
        mismatch = (
            grant is None
            or grant.get("subject_principal_id")
            != event.get("authorization_principal_id")
            or grant.get("capability")
            != event.get("authorization_required_capability")
            or grant.get("expected_prior_state")
            != event.get("authorization_prior_state")
            or grant.get("requested_state")
            != event.get("authorization_requested_state")
            or not isinstance(sequence, int)
            or not isinstance(grant.get("event_sequence"), int)
            or int(grant.get("event_sequence", 2**63)) >= int(sequence or -1)
            or (
                isinstance(grant.get("revocation_sequence"), int)
                and int(grant["revocation_sequence"]) < int(sequence or -1)
            )
        )
        if not nonpacket:
            mismatch = mismatch or (
                grant is None
                or grant.get("scope_version") != scope_version
                or grant.get("brand_id") != scope_values[0]
                or grant.get("channel_id") != scope_values[1]
                or grant.get("destination_id") != scope_values[2]
            )
        if mismatch:
            failures.append(
                _failure(
                    "canonical_policy",
                    "authorizing_grant_mismatch",
                    "Allowed authorization does not match an active prior grant",
                    event_id=event.get("event_id"),
                    event_sequence=sequence,
                )
            )


def verify_integrity(
    database_path: Path, receipt_log: Path
) -> IntegrityVerificationResult:
    """Read and verify the complete canonical chain and its JSONL projection."""
    failures: list[IntegrityFailure] = []
    capability_grants_checked = 0
    capability_revocations_checked = 0
    authorization_events_checked = 0
    destination_bindings_checked = 0
    effect_executors_checked = 0
    external_effect_requests_checked = 0
    external_effect_dispatches_checked = 0
    external_effect_results_checked = 0
    with closing(_read_only_connection(database_path)) as connection:
        schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        required_tables = {
            "transition_events",
            "transition_event_chain_entries",
            "transition_event_chain_state",
        }
        missing_tables = sorted(
            table for table in required_tables if not _table_exists(connection, table)
        )
        if schema_version < 3 or missing_tables:
            failures.append(
                _failure(
                    "canonical_chain",
                    "chain_not_activated",
                    "Schema-3 event chaining is not activated"
                    + (f"; missing tables: {', '.join(missing_tables)}" if missing_tables else ""),
                )
            )
            return IntegrityVerificationResult(
                database_schema_version=schema_version,
                chain_version=None,
                activation_hash=None,
                canonical_chain_valid=False,
                native_chain_start_event_id=None,
                events_checked=0,
                legacy_events_checked=0,
                native_events_checked=0,
                canonical_policy_valid=False,
                canonical_external_effect_valid=False,
                projection_valid=True,
                projection_complete=False,
                receipts_checked=0,
                pending_projection_count=0,
                legacy_unbound_receipt_count=0,
                failures=_sorted_failures(failures),
            )

        state_row = connection.execute(
            "SELECT * FROM transition_event_chain_state WHERE singleton_id = 1"
        ).fetchone()
        if state_row is None:
            failures.append(
                _failure(
                    "canonical_chain",
                    "missing_chain_state",
                    "Canonical event chain state is missing",
                )
            )
            state: dict[str, object] = {}
        else:
            state = dict(state_row)

        rows = [
            dict(row)
            for row in connection.execute(
                """
                SELECT e.*, c.chain_version, c.chain_origin, c.event_sequence,
                       c.previous_event_hash, c.event_hash
                FROM transition_events AS e
                LEFT JOIN transition_event_chain_entries AS c
                  ON c.event_id = e.event_id
                ORDER BY CASE WHEN c.event_sequence IS NULL THEN 0 ELSE 1 END,
                         e.occurred_at_utc, e.event_id, c.event_sequence
                """
            ).fetchall()
        ]
        orphan_entries = connection.execute(
            """
            SELECT c.event_id, c.event_sequence
            FROM transition_event_chain_entries AS c
            LEFT JOIN transition_events AS e ON e.event_id = c.event_id
            WHERE e.event_id IS NULL
            ORDER BY c.event_sequence, c.event_id
            """
        ).fetchall()
        for orphan in orphan_entries:
            failures.append(
                _failure(
                    "canonical_chain",
                    "orphan_chain_entry",
                    "Chain entry has no canonical transition event",
                    event_id=orphan["event_id"],
                    event_sequence=orphan["event_sequence"],
                )
            )

        legacy_rows = [row for row in rows if row.get("event_sequence") is None]
        native_rows = [row for row in rows if row.get("event_sequence") is not None]
        activation_hash = calculate_activation_hash(legacy_rows)
        if state:
            fixed_state = {
                "chain_version": CHAIN_VERSION,
                "chain_origin": CHAIN_ORIGIN,
                "hash_algorithm": CHAIN_HASH_ALGORITHM,
                "event_domain": CHAIN_DOMAIN,
                "activation_domain": CHAIN_ACTIVATION_DOMAIN,
                "legacy_ordering": LEGACY_ORDERING,
                "legacy_event_count": len(legacy_rows),
                "activation_hash": activation_hash,
            }
            mismatches = [
                field for field, expected in fixed_state.items() if state.get(field) != expected
            ]
            if mismatches:
                failures.append(
                    _failure(
                        "canonical_chain",
                        "activation_checkpoint_mismatch",
                        "Activation checkpoint mismatch: "
                        + ", ".join(sorted(mismatches)),
                    )
                )

        valid_native_rows: list[dict[str, object]] = []
        for event in native_rows:
            sequence_value = event.get("event_sequence")
            if (
                not isinstance(sequence_value, int)
                or isinstance(sequence_value, bool)
                or sequence_value < 1
            ):
                failures.append(
                    _failure(
                        "canonical_chain",
                        "invalid_event_sequence",
                        "Native event sequence must be a positive integer",
                        event_id=event.get("event_id"),
                    )
                )
            else:
                valid_native_rows.append(event)

        expected_previous = activation_hash
        expected_sequence = 1
        for event in sorted(valid_native_rows, key=lambda row: int(row["event_sequence"])):
            event_id = event.get("event_id")
            sequence = int(event["event_sequence"])
            if sequence != expected_sequence:
                failures.append(
                    _failure(
                        "canonical_chain",
                        "sequence_discontinuity",
                        f"Expected event sequence {expected_sequence}, found {sequence}",
                        event_id=event_id,
                        event_sequence=sequence,
                    )
                )
            if event.get("previous_event_hash") != expected_previous:
                failures.append(
                    _failure(
                        "canonical_chain",
                        "predecessor_mismatch",
                        "Event predecessor does not match the prior canonical hash",
                        event_id=event_id,
                        event_sequence=sequence,
                    )
                )
            try:
                canonical_receipt_from_event(event)
            except Exception as error:
                failures.append(
                    _failure(
                        "canonical_chain",
                        "event_hash_mismatch",
                        str(error),
                        event_id=event_id,
                        event_sequence=sequence,
                    )
                )
            expected_previous = str(event.get("event_hash"))
            expected_sequence = sequence + 1

        native_start = None if not valid_native_rows else str(
            min(valid_native_rows, key=lambda row: int(row["event_sequence"]))[
                "event_id"
            ]
        )
        if state:
            if valid_native_rows:
                tail = max(
                    valid_native_rows, key=lambda row: int(row["event_sequence"])
                )
                expected_head = {
                    "head_sequence": int(tail["event_sequence"]),
                    "head_event_id": tail["event_id"],
                    "head_event_hash": tail["event_hash"],
                }
            else:
                expected_head = {
                    "head_sequence": 0,
                    "head_event_id": None,
                    "head_event_hash": activation_hash,
                }
            head_mismatches = [
                field for field, expected in expected_head.items() if state.get(field) != expected
            ]
            if head_mismatches:
                failures.append(
                    _failure(
                        "canonical_chain",
                        "chain_head_mismatch",
                        "Chain head mismatch: " + ", ".join(sorted(head_mismatches)),
                    )
                )

        policy_tables = {
            "capability_grants",
            "capability_revocations",
            "capability_policy_state",
            "authenticated_operations",
            "trusted_principals",
        }
        missing_policy_tables = sorted(
            table for table in policy_tables if not _table_exists(connection, table)
        )
        if schema_version < 4 or missing_policy_tables:
            failures.append(
                _failure(
                    "canonical_policy",
                    "policy_not_activated",
                    "Schema-4 capability policy is not activated"
                    + (
                        f"; missing tables: {', '.join(missing_policy_tables)}"
                        if missing_policy_tables
                        else ""
                    ),
                )
            )
        else:
            if schema_version < 5:
                failures.append(
                    _failure(
                        "canonical_policy",
                        "scope_not_activated",
                        "Schema-5 packet scope authorization is not activated",
                    )
                )
            grants = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT g.*, c.event_sequence,
                           r.revocation_id, rc.event_sequence AS revocation_sequence
                    FROM capability_grants AS g
                    LEFT JOIN transition_event_chain_entries AS c
                      ON c.event_id = g.policy_event_id
                    LEFT JOIN capability_revocations AS r ON r.grant_id = g.grant_id
                    LEFT JOIN transition_event_chain_entries AS rc
                      ON rc.event_id = r.policy_event_id
                    ORDER BY c.event_sequence, g.grant_id
                    """
                ).fetchall()
            ]
            revocations = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT r.*, c.event_sequence
                    FROM capability_revocations AS r
                    LEFT JOIN transition_event_chain_entries AS c
                      ON c.event_id = r.policy_event_id
                    ORDER BY c.event_sequence, r.revocation_id
                    """
                ).fetchall()
            ]
            capability_grants_checked = len(grants)
            capability_revocations_checked = len(revocations)
            authorization_events_checked = sum(
                event.get("authorization_status") is not None for event in rows
            )
            event_by_id = {str(event["event_id"]): event for event in rows}
            grant_by_id = {str(grant["grant_id"]): grant for grant in grants}
            trusted_ids = {
                str(row["principal_id"])
                for row in connection.execute(
                    "SELECT principal_id FROM trusted_principals"
                ).fetchall()
            }
            authenticated_operations = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM authenticated_operations ORDER BY operation_id"
                ).fetchall()
            ]
            authenticated_operation_by_id = {
                str(operation["operation_id"]): operation
                for operation in authenticated_operations
            }
            authenticated_operation_ids = set(authenticated_operation_by_id)
            authenticated_envelopes: dict[str, dict[str, Any]] = {}
            for operation in authenticated_operations:
                operation_id = str(operation["operation_id"])
                event = event_by_id.get(str(operation["adjudication_event_id"]))
                try:
                    envelope = json.loads(str(operation["envelope_json"]))
                    if not isinstance(envelope, dict):
                        raise TypeError("authenticated envelope is not a JSON object")
                    if canonical_json(envelope) != operation["envelope_json"]:
                        raise ValueError("authenticated envelope JSON is not canonical")
                except (TypeError, ValueError, json.JSONDecodeError) as error:
                    failures.append(
                        _failure(
                            "canonical_policy",
                            "invalid_authenticated_operation",
                            f"Authenticated operation envelope is invalid: {error}",
                            event_id=operation.get("adjudication_event_id"),
                        )
                    )
                    continue
                authenticated_envelopes[operation_id] = envelope
                proof_material = {
                    "schema_version": "1.0",
                    "envelope": envelope,
                    "signature_b64": operation["signature_b64"],
                }
                common_mismatch = (
                    event is None
                    or envelope.get("operation_id") != operation_id
                    or envelope.get("principal_id") != operation["principal_id"]
                    or envelope.get("authentication_scheme")
                    != operation["authentication_scheme"]
                    or envelope.get("key_id") != operation["key_id"]
                    or canonical_json_hash(envelope) != operation["envelope_hash"]
                    or canonical_json_hash(proof_material) != operation["proof_hash"]
                    or event.get("authentication_status") != "verified"
                    or event.get("authenticated_principal_id")
                    != operation["principal_id"]
                    or event.get("authentication_scheme")
                    != operation["authentication_scheme"]
                    or event.get("authentication_key_id") != operation["key_id"]
                    or event.get("authentication_verifier_fingerprint")
                    != operation["verifier_fingerprint"]
                    or event.get("authentication_operation_id") != operation_id
                    or event.get("authentication_envelope_hash")
                    != operation["envelope_hash"]
                    or event.get("authentication_proof_hash")
                    != operation["proof_hash"]
                    or event.get("authenticated_at_utc")
                    != operation["verified_at_utc"]
                    or event.get("outcome") != operation["adjudication_outcome"]
                )
                try:
                    identifiers = (
                        {}
                        if event is None
                        else _json_object(
                            event.get("input_identifiers_json"),
                            field="input_identifiers_json",
                        )
                    )
                except CanonicalChainError:
                    identifiers = {}
                    common_mismatch = True
                target_type = envelope.get("target_type")
                if target_type == "packet":
                    binding_mismatch = (
                        event is None
                        or event.get("command") != envelope.get("operation")
                        or event.get("target_type") != "packet"
                        or event.get("target_id") != envelope.get("target_id")
                        or identifiers.get("authentication_operation_id")
                        != operation_id
                        or identifiers.get("packet_id") != envelope.get("target_id")
                        or identifiers.get("candidate_id")
                        != envelope.get("candidate_id")
                        or identifiers.get("approval_id")
                        != envelope.get("approval_id")
                        or identifiers.get("approval_decision")
                        != envelope.get("approval_decision")
                        or identifiers.get("scope_version")
                        != envelope.get("scope_version")
                        or identifiers.get("brand_id") != envelope.get("brand_id")
                        or identifiers.get("channel_id")
                        != envelope.get("channel_id")
                        or identifiers.get("destination_id")
                        != envelope.get("destination_id")
                        or (
                            envelope.get("approval_transition_event_id") is not None
                            and identifiers.get("approval_transition_event_id")
                            != envelope.get("approval_transition_event_id")
                        )
                    )
                elif target_type == "capability_policy":
                    binding_mismatch = (
                        event is None
                        or event.get("command") != envelope.get("operation")
                        or event.get("target_type") != "capability_policy"
                        or event.get("target_id") != "capability_policy"
                        or envelope.get("target_id") != "capability_policy"
                        or identifiers.get("authentication_operation_id")
                        != operation_id
                        or identifiers.get("policy_grant_id")
                        != envelope.get("grant_id")
                        or identifiers.get("subject_principal_id")
                        != envelope.get("subject_principal_id")
                        or identifiers.get("capability") != envelope.get("capability")
                        or identifiers.get("expected_prior_state")
                        != envelope.get("expected_prior_state")
                        or identifiers.get("requested_state")
                        != envelope.get("requested_state")
                        or identifiers.get("scope_version")
                        != envelope.get("scope_version")
                        or identifiers.get("brand_id") != envelope.get("brand_id")
                        or identifiers.get("channel_id")
                        != envelope.get("channel_id")
                        or identifiers.get("destination_id")
                        != envelope.get("destination_id")
                        or (
                            envelope.get("revocation_id") is not None
                            and identifiers.get("policy_revocation_id")
                            != envelope.get("revocation_id")
                        )
                    )
                elif target_type == "external_destination_binding":
                    binding_mismatch = (
                        event is None
                        or event.get("command") != "register-destination-binding"
                        or event.get("target_type") != target_type
                        or event.get("target_id") != envelope.get("target_id")
                        or identifiers.get("authentication_operation_id")
                        != operation_id
                        or identifiers.get("destination_binding_id")
                        != envelope.get("target_id")
                        or identifiers.get("scope_version")
                        != envelope.get("scope_version")
                        or identifiers.get("brand_id") != envelope.get("brand_id")
                        or identifiers.get("channel_id")
                        != envelope.get("channel_id")
                        or identifiers.get("destination_id")
                        != envelope.get("destination_id")
                        or identifiers.get("adapter_id") != envelope.get("adapter_id")
                        or identifiers.get("external_target_ref")
                        != envelope.get("external_target_ref")
                        or identifiers.get("credential_ref")
                        != envelope.get("credential_ref")
                    )
                elif target_type == "trusted_effect_executor":
                    binding_mismatch = (
                        event is None
                        or event.get("command") != "register-effect-executor"
                        or event.get("target_type") != target_type
                        or event.get("target_id") != envelope.get("target_id")
                        or identifiers.get("authentication_operation_id")
                        != operation_id
                        or identifiers.get("executor_id") != envelope.get("target_id")
                        or identifiers.get("executor_authentication_scheme")
                        != envelope.get("executor_authentication_scheme")
                        or identifiers.get("executor_key_id")
                        != envelope.get("executor_key_id")
                        or identifiers.get("executor_verifier_fingerprint")
                        != envelope.get("executor_verifier_fingerprint")
                        or identifiers.get("allowed_adapter_ids")
                        != envelope.get("allowed_adapter_ids")
                    )
                else:
                    binding_mismatch = True
                if common_mismatch or binding_mismatch:
                    failures.append(
                        _failure(
                            "canonical_policy",
                            "authenticated_operation_mismatch",
                            "Authenticated operation does not match its canonical adjudication event",
                            event_id=operation.get("adjudication_event_id"),
                            event_sequence=(
                                None if event is None else event.get("event_sequence")
                            ),
                        )
                    )

            policy_start_sequence: int | None = None
            state_rows = connection.execute(
                "SELECT * FROM capability_policy_state ORDER BY singleton_id"
            ).fetchall()
            if len(state_rows) > 1:
                failures.append(
                    _failure(
                        "canonical_policy",
                        "invalid_policy_state",
                        "Capability policy has more than one bootstrap state row",
                    )
                )
            if grants and not state_rows:
                failures.append(
                    _failure(
                        "canonical_policy",
                        "missing_policy_state",
                        "Capability grants exist without canonical bootstrap state",
                    )
                )
            if state_rows:
                policy_state = dict(state_rows[0])
                bootstrap_grant = grant_by_id.get(
                    str(policy_state["bootstrap_grant_id"])
                )
                bootstrap_event = event_by_id.get(
                    str(policy_state["bootstrap_event_id"])
                )
                if bootstrap_event is not None and isinstance(
                    bootstrap_event.get("event_sequence"), int
                ):
                    policy_start_sequence = int(bootstrap_event["event_sequence"])
                if (
                    policy_state.get("singleton_id") != 1
                    or bootstrap_grant is None
                    or bootstrap_event is None
                    or bootstrap_grant["capability"]
                    != "policy.manage_capabilities"
                    or bootstrap_grant["subject_principal_id"]
                    != policy_state["bootstrap_principal_id"]
                    or bootstrap_grant["policy_event_id"]
                    != policy_state["bootstrap_event_id"]
                    or bootstrap_grant["authenticated_operation_id"]
                    != policy_state["bootstrap_operation_id"]
                    or policy_state["bootstrap_operation_id"]
                    not in authenticated_operation_ids
                    or bootstrap_event.get("command")
                    != "bootstrap-capability-policy"
                    or str(policy_state["bootstrap_principal_id"])
                    not in trusted_ids
                ):
                    failures.append(
                        _failure(
                            "canonical_policy",
                            "bootstrap_linkage_mismatch",
                            "Capability-policy bootstrap state does not match its grant/event",
                            event_id=policy_state.get("bootstrap_event_id"),
                        )
                    )

                active_admins = {
                    str(grant["subject_principal_id"])
                    for grant in grants
                    if grant["capability"] == "policy.manage_capabilities"
                    and grant.get("revocation_id") is None
                }
                if not active_admins:
                    failures.append(
                        _failure(
                            "canonical_policy",
                            "missing_effective_policy_admin",
                            "Bootstrapped policy has no effective policy administrator",
                        )
                    )

            canonical_scopes = {
                "packet.approve": ("AWAITING_APPROVAL", "APPROVED"),
                "packet.reject": ("AWAITING_APPROVAL", "REJECTED"),
                "packet.release": ("APPROVED", "RELEASED"),
                "policy.manage_capabilities": (None, None),
                "effect.manage_bindings": (None, None),
            }

            for grant in grants:
                grant_id = str(grant["grant_id"])
                event = event_by_id.get(str(grant["policy_event_id"]))
                operation = authenticated_operation_by_id.get(
                    str(grant["authenticated_operation_id"])
                )
                envelope = authenticated_envelopes.get(
                    str(grant["authenticated_operation_id"]), {}
                )
                try:
                    identifiers = (
                        {}
                        if event is None
                        else _json_object(
                            event.get("input_identifiers_json"),
                            field="input_identifiers_json",
                        )
                    )
                except CanonicalChainError:
                    identifiers = {}
                if (
                    event is None
                    or event.get("outcome") != "accepted"
                    or event.get("target_type") != "capability_policy"
                    or event.get("command")
                    not in {"bootstrap-capability-policy", "grant-capability"}
                    or event.get("authenticated_principal_id")
                    != grant["granted_by_principal_id"]
                    or event.get("authentication_operation_id")
                    != grant["authenticated_operation_id"]
                    or identifiers.get("policy_grant_id") != grant_id
                    or identifiers.get("subject_principal_id")
                    != grant["subject_principal_id"]
                    or identifiers.get("capability") != grant["capability"]
                    or identifiers.get("expected_prior_state")
                    != grant["expected_prior_state"]
                    or identifiers.get("requested_state") != grant["requested_state"]
                    or identifiers.get("scope_version") != grant.get("scope_version")
                    or identifiers.get("brand_id") != grant.get("brand_id")
                    or identifiers.get("channel_id") != grant.get("channel_id")
                    or identifiers.get("destination_id")
                    != grant.get("destination_id")
                    or grant["authenticated_operation_id"]
                    not in authenticated_operation_ids
                    or operation is None
                    or operation.get("adjudication_event_id")
                    != grant["policy_event_id"]
                    or envelope.get("operation")
                    not in {"bootstrap-capability-policy", "grant-capability"}
                    or envelope.get("grant_id") != grant_id
                    or envelope.get("subject_principal_id")
                    != grant["subject_principal_id"]
                    or envelope.get("capability") != grant["capability"]
                    or envelope.get("expected_prior_state")
                    != grant["expected_prior_state"]
                    or envelope.get("requested_state")
                    != grant["requested_state"]
                    or envelope.get("scope_version") != grant.get("scope_version")
                    or envelope.get("brand_id") != grant.get("brand_id")
                    or envelope.get("channel_id") != grant.get("channel_id")
                    or envelope.get("destination_id")
                    != grant.get("destination_id")
                    or event.get("occurred_at_utc") != grant["created_at_utc"]
                    or event.get("application_version") != grant["application_version"]
                    or event.get("authorization_status") != "allowed"
                ):
                    failures.append(
                        _failure(
                            "canonical_policy",
                            "grant_event_mismatch",
                            "Capability grant does not match its canonical event",
                            event_id=grant.get("policy_event_id"),
                            event_sequence=grant.get("event_sequence"),
                        )
                    )
                if (
                    str(grant["subject_principal_id"]) not in trusted_ids
                    or str(grant["granted_by_principal_id"]) not in trusted_ids
                ):
                    failures.append(
                        _failure(
                            "canonical_policy",
                            "unknown_grant_principal",
                            "Capability grant claims a nonexistent trusted principal",
                            event_id=grant.get("policy_event_id"),
                        )
                    )
                if canonical_scopes.get(str(grant["capability"])) != (
                    grant["expected_prior_state"],
                    grant["requested_state"],
                ):
                    failures.append(
                        _failure(
                            "canonical_policy",
                            "invalid_capability_scope",
                            "Capability grant uses unknown capability or noncanonical state scope",
                            event_id=grant.get("policy_event_id"),
                            event_sequence=grant.get("event_sequence"),
                        )
                    )
                grant_scope = (
                    grant.get("brand_id"),
                    grant.get("channel_id"),
                    grant.get("destination_id"),
                )
                if grant["capability"] in {
                    "policy.manage_capabilities",
                    "effect.manage_bindings",
                }:
                    scope_valid = grant_scope == (None, None, None) and grant.get(
                        "scope_version"
                    ) in {None, "1.0"}
                elif grant.get("scope_version") is None:
                    scope_valid = grant_scope == (None, None, None)
                else:
                    try:
                        PacketScope(
                            brand_id=grant.get("brand_id"),
                            channel_id=grant.get("channel_id"),
                            destination_id=grant.get("destination_id"),
                        )
                    except Exception:
                        scope_valid = False
                    else:
                        scope_valid = grant.get("scope_version") == "1.0"
                if not scope_valid:
                    failures.append(
                        _failure(
                            "canonical_policy",
                            "invalid_grant_scope",
                            "Capability grant has malformed or inapplicable packet scope",
                            event_id=grant.get("policy_event_id"),
                            event_sequence=grant.get("event_sequence"),
                        )
                    )

            for revocation in revocations:
                event = event_by_id.get(str(revocation["policy_event_id"]))
                target_grant = grant_by_id.get(str(revocation["grant_id"]), {})
                operation = authenticated_operation_by_id.get(
                    str(revocation["authenticated_operation_id"])
                )
                envelope = authenticated_envelopes.get(
                    str(revocation["authenticated_operation_id"]), {}
                )
                try:
                    identifiers = (
                        {}
                        if event is None
                        else _json_object(
                            event.get("input_identifiers_json"),
                            field="input_identifiers_json",
                        )
                    )
                except CanonicalChainError:
                    identifiers = {}
                if (
                    str(revocation["grant_id"]) not in grant_by_id
                    or event is None
                    or event.get("command") != "revoke-capability"
                    or event.get("outcome") != "accepted"
                    or event.get("authenticated_principal_id")
                    != revocation["revoked_by_principal_id"]
                    or event.get("authentication_operation_id")
                    != revocation["authenticated_operation_id"]
                    or identifiers.get("policy_revocation_id")
                    != revocation["revocation_id"]
                    or identifiers.get("policy_grant_id") != revocation["grant_id"]
                    or revocation["authenticated_operation_id"]
                    not in authenticated_operation_ids
                    or operation is None
                    or operation.get("adjudication_event_id")
                    != revocation["policy_event_id"]
                    or envelope.get("operation") != "revoke-capability"
                    or envelope.get("revocation_id")
                    != revocation["revocation_id"]
                    or envelope.get("grant_id") != revocation["grant_id"]
                    or envelope.get("subject_principal_id")
                    != target_grant.get("subject_principal_id")
                    or envelope.get("capability") != target_grant.get("capability")
                    or envelope.get("expected_prior_state")
                    != target_grant.get("expected_prior_state")
                    or envelope.get("requested_state")
                    != target_grant.get("requested_state")
                    or envelope.get("scope_version")
                    != target_grant.get("scope_version")
                    or envelope.get("brand_id") != target_grant.get("brand_id")
                    or envelope.get("channel_id")
                    != target_grant.get("channel_id")
                    or envelope.get("destination_id")
                    != target_grant.get("destination_id")
                    or event.get("occurred_at_utc") != revocation["revoked_at_utc"]
                    or event.get("application_version")
                    != revocation["application_version"]
                    or event.get("authorization_status") != "allowed"
                    or str(revocation["revoked_by_principal_id"]) not in trusted_ids
                    or not isinstance(revocation.get("event_sequence"), int)
                    or not isinstance(
                        grant_by_id.get(str(revocation["grant_id"]), {}).get(
                            "event_sequence"
                        ),
                        int,
                    )
                    or int(
                        grant_by_id.get(str(revocation["grant_id"]), {}).get(
                            "event_sequence", 2**63
                        )
                    )
                    >= int(revocation.get("event_sequence") or -1)
                ):
                    failures.append(
                        _failure(
                            "canonical_policy",
                            "revocation_event_mismatch",
                            "Capability revocation does not match its canonical event/grant",
                            event_id=revocation.get("policy_event_id"),
                            event_sequence=revocation.get("event_sequence"),
                        )
                    )

            if schema_version >= 5:
                from .packets import recompute_packet_manifest

                packets = [
                    dict(row)
                    for row in connection.execute(
                        "SELECT * FROM packets ORDER BY packet_id"
                    ).fetchall()
                ]
                approvals = [
                    dict(row)
                    for row in connection.execute(
                        "SELECT * FROM approvals ORDER BY approval_id"
                    ).fetchall()
                ]
                approvals_by_packet: dict[str, list[dict[str, Any]]] = {}
                for approval in approvals:
                    approvals_by_packet.setdefault(
                        str(approval["packet_id"]), []
                    ).append(approval)
                for packet in packets:
                    packet_id = str(packet["packet_id"])
                    scope_values = (
                        packet.get("brand_id"),
                        packet.get("channel_id"),
                        packet.get("destination_id"),
                    )
                    if packet.get("scope_version") is None:
                        packet_scope_valid = scope_values == (None, None, None)
                    else:
                        try:
                            PacketScope(
                                brand_id=scope_values[0],
                                channel_id=scope_values[1],
                                destination_id=scope_values[2],
                            )
                        except Exception:
                            packet_scope_valid = False
                        else:
                            packet_scope_valid = packet.get("scope_version") == "1.0"
                    if not packet_scope_valid:
                        failures.append(
                            _failure(
                                "canonical_policy",
                                "invalid_packet_scope",
                                "Packet has malformed or partial canonical scope",
                                event_id=packet_id,
                            )
                        )
                        continue
                    if packet.get("scope_version") is None:
                        continue
                    try:
                        _, manifest_hash = recompute_packet_manifest(packet)
                    except Exception as error:
                        failures.append(
                            _failure(
                                "canonical_policy",
                                "packet_scope_evidence_mismatch",
                                f"Packet scope/artifact evidence is invalid: {error}",
                                event_id=packet_id,
                            )
                        )
                    else:
                        if manifest_hash != packet.get("manifest_hash"):
                            failures.append(
                                _failure(
                                    "canonical_policy",
                                    "packet_manifest_mismatch",
                                    "Packet manifest does not bind its current canonical scope",
                                    event_id=packet_id,
                                )
                            )
                    packet_events = [
                        event for event in rows if event.get("packet_id") == packet_id
                    ]
                    generation_bound = False
                    for packet_event in packet_events:
                        try:
                            identifiers = _json_object(
                                packet_event.get("input_identifiers_json"),
                                field="input_identifiers_json",
                            )
                        except CanonicalChainError:
                            continue
                        if (
                            packet_event.get("command") == "generate"
                            and packet_event.get("outcome") == "accepted"
                            and identifiers.get("scope_version") == "1.0"
                            and identifiers.get("brand_id") == scope_values[0]
                            and identifiers.get("channel_id") == scope_values[1]
                            and identifiers.get("destination_id") == scope_values[2]
                            and packet_event.get("governed_hash")
                            == packet.get("manifest_hash")
                        ):
                            generation_bound = True
                        if (
                            packet_event.get("authorization_scope_version") == "1.0"
                            and packet_event.get("authorization_required_capability")
                            in {"packet.approve", "packet.reject", "packet.release"}
                            and (
                                packet_event.get("authorization_brand_id"),
                                packet_event.get("authorization_channel_id"),
                                packet_event.get("authorization_destination_id"),
                            )
                            != scope_values
                        ):
                            failures.append(
                                _failure(
                                    "canonical_policy",
                                    "packet_event_scope_mismatch",
                                    "Packet authority event scope differs from canonical packet scope",
                                    event_id=packet_event.get("event_id"),
                                    event_sequence=packet_event.get("event_sequence"),
                                )
                            )
                    if not generation_bound:
                        failures.append(
                            _failure(
                                "canonical_policy",
                                "packet_generation_scope_mismatch",
                                "Scoped packet lacks matching canonical generation evidence",
                                event_id=packet_id,
                            )
                        )
                    for approval in approvals_by_packet.get(packet_id, []):
                        approval_event = event_by_id.get(
                            str(approval["transition_event_id"])
                        )
                        if (
                            approval.get("scope_version") != "1.0"
                            or (
                                approval.get("brand_id"),
                                approval.get("channel_id"),
                                approval.get("destination_id"),
                            )
                            != scope_values
                            or approval.get("manifest_hash")
                            != packet.get("manifest_hash")
                            or approval_event is None
                            or (
                                approval_event.get("authorization_brand_id"),
                                approval_event.get("authorization_channel_id"),
                                approval_event.get("authorization_destination_id"),
                            )
                            != scope_values
                        ):
                            failures.append(
                                _failure(
                                    "canonical_policy",
                                    "approval_scope_mismatch",
                                    "Approval does not bind the canonical packet scope",
                                    event_id=approval.get("transition_event_id"),
                                )
                            )

            authorization_scopes = {
                "approve": (
                    "packet.approve",
                    "AWAITING_APPROVAL",
                    "APPROVED",
                ),
                "reject": (
                    "packet.reject",
                    "AWAITING_APPROVAL",
                    "REJECTED",
                ),
                "release": ("packet.release", "APPROVED", "RELEASED"),
                "bootstrap-capability-policy": (
                    "policy.manage_capabilities",
                    None,
                    None,
                ),
                "grant-capability": (
                    "policy.manage_capabilities",
                    None,
                    None,
                ),
                "revoke-capability": (
                    "policy.manage_capabilities",
                    None,
                    None,
                ),
                "register-destination-binding": (
                    "effect.manage_bindings",
                    None,
                    None,
                ),
                "register-effect-executor": (
                    "effect.manage_bindings",
                    None,
                    None,
                ),
            }
            for event in rows:
                authorization_status = event.get("authorization_status")
                event_sequence = event.get("event_sequence")
                if authorization_status is not None:
                    reason_code = event.get("authorization_reason_code")
                    allowed_reasons = {
                        AuthorizationReason.ACTIVE_GRANT.value,
                        AuthorizationReason.BOOTSTRAP_ALLOWED.value,
                    }
                    not_evaluated_reasons = {
                        AuthorizationReason.REPLAY_REJECTED.value,
                        AuthorizationReason.REQUEST_BINDING_REJECTED.value,
                    }
                    known_reasons = {reason.value for reason in AuthorizationReason}
                    reason_valid = reason_code in known_reasons
                    if authorization_status == "allowed":
                        reason_valid = reason_valid and reason_code in allowed_reasons
                    elif authorization_status == "not_evaluated":
                        reason_valid = (
                            reason_valid and reason_code in not_evaluated_reasons
                        )
                    elif authorization_status == "denied":
                        reason_valid = reason_valid and reason_code not in (
                            allowed_reasons | not_evaluated_reasons
                        )
                    if not reason_valid:
                        failures.append(
                            _failure(
                                "canonical_policy",
                                "invalid_authorization_reason",
                                "Authorization status and reason code are inconsistent",
                                event_id=event.get("event_id"),
                                event_sequence=event_sequence,
                            )
                        )

        external_tables = {
            "external_destination_bindings",
            "trusted_effect_executors",
            "external_effect_requests",
            "external_effect_dispatches",
            "external_effect_results",
        }
        missing_external_tables = sorted(
            table
            for table in external_tables
            if not _table_exists(connection, table)
        )
        if schema_version < 6 or missing_external_tables:
            failures.append(
                _failure(
                    "canonical_external_effect",
                    "external_effect_not_activated",
                    "Schema-6 privileged external effects are not activated"
                    + (
                        "; missing tables: " + ", ".join(missing_external_tables)
                        if missing_external_tables
                        else ""
                    ),
                )
            )
        else:
            from .effect_protocol import (
                _executor_key_identity,
                calculate_effect_request_hash,
                calculate_idempotency_key,
                verify_executor_result_signature,
            )
            from .models import (
                ExecutorResultEnvelope,
                ExternalEffectDispatch,
                ExternalEffectRequest,
                SignedExecutorResult,
            )
            from .packets import recompute_packet_manifest

            event_by_id = {str(event["event_id"]): event for event in rows}
            bindings = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT b.*, c.event_sequence
                    FROM external_destination_bindings AS b
                    LEFT JOIN transition_event_chain_entries AS c
                      ON c.event_id = b.registration_event_id
                    ORDER BY b.binding_id
                    """
                ).fetchall()
            ]
            executors = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT x.*, c.event_sequence
                    FROM trusted_effect_executors AS x
                    LEFT JOIN transition_event_chain_entries AS c
                      ON c.event_id = x.registration_event_id
                    ORDER BY x.executor_id
                    """
                ).fetchall()
            ]
            effect_requests = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT q.*, c.event_sequence AS request_event_sequence
                    FROM external_effect_requests AS q
                    LEFT JOIN transition_event_chain_entries AS c
                      ON c.event_id = q.request_event_id
                    ORDER BY q.effect_id
                    """
                ).fetchall()
            ]
            dispatches = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT d.*, c.event_sequence
                    FROM external_effect_dispatches AS d
                    LEFT JOIN transition_event_chain_entries AS c
                      ON c.event_id = d.dispatch_event_id
                    ORDER BY d.effect_id, d.attempt_number
                    """
                ).fetchall()
            ]
            results = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT r.*, c.event_sequence
                    FROM external_effect_results AS r
                    LEFT JOIN transition_event_chain_entries AS c
                      ON c.event_id = r.result_event_id
                    ORDER BY r.effect_id, r.completed_at_utc, r.result_id
                    """
                ).fetchall()
            ]
            destination_bindings_checked = len(bindings)
            effect_executors_checked = len(executors)
            external_effect_requests_checked = len(effect_requests)
            external_effect_dispatches_checked = len(dispatches)
            external_effect_results_checked = len(results)
            binding_by_id = {str(row["binding_id"]): row for row in bindings}
            executor_by_id = {str(row["executor_id"]): row for row in executors}
            request_by_id = {str(row["effect_id"]): row for row in effect_requests}
            dispatch_by_id = {str(row["dispatch_id"]): row for row in dispatches}

            for binding in bindings:
                event = event_by_id.get(str(binding["registration_event_id"]))
                try:
                    identifiers = (
                        {}
                        if event is None
                        else _json_object(
                            event.get("input_identifiers_json"),
                            field="input_identifiers_json",
                        )
                    )
                    PacketScope(
                        brand_id=binding["brand_id"],
                        channel_id=binding["channel_id"],
                        destination_id=binding["destination_id"],
                    )
                except Exception:
                    identifiers = {}
                expected_identifiers = {
                    "destination_binding_id": binding["binding_id"],
                    "scope_version": binding["scope_version"],
                    "brand_id": binding["brand_id"],
                    "channel_id": binding["channel_id"],
                    "destination_id": binding["destination_id"],
                    "adapter_id": binding["adapter_id"],
                    "external_target_ref": binding["external_target_ref"],
                    "credential_ref": binding["credential_ref"],
                    "authentication_operation_id": binding[
                        "authenticated_operation_id"
                    ],
                }
                operation = connection.execute(
                    "SELECT envelope_json FROM authenticated_operations WHERE operation_id = ?",
                    (binding["authenticated_operation_id"],),
                ).fetchone()
                try:
                    envelope = json.loads(str(operation["envelope_json"]))
                except Exception:
                    envelope = {}
                if (
                    event is None
                    or event.get("command") != "register-destination-binding"
                    or event.get("target_type") != "external_destination_binding"
                    or event.get("target_id") != binding["binding_id"]
                    or event.get("outcome") != "accepted"
                    or event.get("authorization_status") != "allowed"
                    or event.get("authorization_required_capability")
                    != "effect.manage_bindings"
                    or event.get("authenticated_principal_id")
                    != binding["registered_by_principal_id"]
                    or any(
                        identifiers.get(field) != value
                        for field, value in expected_identifiers.items()
                    )
                    or envelope.get("target_id") != binding["binding_id"]
                    or envelope.get("adapter_id") != binding["adapter_id"]
                    or envelope.get("external_target_ref")
                    != binding["external_target_ref"]
                    or envelope.get("credential_ref") != binding["credential_ref"]
                    or (
                        envelope.get("scope_version"),
                        envelope.get("brand_id"),
                        envelope.get("channel_id"),
                        envelope.get("destination_id"),
                    )
                    != (
                        binding["scope_version"],
                        binding["brand_id"],
                        binding["channel_id"],
                        binding["destination_id"],
                    )
                    or binding["adapter_id"] != "test.capture"
                    or not str(binding["credential_ref"]).startswith("cred_")
                    or event.get("occurred_at_utc") != binding["created_at_utc"]
                    or event.get("application_version")
                    != binding["application_version"]
                ):
                    failures.append(
                        _failure(
                            "canonical_external_effect",
                            "destination_binding_mismatch",
                            "Destination binding does not match its signed canonical event",
                            event_id=binding.get("registration_event_id"),
                            event_sequence=binding.get("event_sequence"),
                        )
                    )

            for executor in executors:
                event = event_by_id.get(str(executor["registration_event_id"]))
                operation = connection.execute(
                    "SELECT envelope_json FROM authenticated_operations WHERE operation_id = ?",
                    (executor["authenticated_operation_id"],),
                ).fetchone()
                try:
                    envelope = json.loads(str(operation["envelope_json"]))
                    allowed = json.loads(str(executor["allowed_adapter_ids_json"]))
                    raw_public = base64.b64decode(
                        str(executor["public_key_b64"]), validate=True
                    )
                    key_id, fingerprint, public_b64 = _executor_key_identity(
                        Ed25519PublicKey.from_public_bytes(raw_public)
                    )
                except Exception:
                    envelope = {}
                    allowed = []
                    key_id = fingerprint = public_b64 = None
                if (
                    event is None
                    or event.get("command") != "register-effect-executor"
                    or event.get("target_type") != "trusted_effect_executor"
                    or event.get("target_id") != executor["executor_id"]
                    or event.get("outcome") != "accepted"
                    or event.get("authorization_status") != "allowed"
                    or event.get("authorization_required_capability")
                    != "effect.manage_bindings"
                    or event.get("authenticated_principal_id")
                    != executor["registered_by_principal_id"]
                    or envelope.get("target_id") != executor["executor_id"]
                    or envelope.get("executor_key_id") != executor["key_id"]
                    or envelope.get("executor_public_key_b64")
                    != executor["public_key_b64"]
                    or envelope.get("executor_verifier_fingerprint")
                    != executor["verifier_fingerprint"]
                    or envelope.get("allowed_adapter_ids") != allowed
                    or allowed != ["test.capture"]
                    or key_id != executor["key_id"]
                    or fingerprint != executor["verifier_fingerprint"]
                    or public_b64 != executor["public_key_b64"]
                    or event.get("occurred_at_utc") != executor["created_at_utc"]
                    or event.get("application_version")
                    != executor["application_version"]
                ):
                    failures.append(
                        _failure(
                            "canonical_external_effect",
                            "effect_executor_mismatch",
                            "Trusted executor does not match its signed canonical event",
                            event_id=executor.get("registration_event_id"),
                            event_sequence=executor.get("event_sequence"),
                        )
                    )

            for effect in effect_requests:
                event = event_by_id.get(str(effect["request_event_id"]))
                release = event_by_id.get(str(effect["release_event_id"]))
                binding = binding_by_id.get(str(effect["destination_binding_id"]))
                packet = connection.execute(
                    "SELECT * FROM packets WHERE packet_id = ?", (effect["packet_id"],)
                ).fetchone()
                approval = connection.execute(
                    "SELECT * FROM approvals WHERE approval_id = ?",
                    (effect["approval_id"],),
                ).fetchone()
                grant = connection.execute(
                    """
                    SELECT g.*, c.event_sequence AS grant_sequence,
                           rc.event_sequence AS revocation_sequence
                    FROM capability_grants AS g
                    LEFT JOIN transition_event_chain_entries AS c
                      ON c.event_id = g.policy_event_id
                    LEFT JOIN capability_revocations AS r ON r.grant_id = g.grant_id
                    LEFT JOIN transition_event_chain_entries AS rc
                      ON rc.event_id = r.policy_event_id
                    WHERE g.grant_id = ?
                    """,
                    (effect["authorizing_grant_id"],),
                ).fetchone()
                try:
                    ExternalEffectRequest.model_validate(
                        {
                            key: value
                            for key, value in effect.items()
                            if key != "request_event_sequence"
                        }
                    )
                    expected_hash = calculate_effect_request_hash(effect)
                    expected_idempotency = calculate_idempotency_key(
                        str(effect["effect_id"]), str(effect["release_event_hash"])
                    )
                    identifiers = _json_object(
                        None if event is None else event.get("input_identifiers_json"),
                        field="input_identifiers_json",
                    )
                    if packet is None:
                        raise ValueError("packet missing")
                    artifact_hashes, manifest_hash = recompute_packet_manifest(dict(packet))
                except Exception:
                    expected_hash = expected_idempotency = None
                    identifiers = {}
                    artifact_hashes = {}
                    manifest_hash = None
                scope = (
                    effect["scope_version"], effect["brand_id"],
                    effect["channel_id"], effect["destination_id"],
                )
                if (
                    event is None
                    or release is None
                    or binding is None
                    or packet is None
                    or approval is None
                    or grant is None
                    or effect["request_hash"] != expected_hash
                    or effect["idempotency_key"] != expected_idempotency
                    or event.get("command") != "create-external-effect-request"
                    or event.get("target_type") != "external_effect"
                    or event.get("target_id") != effect["effect_id"]
                    or event.get("outcome") != "accepted"
                    or event.get("governed_hash") != effect["request_hash"]
                    or event.get("occurred_at_utc") != effect["created_at_utc"]
                    or release.get("command") != "release"
                    or release.get("outcome") != "accepted"
                    or release.get("resulting_state") != "RELEASED"
                    or release.get("event_hash") != effect["release_event_hash"]
                    or release.get("event_sequence")
                    != effect["release_event_sequence"]
                    or release.get("packet_id") != effect["packet_id"]
                    or release.get("authenticated_principal_id")
                    != effect["authenticated_principal_id"]
                    or release.get("authorization_matching_grant_id")
                    != effect["authorizing_grant_id"]
                    or release.get("authorization_required_capability")
                    != "packet.release"
                    or approval["packet_id"] != effect["packet_id"]
                    or approval["transition_event_id"] != effect["approval_event_id"]
                    or grant["subject_principal_id"]
                    != effect["authenticated_principal_id"]
                    or grant["capability"] != "packet.release"
                    or int(grant["grant_sequence"])
                    >= int(effect["release_event_sequence"])
                    or (
                        grant["revocation_sequence"] is not None
                        and int(grant["revocation_sequence"])
                        <= int(effect["release_event_sequence"])
                    )
                    or (
                        grant["scope_version"], grant["brand_id"],
                        grant["channel_id"], grant["destination_id"],
                    ) != scope
                    or (
                        binding["scope_version"], binding["brand_id"],
                        binding["channel_id"], binding["destination_id"],
                    ) != scope
                    or binding["adapter_id"] != effect["adapter_id"]
                    or binding["external_target_ref"]
                    != effect["external_target_ref"]
                    or binding["credential_ref"] != effect["credential_ref"]
                    or packet["state"] != "RELEASED"
                    or packet["candidate_id"] != effect["candidate_id"]
                    or packet["manifest_hash"] != effect["packet_manifest_hash"]
                    or manifest_hash != effect["packet_manifest_hash"]
                    or artifact_hashes.get("packet_receipt.json")
                    != effect["packet_receipt_hash"]
                    or not isinstance(effect.get("request_event_sequence"), int)
                    or int(effect["request_event_sequence"])
                    <= int(effect["release_event_sequence"])
                    or not isinstance(binding.get("event_sequence"), int)
                    or int(binding["event_sequence"])
                    >= int(effect["request_event_sequence"])
                    or identifiers.get("effect_id") != effect["effect_id"]
                    or identifiers.get("release_event_id")
                    != effect["release_event_id"]
                    or identifiers.get("destination_binding_id")
                    != effect["destination_binding_id"]
                    or identifiers.get("credential_ref") != effect["credential_ref"]
                    or identifiers.get("request_hash") != effect["request_hash"]
                ):
                    failures.append(
                        _failure(
                            "canonical_external_effect",
                            "external_effect_request_mismatch",
                            "External-effect request diverges from release, grant, binding, artifact, or event evidence",
                            event_id=effect.get("request_event_id"),
                            event_sequence=effect.get("request_event_sequence"),
                        )
                    )

            prior_attempt: dict[str, int] = {}
            for dispatch in dispatches:
                effect = request_by_id.get(str(dispatch["effect_id"]))
                event = event_by_id.get(str(dispatch["dispatch_event_id"]))
                try:
                    ExternalEffectDispatch.model_validate(
                        {key: value for key, value in dispatch.items() if key != "event_sequence"}
                    )
                    identifiers = _json_object(
                        None if event is None else event.get("input_identifiers_json"),
                        field="input_identifiers_json",
                    )
                except Exception:
                    identifiers = {}
                previous = prior_attempt.get(str(dispatch["effect_id"]), 0)
                prior_attempt[str(dispatch["effect_id"])] = int(dispatch["attempt_number"])
                if (
                    effect is None
                    or event is None
                    or int(dispatch["attempt_number"]) != previous + 1
                    or dispatch["effect_request_hash"] != effect["request_hash"]
                    or event.get("command") != "claim-external-effect"
                    or event.get("target_type") != "external_effect_dispatch"
                    or event.get("target_id") != dispatch["dispatch_id"]
                    or event.get("outcome") != "accepted"
                    or event.get("governed_hash") != dispatch["effect_request_hash"]
                    or event.get("occurred_at_utc") != dispatch["claimed_at_utc"]
                    or not isinstance(dispatch.get("event_sequence"), int)
                    or int(dispatch["event_sequence"])
                    <= int(effect["request_event_sequence"])
                    or identifiers.get("effect_id") != dispatch["effect_id"]
                    or identifiers.get("dispatch_id") != dispatch["dispatch_id"]
                    or identifiers.get("attempt_number")
                    != dispatch["attempt_number"]
                ):
                    failures.append(
                        _failure(
                            "canonical_external_effect",
                            "external_effect_dispatch_mismatch",
                            "External-effect dispatch claim is missing, reordered, or inconsistent",
                            event_id=dispatch.get("dispatch_event_id"),
                            event_sequence=dispatch.get("event_sequence"),
                        )
                    )

            results_by_dispatch = {str(row["dispatch_id"]): row for row in results}
            for dispatch in dispatches:
                if int(dispatch["attempt_number"]) <= 1:
                    continue
                prior = next(
                    (
                        candidate
                        for candidate in dispatches
                        if candidate["effect_id"] == dispatch["effect_id"]
                        and int(candidate["attempt_number"])
                        == int(dispatch["attempt_number"]) - 1
                    ),
                    None,
                )
                prior_result = (
                    None
                    if prior is None
                    else results_by_dispatch.get(str(prior["dispatch_id"]))
                )
                if (
                    prior_result is None
                    or prior_result["outcome"] != "FAILED"
                    or not bool(prior_result["retry_permitted"])
                    or int(prior_result["event_sequence"])
                    >= int(dispatch["event_sequence"])
                ):
                    failures.append(
                        _failure(
                            "canonical_external_effect",
                            "unsafe_effect_retry",
                            "External effect was retried without a prior confirmed retry-safe failure",
                            event_id=dispatch.get("dispatch_event_id"),
                            event_sequence=dispatch.get("event_sequence"),
                        )
                    )

            for result in results:
                effect = request_by_id.get(str(result["effect_id"]))
                dispatch = dispatch_by_id.get(str(result["dispatch_id"]))
                executor = executor_by_id.get(str(result["executor_id"]))
                event = event_by_id.get(str(result["result_event_id"]))
                try:
                    envelope_json = json.loads(str(result["envelope_json"]))
                    envelope = ExecutorResultEnvelope.model_validate(envelope_json)
                    signed = SignedExecutorResult(
                        envelope=envelope, signature_b64=str(result["signature_b64"])
                    )
                    envelope_hash, proof_hash = verify_executor_result_signature(
                        signed, executor or {}
                    )
                    identifiers = _json_object(
                        None if event is None else event.get("input_identifiers_json"),
                        field="input_identifiers_json",
                    )
                except Exception:
                    envelope = None
                    envelope_hash = proof_hash = None
                    identifiers = {}
                row_binding = None if envelope is None else {
                    "result_id": envelope.result_id,
                    "effect_id": envelope.effect_id,
                    "dispatch_id": envelope.dispatch_id,
                    "executor_id": envelope.executor_id,
                    "executor_key_id": envelope.executor_key_id,
                    "effect_request_hash": envelope.effect_request_hash,
                    "adapter_id": envelope.adapter_id,
                    "scope_version": envelope.scope_version,
                    "brand_id": envelope.brand_id,
                    "channel_id": envelope.channel_id,
                    "destination_id": envelope.destination_id,
                    "destination_binding_id": envelope.destination_binding_id,
                    "artifact_hash": envelope.artifact_hash,
                    "idempotency_key": envelope.idempotency_key,
                    "outcome": envelope.outcome.value,
                    "effect_may_have_occurred": int(envelope.effect_may_have_occurred),
                    "retry_permitted": int(envelope.retry_permitted),
                    "remote_reference": envelope.remote_reference,
                    "response_hash": envelope.response_hash,
                    "error_code": envelope.error_code,
                    "started_at_utc": envelope.started_at_utc,
                    "completed_at_utc": envelope.completed_at_utc,
                }
                if (
                    effect is None
                    or dispatch is None
                    or executor is None
                    or event is None
                    or envelope is None
                    or any(result.get(field) != value for field, value in row_binding.items())
                    or result["envelope_hash"] != envelope_hash
                    or result["proof_hash"] != proof_hash
                    or event.get("command") != "record-external-effect-result"
                    or event.get("target_type") != "external_effect_result"
                    or event.get("target_id") != result["result_id"]
                    or event.get("outcome") != "accepted"
                    or event.get("governed_hash") != result["effect_request_hash"]
                    or identifiers.get("executor_envelope_hash") != envelope_hash
                    or identifiers.get("executor_proof_hash") != proof_hash
                    or identifiers.get("effect_outcome") != result["outcome"]
                    or not isinstance(result.get("event_sequence"), int)
                    or int(result["event_sequence"]) <= int(dispatch["event_sequence"])
                    or int(result["event_sequence"]) <= int(executor["event_sequence"])
                ):
                    failures.append(
                        _failure(
                            "canonical_external_effect",
                            "external_effect_result_mismatch",
                            "Executor result signature, semantics, event, or authority binding is invalid",
                            event_id=result.get("result_event_id"),
                            event_sequence=result.get("event_sequence"),
                        )
                    )
                    # The remaining inline policy checks below are retained for
                    # legacy source compatibility; the complete, correctly scoped
                    # pass runs once after external-effect verification.
                    continue
                    expected_scope = authorization_scopes.get(str(event.get("command")))
                    if expected_scope is None or expected_scope != (
                        event.get("authorization_required_capability"),
                        event.get("authorization_prior_state"),
                        event.get("authorization_requested_state"),
                    ):
                        failures.append(
                            _failure(
                                "canonical_policy",
                                "invalid_authorization_scope",
                                "Authorization evidence uses a noncanonical capability/state scope",
                                event_id=event.get("event_id"),
                                event_sequence=event_sequence,
                            )
                        )
                    scope_values = (
                        event.get("authorization_brand_id"),
                        event.get("authorization_channel_id"),
                        event.get("authorization_destination_id"),
                    )
                    scope_version = event.get("authorization_scope_version")
                    if scope_version is None:
                        event_scope_valid = scope_values == (None, None, None)
                    elif scope_values == (None, None, None):
                        event_scope_valid = event.get(
                            "authorization_required_capability"
                        ) in {
                            "policy.manage_capabilities",
                            "effect.manage_bindings",
                        } or event.get(
                            "authorization_reason_code"
                        ) == "SCOPE_REQUIRED"
                    else:
                        try:
                            PacketScope(
                                brand_id=scope_values[0],
                                channel_id=scope_values[1],
                                destination_id=scope_values[2],
                            )
                        except Exception:
                            event_scope_valid = False
                        else:
                            event_scope_valid = scope_version == "1.0"
                    if not event_scope_valid:
                        failures.append(
                            _failure(
                                "canonical_policy",
                                "invalid_authorization_packet_scope",
                                "Authorization evidence has malformed or inapplicable packet scope",
                                event_id=event.get("event_id"),
                                event_sequence=event_sequence,
                            )
                        )
                    if event_sequence is None:
                        failures.append(
                            _failure(
                                "canonical_policy",
                                "fabricated_historical_authorization",
                                "Unchained historical event claims Slice-5 authorization evidence",
                                event_id=event.get("event_id"),
                            )
                        )
                    before_bootstrap = (
                        isinstance(event_sequence, int)
                        and (
                            policy_start_sequence is None
                            or event_sequence < policy_start_sequence
                        )
                    )
                    if before_bootstrap and authorization_status == "allowed":
                        failures.append(
                            _failure(
                                "canonical_policy",
                                "authorization_before_bootstrap",
                                "Event claims allowed authorization before policy bootstrap",
                                event_id=event.get("event_id"),
                                event_sequence=event_sequence,
                            )
                        )
                if (
                    policy_start_sequence is not None
                    and isinstance(event_sequence, int)
                    and int(event_sequence) >= policy_start_sequence
                    and event.get("authentication_status")
                    in {"verified", "replay_rejected"}
                    and event.get("command")
                    in {
                        "approve",
                        "reject",
                        "release",
                        "bootstrap-capability-policy",
                        "grant-capability",
                        "revoke-capability",
                        "register-destination-binding",
                        "register-effect-executor",
                    }
                    and event.get("authorization_status") is None
                ):
                    failures.append(
                        _failure(
                            "canonical_policy",
                            "missing_authorization_evidence",
                            "Post-bootstrap authenticated authority event lacks authorization evidence",
                            event_id=event.get("event_id"),
                            event_sequence=event.get("event_sequence"),
                        )
                    )
                if event.get("authorization_status") is None:
                    continue
                if event.get("authorization_principal_id") != event.get(
                    "authenticated_principal_id"
                ):
                    failures.append(
                        _failure(
                            "canonical_policy",
                            "authorization_principal_mismatch",
                            "Authorization principal differs from authenticated principal",
                            event_id=event.get("event_id"),
                            event_sequence=event.get("event_sequence"),
                        )
                    )
                matching_id = event.get("authorization_matching_grant_id")
                if (
                    event.get("authorization_status") == "allowed"
                    and not matching_id
                    and event.get("authorization_reason_code")
                    != "BOOTSTRAP_ALLOWED"
                ):
                    failures.append(
                        _failure(
                            "canonical_policy",
                            "missing_authorizing_grant",
                            "Allowed authorization lacks its exact canonical grant",
                            event_id=event.get("event_id"),
                            event_sequence=event.get("event_sequence"),
                        )
                    )
                if event.get("authorization_status") == "allowed" and matching_id:
                    grant = grant_by_id.get(str(matching_id))
                    event_sequence = event.get("event_sequence")
                    if (
                        grant is None
                        or grant["subject_principal_id"]
                        != event.get("authorization_principal_id")
                        or grant["capability"]
                        != event.get("authorization_required_capability")
                        or grant["expected_prior_state"]
                        != event.get("authorization_prior_state")
                        or grant["requested_state"]
                        != event.get("authorization_requested_state")
                        or (
                            grant["capability"]
                            not in {
                                "policy.manage_capabilities",
                                "effect.manage_bindings",
                            }
                            and (
                                grant.get("scope_version")
                                != event.get("authorization_scope_version")
                                or grant.get("brand_id")
                                != event.get("authorization_brand_id")
                                or grant.get("channel_id")
                                != event.get("authorization_channel_id")
                                or grant.get("destination_id")
                                != event.get("authorization_destination_id")
                            )
                        )
                        or not isinstance(event_sequence, int)
                        or not isinstance(grant.get("event_sequence"), int)
                        or int(grant["event_sequence"]) >= event_sequence
                        or (
                            isinstance(grant.get("revocation_sequence"), int)
                            and int(grant["revocation_sequence"]) < event_sequence
                        )
                    ):
                        failures.append(
                            _failure(
                                "canonical_policy",
                                "authorizing_grant_mismatch",
                                "Allowed authorization does not match an active prior grant",
                                event_id=event.get("event_id"),
                                event_sequence=event_sequence,
                            )
                        )

        if schema_version >= 4 and not missing_policy_tables:
            _verify_authorization_event_bindings(
                rows,
                policy_start_sequence=policy_start_sequence,
                grant_by_id=grant_by_id,
                failures=failures,
            )

    receipt_records: dict[str, tuple[int, dict[str, Any]]] = {}
    receipts_checked = 0
    if not receipt_log.exists():
        failures.append(
            _failure(
                "projection", "missing_receipt_log", "JSONL receipt projection is missing"
            )
        )
    else:
        try:
            with receipt_log.open("r", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, start=1):
                    if not line.strip():
                        continue
                    receipts_checked += 1
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError as error:
                        failures.append(
                            _failure(
                                "projection",
                                "malformed_receipt",
                                f"Receipt line is not valid JSON: {error.msg}",
                                receipt_line=line_number,
                            )
                        )
                        continue
                    if not isinstance(value, dict) or not isinstance(
                        value.get("run_id"), str
                    ):
                        failures.append(
                            _failure(
                                "projection",
                                "invalid_receipt_identity",
                                "Receipt line must be an object with a string run_id",
                                receipt_line=line_number,
                            )
                        )
                        continue
                    run_id = str(value["run_id"])
                    if run_id in receipt_records:
                        failures.append(
                            _failure(
                                "projection",
                                "duplicate_receipt_id",
                                "Receipt run ID occurs more than once",
                                event_id=run_id,
                                receipt_line=line_number,
                            )
                        )
                        continue
                    receipt_records[run_id] = (line_number, value)
        except UnicodeDecodeError as error:
            failures.append(
                _failure(
                    "projection",
                    "invalid_receipt_encoding",
                    f"Receipt log is not valid UTF-8: {error.reason}",
                )
            )

    event_ids = {str(event["event_id"]) for event in rows}
    pending_count = 0
    projection_complete = True
    for event in rows:
        event_id = str(event["event_id"])
        projected = event.get("receipt_projected_at_utc") is not None
        existing = receipt_records.get(event_id)
        if not projected:
            pending_count += 1
            projection_complete = False
        if existing is None:
            if projected:
                projection_complete = False
                failures.append(
                    _failure(
                        "projection",
                        "missing_projected_receipt",
                        "Canonical event is marked projected but its receipt is missing",
                        event_id=event_id,
                        event_sequence=event.get("event_sequence"),
                    )
                )
            continue
        line_number, receipt_value = existing
        if canonical_json(receipt_value) != str(event.get("receipt_json")):
            failures.append(
                _failure(
                    "projection",
                    "receipt_payload_mismatch",
                    "JSONL receipt differs from the canonical event payload",
                    event_id=event_id,
                    event_sequence=event.get("event_sequence"),
                    receipt_line=line_number,
                )
            )

    legacy_unbound = 0
    for run_id, (line_number, receipt_value) in receipt_records.items():
        if run_id in event_ids:
            continue
        if any(field in receipt_value for field in CHAIN_RECEIPT_FIELDS):
            failures.append(
                _failure(
                    "projection",
                    "orphan_native_receipt",
                    "Native chained receipt has no canonical transition event",
                    event_id=run_id,
                    receipt_line=line_number,
                )
            )
        else:
            legacy_unbound += 1

    canonical_valid = not any(
        failure.scope == "canonical_chain" for failure in failures
    )
    policy_valid = not any(
        failure.scope == "canonical_policy" for failure in failures
    )
    external_effect_valid = not any(
        failure.scope == "canonical_external_effect" for failure in failures
    )
    projection_valid = not any(failure.scope == "projection" for failure in failures)
    return IntegrityVerificationResult(
        database_schema_version=schema_version,
        chain_version=(None if not state else str(state.get("chain_version"))),
        activation_hash=(None if not state else str(state.get("activation_hash"))),
        canonical_chain_valid=canonical_valid,
        native_chain_start_event_id=native_start,
        events_checked=len(rows),
        legacy_events_checked=len(legacy_rows),
        native_events_checked=len(native_rows),
        canonical_policy_valid=policy_valid,
        capability_grants_checked=capability_grants_checked,
        capability_revocations_checked=capability_revocations_checked,
        authorization_events_checked=authorization_events_checked,
        canonical_external_effect_valid=external_effect_valid,
        destination_bindings_checked=destination_bindings_checked,
        effect_executors_checked=effect_executors_checked,
        external_effect_requests_checked=external_effect_requests_checked,
        external_effect_dispatches_checked=external_effect_dispatches_checked,
        external_effect_results_checked=external_effect_results_checked,
        projection_valid=projection_valid,
        projection_complete=projection_complete,
        receipts_checked=receipts_checked,
        pending_projection_count=pending_count,
        legacy_unbound_receipt_count=legacy_unbound,
        failures=_sorted_failures(failures),
    )
