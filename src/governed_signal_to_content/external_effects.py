"""Canonical, provider-neutral external-effect authority and ledger."""

from __future__ import annotations

import json
from pathlib import Path
from typing import NoReturn
from uuid import uuid4

from . import __version__, database
from .authentication import (
    AuthenticationError,
    AuthenticatedExecutionManagementRequest,
    OperationBindingError,
    ReplayDetected,
    authenticate_authority_request,
)
from .authorization import (
    AuthorizationRejected,
    CapabilityPolicyEvaluator,
    denied_decision,
    not_evaluated_decision,
)
from .config import WorkspacePaths
from .effect_protocol import (
    calculate_effect_request_hash,
    calculate_idempotency_key,
    verify_executor_result_signature,
)
from .hashing import canonical_json, canonical_json_hash
from .models import (
    AuthorizationDecision,
    AuthorizationReason,
    Capability,
    DestinationBindingOperationEnvelope,
    ExecutionManagementOperation,
    ExecutionManagementResult,
    ExecutorRegistrationOperationEnvelope,
    ExternalEffectDispatch,
    ExternalEffectRequest,
    SignedExecutorResult,
    SignedOperation,
)
from .packets import PacketIntegrityError, recompute_packet_manifest
from .receipts import (
    execution_identity,
    new_receipt,
    project_transition_event,
    transition_event_from_receipt,
    utc_now,
)


class ExternalEffectError(RuntimeError):
    """The canonical external-effect lifecycle rejected an operation."""


class ExternalEffectIntegrityError(ExternalEffectError):
    """The effect request no longer matches governed canonical evidence."""


class ExternalEffectClaimError(ExternalEffectError):
    """An effect cannot safely acquire another execution claim."""


def _management_identifiers(
    request: DestinationBindingOperationEnvelope | ExecutorRegistrationOperationEnvelope,
) -> dict[str, object]:
    common: dict[str, object] = {
        "authentication_operation_id": request.operation_id,
    }
    if isinstance(request, DestinationBindingOperationEnvelope):
        return {
            **common,
            "destination_binding_id": request.target_id,
            "scope_version": request.scope_version,
            "brand_id": request.brand_id,
            "channel_id": request.channel_id,
            "destination_id": request.destination_id,
            "adapter_id": request.adapter_id,
            "external_target_ref": request.external_target_ref,
            "credential_ref": request.credential_ref,
        }
    return {
        **common,
        "executor_id": request.target_id,
        "executor_authentication_scheme": request.executor_authentication_scheme,
        "executor_key_id": request.executor_key_id,
        "executor_verifier_fingerprint": request.executor_verifier_fingerprint,
        "allowed_adapter_ids": list(request.allowed_adapter_ids),
    }


def _management_result(
    request: DestinationBindingOperationEnvelope | ExecutorRegistrationOperationEnvelope,
    event_id: str,
    *,
    accepted: bool,
    reason: str | None = None,
) -> ExecutionManagementResult:
    return ExecutionManagementResult(
        request_id=request.operation_id,
        operation=request.operation,
        outcome="accepted" if accepted else "rejected",
        canonical_event_id=event_id,
        target_id=request.target_id,
        rejection_reason=reason,
    )


def _raise_management_rejection(
    decision: AuthorizationDecision,
    result: ExecutionManagementResult,
) -> NoReturn:
    error = AuthorizationRejected(decision)
    error.execution_management_result = result  # type: ignore[attr-defined]
    raise error


def _record_management_replay(
    paths: WorkspacePaths,
    *,
    authenticated_error: ReplayDetected,
    signed_operation: SignedOperation,
    asserted_actor: str,
) -> None:
    request = signed_operation.envelope
    if not isinstance(
        request,
        (DestinationBindingOperationEnvelope, ExecutorRegistrationOperationEnvelope),
    ):
        return
    principal_id = authenticated_error.evidence.authenticated_principal_id
    if principal_id is None:
        return
    decision = not_evaluated_decision(
        principal_id=principal_id,
        required_capability=Capability.EFFECT_MANAGE_BINDINGS,
        reason=AuthorizationReason.REPLAY_REJECTED,
    )
    receipt = new_receipt(
        command=request.operation.value,
        actor=asserted_actor,
        input_identifiers=_management_identifiers(request),
        prior_state=None,
        requested_transition=None,
        resulting_state=None,
        outcome="rejected",
        reason=str(authenticated_error),
        authentication=authenticated_error.evidence,
        authorization=decision,
    )
    database.record_transition_event(
        paths.database,
        transition_event_from_receipt(
            receipt, target_type=request.target_type, target_id=request.target_id
        ),
    )
    project_transition_event(paths.database, paths.receipt_log, receipt.run_id)


def mediate_execution_management(
    *,
    paths: WorkspacePaths,
    signed_operation: SignedOperation | None,
    asserted_actor: str,
) -> ExecutionManagementResult:
    """Authenticate, authorize, consume, and commit one binding/executor registration."""
    try:
        authenticated = authenticate_authority_request(paths.database, signed_operation)
    except ReplayDetected as error:
        if signed_operation is not None:
            _record_management_replay(
                paths,
                authenticated_error=error,
                signed_operation=signed_operation,
                asserted_actor=asserted_actor,
            )
        raise
    if not isinstance(authenticated, AuthenticatedExecutionManagementRequest):
        raise OperationBindingError(
            "Authenticated operation is not execution management",
            authenticated.evidence(),
        )
    request = authenticated.request
    consumption = authenticated.consumption_record()
    with database.connect(paths.database, immediate=True) as connection:
        decision = CapabilityPolicyEvaluator.evaluate(
            connection,
            principal_id=authenticated.principal.principal_id,
            required_capability=Capability.EFFECT_MANAGE_BINDINGS,
            actual_prior_state=None,
            requested_state=None,
        )
        accepted = decision.allowed
        rejection_reason = ""
        if accepted and isinstance(request, DestinationBindingOperationEnvelope):
            existing_scope = connection.execute(
                """
                SELECT binding_id FROM external_destination_bindings
                WHERE scope_version = ? AND brand_id = ? AND channel_id = ?
                  AND destination_id = ?
                """,
                (
                    request.scope_version,
                    request.brand_id,
                    request.channel_id,
                    request.destination_id,
                ),
            ).fetchone()
            existing_target = connection.execute(
                """
                SELECT binding_id FROM external_destination_bindings
                WHERE adapter_id = ? AND external_target_ref = ?
                """,
                (request.adapter_id, request.external_target_ref),
            ).fetchone()
            if existing_scope is not None or existing_target is not None:
                decision = denied_decision(
                    principal_id=authenticated.principal.principal_id,
                    required_capability=Capability.EFFECT_MANAGE_BINDINGS,
                    reason=AuthorizationReason.REQUEST_BINDING_REJECTED,
                )
                accepted = False
        elif accepted:
            assert isinstance(request, ExecutorRegistrationOperationEnvelope)
            if connection.execute(
                """
                SELECT 1 FROM trusted_effect_executors
                WHERE executor_id = ? OR key_id = ? OR verifier_fingerprint = ?
                """,
                (
                    request.target_id,
                    request.executor_key_id,
                    request.executor_verifier_fingerprint,
                ),
            ).fetchone() is not None:
                decision = denied_decision(
                    principal_id=authenticated.principal.principal_id,
                    required_capability=Capability.EFFECT_MANAGE_BINDINGS,
                    reason=AuthorizationReason.REQUEST_BINDING_REJECTED,
                )
                accepted = False
        if not accepted:
            rejection_reason = f"Authorization denied: {decision.reason.value}"
        receipt = new_receipt(
            command=request.operation.value,
            actor=asserted_actor,
            input_identifiers=_management_identifiers(request),
            prior_state=None,
            requested_transition=None,
            resulting_state=None,
            outcome="accepted" if accepted else "rejected",
            reason=request.reason if accepted else rejection_reason,
            authentication=authenticated.evidence(),
            authorization=decision,
        )
        event = transition_event_from_receipt(
            receipt, target_type=request.target_type, target_id=request.target_id
        )
        database._validate_authorization_event(
            event, decision, consumption, accepted=accepted
        )
        stored = database.insert_transition_event(connection, event)
        database.insert_authenticated_operation(
            connection,
            consumption,
            adjudication_event_id=receipt.run_id,
            adjudication_outcome="accepted" if accepted else "rejected",
        )
        if accepted and isinstance(request, DestinationBindingOperationEnvelope):
            connection.execute(
                """
                INSERT INTO external_destination_bindings (
                    binding_id, scope_version, brand_id, channel_id, destination_id,
                    adapter_id, external_target_ref, credential_ref,
                    registered_by_principal_id, authenticated_operation_id,
                    registration_event_id, created_at_utc, application_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.target_id,
                    request.scope_version,
                    request.brand_id,
                    request.channel_id,
                    request.destination_id,
                    request.adapter_id,
                    request.external_target_ref,
                    request.credential_ref,
                    authenticated.principal.principal_id,
                    request.operation_id,
                    receipt.run_id,
                    receipt.timestamp_utc,
                    __version__,
                ),
            )
        elif accepted:
            assert isinstance(request, ExecutorRegistrationOperationEnvelope)
            connection.execute(
                """
                INSERT INTO trusted_effect_executors (
                    executor_id, authentication_scheme, key_id, public_key_b64,
                    verifier_fingerprint, allowed_adapter_ids_json,
                    registered_by_principal_id, authenticated_operation_id,
                    registration_event_id, created_at_utc, application_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.target_id,
                    request.executor_authentication_scheme,
                    request.executor_key_id,
                    request.executor_public_key_b64,
                    request.executor_verifier_fingerprint,
                    canonical_json(list(request.allowed_adapter_ids)),
                    authenticated.principal.principal_id,
                    request.operation_id,
                    receipt.run_id,
                    receipt.timestamp_utc,
                    __version__,
                ),
            )
    project_transition_event(paths.database, paths.receipt_log, str(stored["event_id"]))
    result = _management_result(
        request,
        receipt.run_id,
        accepted=accepted,
        reason=None if accepted else rejection_reason,
    )
    if not accepted:
        _raise_management_rejection(decision, result)
    return result


def _effect_from_row(row: object) -> ExternalEffectRequest:
    return ExternalEffectRequest.model_validate(dict(row))  # type: ignore[arg-type]


def _dispatch_from_row(row: object) -> ExternalEffectDispatch:
    return ExternalEffectDispatch.model_validate(dict(row))  # type: ignore[arg-type]


def get_external_effect(
    database_path: Path, effect_id: str
) -> ExternalEffectRequest | None:
    with database.connect(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM external_effect_requests WHERE effect_id = ?", (effect_id,)
        ).fetchone()
    return None if row is None else _effect_from_row(row)


def create_external_effect_request(
    *, paths: WorkspacePaths, packet_id: str, asserted_actor: str | None = None
) -> ExternalEffectRequest:
    """Derive one immutable effect intent solely from a canonical RELEASED packet."""
    packet = database.get_packet(paths.database, packet_id)
    if packet is None:
        raise KeyError(f"Unknown packet: {packet_id}")
    try:
        artifact_hashes, manifest_hash = recompute_packet_manifest(packet)
    except PacketIntegrityError as error:
        raise ExternalEffectIntegrityError(str(error)) from error
    with database.connect(paths.database, immediate=True) as connection:
        packet_row = connection.execute(
            "SELECT * FROM packets WHERE packet_id = ?", (packet_id,)
        ).fetchone()
        if packet_row is None or str(packet_row["state"]) != "RELEASED":
            raise ExternalEffectError("External effects require a RELEASED packet")
        existing = connection.execute(
            "SELECT * FROM external_effect_requests WHERE packet_id = ?", (packet_id,)
        ).fetchone()
        if existing is not None:
            if (
                manifest_hash != existing["packet_manifest_hash"]
                or artifact_hashes.get("packet_receipt.json")
                != existing["packet_receipt_hash"]
                or manifest_hash != packet_row["manifest_hash"]
            ):
                raise ExternalEffectIntegrityError(
                    "Existing effect request no longer matches governed packet artifacts"
                )
            return _effect_from_row(existing)
        current_packet = dict(packet_row)
        current_hashes, current_manifest = recompute_packet_manifest(current_packet)
        if (
            current_manifest != manifest_hash
            or current_hashes != artifact_hashes
            or current_manifest != str(packet_row["manifest_hash"])
        ):
            raise ExternalEffectIntegrityError(
                "Packet artifacts changed while deriving the external effect"
            )
        release = connection.execute(
            """
            SELECT e.*, c.event_sequence, c.event_hash
            FROM transition_events AS e
            JOIN transition_event_chain_entries AS c ON c.event_id = e.event_id
            WHERE e.packet_id = ? AND e.command = 'release'
              AND e.outcome = 'accepted' AND e.resulting_state = 'RELEASED'
            ORDER BY c.event_sequence DESC LIMIT 1
            """,
            (packet_id,),
        ).fetchone()
        if release is None:
            raise ExternalEffectIntegrityError(
                "RELEASED packet lacks its accepted canonical release event"
            )
        identifiers = json.loads(str(release["input_identifiers_json"]))
        release_hashes = json.loads(str(release["file_hashes_json"]))
        grant_id = release["authorization_matching_grant_id"]
        if (
            release["authorization_status"] != "allowed"
            or release["authorization_required_capability"] != "packet.release"
            or grant_id is None
            or release["authenticated_principal_id"] is None
        ):
            raise ExternalEffectIntegrityError(
                "Release event lacks exact authenticated release authority"
            )
        approval_id = identifiers.get("approval_id")
        approval_event_id = identifiers.get("approval_transition_event_id")
        approval = connection.execute(
            """
            SELECT * FROM approvals WHERE approval_id = ? AND packet_id = ?
              AND decision = 'APPROVED' AND transition_event_id = ?
            """,
            (approval_id, packet_id, approval_event_id),
        ).fetchone()
        grant = connection.execute(
            """
            SELECT g.*, c.event_sequence AS grant_sequence,
                   r.policy_event_id AS revocation_event_id,
                   rc.event_sequence AS revocation_sequence
            FROM capability_grants AS g
            JOIN transition_event_chain_entries AS c ON c.event_id = g.policy_event_id
            LEFT JOIN capability_revocations AS r ON r.grant_id = g.grant_id
            LEFT JOIN transition_event_chain_entries AS rc
              ON rc.event_id = r.policy_event_id
            WHERE g.grant_id = ?
            """,
            (grant_id,),
        ).fetchone()
        scope = (
            packet_row["scope_version"],
            packet_row["brand_id"],
            packet_row["channel_id"],
            packet_row["destination_id"],
        )
        if approval is None:
            raise ExternalEffectIntegrityError("Release approval evidence is missing")
        if (
            grant is None
            or grant["subject_principal_id"] != release["authenticated_principal_id"]
            or grant["capability"] != "packet.release"
            or grant["expected_prior_state"] != "APPROVED"
            or grant["requested_state"] != "RELEASED"
            or (
                grant["scope_version"],
                grant["brand_id"],
                grant["channel_id"],
                grant["destination_id"],
            )
            != scope
            or int(grant["grant_sequence"]) >= int(release["event_sequence"])
            or (
                grant["revocation_sequence"] is not None
                and int(grant["revocation_sequence"]) <= int(release["event_sequence"])
            )
        ):
            raise ExternalEffectIntegrityError("Release grant evidence is inconsistent")
        binding = connection.execute(
            """
            SELECT * FROM external_destination_bindings
            WHERE scope_version = ? AND brand_id = ? AND channel_id = ?
              AND destination_id = ?
            """,
            scope,
        ).fetchone()
        if binding is None:
            raise ExternalEffectError(
                "No immutable external destination binding exists for the packet scope"
            )
        effect_seed = canonical_json_hash(
            {
                "release_event_hash": release["event_hash"],
                "destination_binding_id": binding["binding_id"],
            }
        )
        effect_id = f"effect_{effect_seed[:32]}"
        request_event_id = str(uuid4())
        created_at = utc_now()
        values: dict[str, object] = {
            "schema_version": "1.0",
            "effect_id": effect_id,
            "release_event_id": release["event_id"],
            "packet_id": packet_id,
            "candidate_id": packet_row["candidate_id"],
            "approval_id": approval_id,
            "approval_event_id": approval_event_id,
            "authenticated_principal_id": release["authenticated_principal_id"],
            "authorizing_grant_id": grant_id,
            "capability": "packet.release",
            "scope_version": scope[0],
            "brand_id": scope[1],
            "channel_id": scope[2],
            "destination_id": scope[3],
            "destination_binding_id": binding["binding_id"],
            "adapter_id": binding["adapter_id"],
            "external_target_ref": binding["external_target_ref"],
            "credential_ref": binding["credential_ref"],
            "packet_manifest_hash": current_manifest,
            "packet_receipt_hash": current_hashes["packet_receipt.json"],
            "release_event_hash": release["event_hash"],
            "release_event_sequence": int(release["event_sequence"]),
            "idempotency_key": calculate_idempotency_key(
                effect_id, str(release["event_hash"])
            ),
            "created_at_utc": created_at,
            "application_version": __version__,
            "request_event_id": request_event_id,
        }
        values["request_hash"] = calculate_effect_request_hash(values)
        effect = ExternalEffectRequest.model_validate(values)
        receipt = new_receipt(
            command="create-external-effect-request",
            actor=asserted_actor or execution_identity(),
            input_identifiers={
                "effect_id": effect.effect_id,
                "release_event_id": effect.release_event_id,
                "release_event_sequence": effect.release_event_sequence,
                "approval_id": effect.approval_id,
                "approval_transition_event_id": effect.approval_event_id,
                "packet_id": effect.packet_id,
                "candidate_id": effect.candidate_id,
                "authorizing_grant_id": effect.authorizing_grant_id,
                "scope_version": effect.scope_version,
                "brand_id": effect.brand_id,
                "channel_id": effect.channel_id,
                "destination_id": effect.destination_id,
                "destination_binding_id": effect.destination_binding_id,
                "adapter_id": effect.adapter_id,
                "external_target_ref": effect.external_target_ref,
                "credential_ref": effect.credential_ref,
                "idempotency_key": effect.idempotency_key,
                "request_hash": effect.request_hash,
            },
            prior_state="RELEASED",
            requested_transition="EXTERNAL_EFFECT_REQUESTED",
            resulting_state="RELEASED",
            outcome="accepted",
            reason="Derived immutable external-effect intent from canonical release authority.",
            file_hashes={
                **current_hashes,
                "packet_manifest": current_manifest,
                "release_event": str(release["event_hash"]),
                "effect_request": effect.request_hash,
            },
            timestamp_utc=created_at,
        )
        event = transition_event_from_receipt(
            receipt,
            target_type="external_effect",
            target_id=effect.effect_id,
            governed_hash=effect.request_hash,
        )
        event["event_id"] = request_event_id
        payload = json.loads(str(event["receipt_json"]))
        payload["run_id"] = request_event_id
        event["receipt_json"] = canonical_json(payload)
        event["input_identifiers_json"] = canonical_json(receipt.input_identifiers)
        database.insert_transition_event(connection, event)
        connection.execute(
            """
            INSERT INTO external_effect_requests (
                effect_id, release_event_id, packet_id, candidate_id, approval_id,
                approval_event_id, authenticated_principal_id, authorizing_grant_id,
                capability, scope_version, brand_id, channel_id, destination_id,
                destination_binding_id, adapter_id, external_target_ref, credential_ref,
                packet_manifest_hash, packet_receipt_hash, release_event_hash,
                release_event_sequence, idempotency_key, request_hash, created_at_utc,
                application_version, request_event_id
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?
            )
            """,
            tuple(values[field] for field in (
                "effect_id", "release_event_id", "packet_id", "candidate_id",
                "approval_id", "approval_event_id", "authenticated_principal_id",
                "authorizing_grant_id", "capability", "scope_version", "brand_id",
                "channel_id", "destination_id", "destination_binding_id", "adapter_id",
                "external_target_ref", "credential_ref", "packet_manifest_hash",
                "packet_receipt_hash", "release_event_hash", "release_event_sequence",
                "idempotency_key", "request_hash", "created_at_utc",
                "application_version", "request_event_id",
            )),
        )
    project_transition_event(paths.database, paths.receipt_log, request_event_id)
    return effect


def claim_external_effect(
    *, paths: WorkspacePaths, effect_id: str, asserted_actor: str | None = None
) -> ExternalEffectDispatch:
    """Atomically acquire the sole safe execution claim for an effect attempt."""
    with database.connect(paths.database, immediate=True) as connection:
        effect_row = connection.execute(
            "SELECT * FROM external_effect_requests WHERE effect_id = ?", (effect_id,)
        ).fetchone()
        if effect_row is None:
            raise KeyError(f"Unknown external effect: {effect_id}")
        latest = connection.execute(
            """
            SELECT d.*, r.outcome, r.retry_permitted
            FROM external_effect_dispatches AS d
            LEFT JOIN external_effect_results AS r ON r.dispatch_id = d.dispatch_id
            WHERE d.effect_id = ? ORDER BY d.attempt_number DESC LIMIT 1
            """,
            (effect_id,),
        ).fetchone()
        if latest is not None and latest["outcome"] is None:
            raise ExternalEffectClaimError(
                "The active execution claim is unresolved; blind retry is prohibited"
            )
        if latest is not None and (
            latest["outcome"] != "FAILED" or not bool(latest["retry_permitted"])
        ):
            raise ExternalEffectClaimError(
                "The prior result does not permit another external-effect attempt"
            )
        attempt = 1 if latest is None else int(latest["attempt_number"]) + 1
        dispatch_id = f"dispatch_{uuid4().hex}"
        event_id = str(uuid4())
        claimed_at = utc_now()
        dispatch = ExternalEffectDispatch(
            dispatch_id=dispatch_id,
            effect_id=effect_id,
            effect_request_hash=str(effect_row["request_hash"]),
            attempt_number=attempt,
            claimed_at_utc=claimed_at,
            application_version=__version__,
            dispatch_event_id=event_id,
        )
        receipt = new_receipt(
            command="claim-external-effect",
            actor=asserted_actor or execution_identity(),
            input_identifiers={
                "effect_id": effect_id,
                "dispatch_id": dispatch_id,
                "effect_request_hash": dispatch.effect_request_hash,
                "attempt_number": attempt,
                "idempotency_key": effect_row["idempotency_key"],
            },
            prior_state="REQUESTED" if attempt == 1 else "FAILED",
            requested_transition="DISPATCH_CLAIMED",
            resulting_state="DISPATCH_CLAIMED",
            outcome="accepted",
            reason="Acquired exclusive external-effect execution claim.",
            file_hashes={"effect_request": dispatch.effect_request_hash},
            timestamp_utc=claimed_at,
        )
        event = transition_event_from_receipt(
            receipt,
            target_type="external_effect_dispatch",
            target_id=dispatch_id,
            governed_hash=dispatch.effect_request_hash,
        )
        event["event_id"] = event_id
        payload = json.loads(str(event["receipt_json"]))
        payload["run_id"] = event_id
        event["receipt_json"] = canonical_json(payload)
        database.insert_transition_event(connection, event)
        connection.execute(
            """
            INSERT INTO external_effect_dispatches (
                dispatch_id, effect_id, effect_request_hash, attempt_number,
                claimed_at_utc, application_version, dispatch_event_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                dispatch.dispatch_id,
                dispatch.effect_id,
                dispatch.effect_request_hash,
                dispatch.attempt_number,
                dispatch.claimed_at_utc,
                dispatch.application_version,
                dispatch.dispatch_event_id,
            ),
        )
    project_transition_event(paths.database, paths.receipt_log, event_id)
    return dispatch


def record_signed_executor_result(
    *,
    paths: WorkspacePaths,
    signed_result: SignedExecutorResult,
    asserted_actor: str | None = None,
) -> dict[str, object]:
    """Verify and atomically ingest one executor-signed terminal attempt result."""
    envelope = signed_result.envelope
    with database.connect(paths.database, immediate=True) as connection:
        executor = connection.execute(
            "SELECT * FROM trusted_effect_executors WHERE executor_id = ?",
            (envelope.executor_id,),
        ).fetchone()
        if executor is None:
            raise ExternalEffectError("Executor identity is not trusted")
        envelope_hash, proof_hash = verify_executor_result_signature(
            signed_result, dict(executor)
        )
        allowed = json.loads(str(executor["allowed_adapter_ids_json"]))
        if envelope.adapter_id not in allowed:
            raise ExternalEffectError("Executor is not registered for this adapter")
        dispatch = connection.execute(
            "SELECT * FROM external_effect_dispatches WHERE dispatch_id = ?",
            (envelope.dispatch_id,),
        ).fetchone()
        effect = connection.execute(
            "SELECT * FROM external_effect_requests WHERE effect_id = ?",
            (envelope.effect_id,),
        ).fetchone()
        if dispatch is None or effect is None:
            raise ExternalEffectError("Executor result targets an unknown effect claim")
        existing = connection.execute(
            "SELECT * FROM external_effect_results WHERE dispatch_id = ?",
            (envelope.dispatch_id,),
        ).fetchone()
        if existing is not None:
            if str(existing["proof_hash"]) == proof_hash:
                return dict(existing)
            raise ExternalEffectError("Execution claim already has an immutable result")
        expected = {
            "effect_id": effect["effect_id"],
            "effect_request_hash": effect["request_hash"],
            "adapter_id": effect["adapter_id"],
            "scope_version": effect["scope_version"],
            "brand_id": effect["brand_id"],
            "channel_id": effect["channel_id"],
            "destination_id": effect["destination_id"],
            "destination_binding_id": effect["destination_binding_id"],
            "artifact_hash": effect["packet_manifest_hash"],
            "idempotency_key": effect["idempotency_key"],
        }
        mismatches = [
            field
            for field, expected_value in expected.items()
            if getattr(envelope, field) != expected_value
        ]
        if dispatch["effect_id"] != envelope.effect_id:
            mismatches.append("dispatch.effect_id")
        if dispatch["effect_request_hash"] != envelope.effect_request_hash:
            mismatches.append("dispatch.effect_request_hash")
        if mismatches:
            raise ExternalEffectIntegrityError(
                "Executor result binding mismatch: " + ", ".join(sorted(mismatches))
            )
        event_id = str(uuid4())
        receipt = new_receipt(
            command="record-external-effect-result",
            actor=asserted_actor or f"executor:{envelope.executor_id}",
            input_identifiers={
                "effect_id": envelope.effect_id,
                "dispatch_id": envelope.dispatch_id,
                "result_id": envelope.result_id,
                "executor_id": envelope.executor_id,
                "executor_key_id": envelope.executor_key_id,
                "effect_request_hash": envelope.effect_request_hash,
                "destination_binding_id": envelope.destination_binding_id,
                "adapter_id": envelope.adapter_id,
                "idempotency_key": envelope.idempotency_key,
                "effect_outcome": envelope.outcome.value,
                "effect_may_have_occurred": envelope.effect_may_have_occurred,
                "retry_permitted": envelope.retry_permitted,
                "remote_reference": envelope.remote_reference,
                "response_hash": envelope.response_hash,
                "error_code": envelope.error_code,
                "executor_envelope_hash": envelope_hash,
                "executor_proof_hash": proof_hash,
            },
            prior_state="DISPATCH_CLAIMED",
            requested_transition=envelope.outcome.value,
            resulting_state=envelope.outcome.value,
            outcome="accepted",
            reason="Verified executor-signed external-effect result.",
            file_hashes={
                "effect_request": envelope.effect_request_hash,
                "packet_manifest": envelope.artifact_hash,
                "executor_envelope": envelope_hash,
                "executor_proof": proof_hash,
                **(
                    {}
                    if envelope.response_hash is None
                    else {"provider_response": envelope.response_hash}
                ),
            },
        )
        event = transition_event_from_receipt(
            receipt,
            target_type="external_effect_result",
            target_id=envelope.result_id,
            governed_hash=envelope.effect_request_hash,
        )
        event["event_id"] = event_id
        payload = json.loads(str(event["receipt_json"]))
        payload["run_id"] = event_id
        event["receipt_json"] = canonical_json(payload)
        database.insert_transition_event(connection, event)
        connection.execute(
            """
            INSERT INTO external_effect_results (
                result_id, effect_id, dispatch_id, executor_id, executor_key_id,
                effect_request_hash, adapter_id, scope_version, brand_id, channel_id,
                destination_id, destination_binding_id, artifact_hash, idempotency_key,
                outcome, effect_may_have_occurred, retry_permitted, remote_reference,
                response_hash, error_code, started_at_utc, completed_at_utc,
                envelope_json, signature_b64, envelope_hash, proof_hash, result_event_id
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            """,
            (
                envelope.result_id,
                envelope.effect_id,
                envelope.dispatch_id,
                envelope.executor_id,
                envelope.executor_key_id,
                envelope.effect_request_hash,
                envelope.adapter_id,
                envelope.scope_version,
                envelope.brand_id,
                envelope.channel_id,
                envelope.destination_id,
                envelope.destination_binding_id,
                envelope.artifact_hash,
                envelope.idempotency_key,
                envelope.outcome.value,
                int(envelope.effect_may_have_occurred),
                int(envelope.retry_permitted),
                envelope.remote_reference,
                envelope.response_hash,
                envelope.error_code,
                envelope.started_at_utc,
                envelope.completed_at_utc,
                canonical_json(envelope.model_dump(mode="json")),
                signed_result.signature_b64,
                envelope_hash,
                proof_hash,
                event_id,
            ),
        )
        result = dict(
            connection.execute(
                "SELECT * FROM external_effect_results WHERE result_id = ?",
                (envelope.result_id,),
            ).fetchone()
        )
    project_transition_event(paths.database, paths.receipt_log, event_id)
    return result


def list_external_effects(database_path: Path) -> list[dict[str, object]]:
    """Return read-only effect status without resolving any credential reference."""
    with database.connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT q.*, d.dispatch_id, d.attempt_number, d.claimed_at_utc,
                   r.result_id, r.executor_id, r.outcome, r.effect_may_have_occurred,
                   r.retry_permitted, r.remote_reference, r.error_code,
                   r.completed_at_utc
            FROM external_effect_requests AS q
            LEFT JOIN external_effect_dispatches AS d ON d.effect_id = q.effect_id
              AND d.attempt_number = (
                SELECT MAX(d2.attempt_number) FROM external_effect_dispatches AS d2
                WHERE d2.effect_id = q.effect_id
              )
            LEFT JOIN external_effect_results AS r ON r.dispatch_id = d.dispatch_id
            ORDER BY q.created_at_utc, q.effect_id
            """
        ).fetchall()
    return [dict(row) for row in rows]


def list_destination_bindings(database_path: Path) -> list[dict[str, object]]:
    with database.connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT * FROM external_destination_bindings
            ORDER BY brand_id, channel_id, destination_id, binding_id
            """
        ).fetchall()
    return [dict(row) for row in rows]
