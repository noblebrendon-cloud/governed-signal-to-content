from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from governed_signal_to_content import cli, database
from governed_signal_to_content.authentication import (
    APPROVAL_REASON,
    RELEASE_REASON,
    AuthenticationError,
    ReplayDetected,
    generate_signing_key,
    prepare_operation,
    prepare_policy_operation,
    sign_operation,
)
from governed_signal_to_content.authorization import (
    AuthorizationRejected,
    CapabilityPolicyEvaluator,
)
from governed_signal_to_content.config import WorkspacePaths
from governed_signal_to_content.integrity import verify_integrity
from governed_signal_to_content.models import (
    AuthorizationReason,
    AuthorityOperation,
    Capability,
    CapabilityPolicyOperation,
    PacketScope,
    SignedOperation,
    WorkflowState,
)
from governed_signal_to_content.packets import generate_packet
from governed_signal_to_content.transition_mediator import (
    mediate_signed_policy_operation,
    mediate_signed_transition,
)


SCOPE_A = PacketScope(
    brand_id="brand-test",
    channel_id="channel-test",
    destination_id="destination-test",
)


def _scope(**changes: str) -> PacketScope:
    return SCOPE_A.model_copy(update=changes)


def _generate(
    qualified_candidate: tuple[WorkspacePaths, str], content_inputs_path: Path
) -> tuple[WorkspacePaths, str, str]:
    paths, candidate_id = qualified_candidate
    packet_id, _, _, _ = generate_packet(paths, candidate_id, content_inputs_path)
    return paths, candidate_id, packet_id


def _signed_policy(
    paths: WorkspacePaths,
    authentication_material: dict[str, object],
    operation: CapabilityPolicyOperation,
    *,
    capability: Capability | None = None,
    scope: PacketScope | None = None,
    grant_id: str | None = None,
) -> SignedOperation:
    envelope = prepare_policy_operation(
        paths=paths,
        operation=operation,
        principal_id=str(authentication_material["principal_id"]),
        subject_principal_id=(
            str(authentication_material["principal_id"])
            if operation is CapabilityPolicyOperation.GRANT
            else None
        ),
        capability=capability,
        grant_id=grant_id,
        brand_id=None if scope is None else scope.brand_id,
        channel_id=None if scope is None else scope.channel_id,
        destination_id=None if scope is None else scope.destination_id,
        reason=f"Slice 6 {operation.value}.",
    )
    return sign_operation(
        envelope, Path(str(authentication_material["private_key"]))
    )


def _bootstrap(
    paths: WorkspacePaths, authentication_material: dict[str, object]
) -> str:
    signed = _signed_policy(
        paths, authentication_material, CapabilityPolicyOperation.BOOTSTRAP
    )
    return mediate_signed_policy_operation(
        paths=paths,
        signed_operation=signed,
        asserted_actor="scope-policy-display",
    ).grant_id


def _grant(
    paths: WorkspacePaths,
    authentication_material: dict[str, object],
    capability: Capability,
    scope: PacketScope = SCOPE_A,
) -> str:
    signed = _signed_policy(
        paths,
        authentication_material,
        CapabilityPolicyOperation.GRANT,
        capability=capability,
        scope=scope,
    )
    return mediate_signed_policy_operation(
        paths=paths,
        signed_operation=signed,
        asserted_actor="scope-policy-display",
    ).grant_id


def _signed_packet(
    paths: WorkspacePaths,
    authentication_material: dict[str, object],
    packet_id: str,
    operation: AuthorityOperation,
    reason: str,
) -> SignedOperation:
    envelope = prepare_operation(
        paths=paths,
        operation=operation,
        packet_id=packet_id,
        principal_id=str(authentication_material["principal_id"]),
        reason=reason,
    )
    return sign_operation(
        envelope, Path(str(authentication_material["private_key"]))
    )


def test_packet_generation_binds_canonical_scope_into_manifest_and_receipt(
    qualified_candidate: tuple[WorkspacePaths, str], content_inputs_path: Path
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    packet = database.get_packet(paths.database, packet_id)
    assert packet is not None
    assert (
        packet["scope_version"],
        packet["brand_id"],
        packet["channel_id"],
        packet["destination_id"],
    ) == ("1.0", SCOPE_A.brand_id, SCOPE_A.channel_id, SCOPE_A.destination_id)
    packet_path = Path(str(packet["packet_path"]))
    sources = json.loads((packet_path / "sources.json").read_text(encoding="utf-8"))
    receipt = json.loads(
        (packet_path / "packet_receipt.json").read_text(encoding="utf-8")
    )
    assert sources["scope"] == SCOPE_A.model_dump(mode="json")
    assert receipt["scope"] == SCOPE_A.model_dump(mode="json")
    generation_events = [
        event
        for event in database.pending_transition_events(paths.database)
        if event["packet_id"] == packet_id
    ]
    assert not generation_events  # both generation receipts projected
    assert verify_integrity(paths.database, paths.receipt_log).canonical_policy_valid


def test_exact_scoped_approval_records_grant_event_and_approval_scope(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    grant_id = _grant(
        paths, authentication_material, Capability.PACKET_APPROVE, SCOPE_A
    )
    signed = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    result = mediate_signed_transition(
        paths=paths, signed_operation=signed, asserted_actor="reviewer-display"
    )
    event = database.get_transition_event(paths.database, result.canonical_event_id)
    approval = database.get_approved_approval(paths.database, packet_id)
    assert event is not None and approval is not None
    assert event["authorization_matching_grant_id"] == grant_id
    assert (
        event["authorization_brand_id"],
        event["authorization_channel_id"],
        event["authorization_destination_id"],
    ) == (SCOPE_A.brand_id, SCOPE_A.channel_id, SCOPE_A.destination_id)
    assert (
        approval["brand_id"],
        approval["channel_id"],
        approval["destination_id"],
    ) == (SCOPE_A.brand_id, SCOPE_A.channel_id, SCOPE_A.destination_id)


@pytest.mark.parametrize(
    ("grant_scope", "expected_reason"),
    [
        (_scope(brand_id="brand-other"), AuthorizationReason.BRAND_SCOPE_MISMATCH),
        (
            _scope(channel_id="channel-other"),
            AuthorizationReason.CHANNEL_SCOPE_MISMATCH,
        ),
        (
            _scope(destination_id="destination-other"),
            AuthorizationReason.DESTINATION_SCOPE_MISMATCH,
        ),
        (
            _scope(brand_id="brand-other", channel_id="channel-other"),
            AuthorizationReason.BRAND_SCOPE_MISMATCH,
        ),
        (
            _scope(
                brand_id="brand-other",
                channel_id="channel-other",
                destination_id="destination-other",
            ),
            AuthorizationReason.BRAND_SCOPE_MISMATCH,
        ),
    ],
)
def test_scope_mismatch_denies_consumes_and_records_actual_packet_scope(
    grant_scope: PacketScope,
    expected_reason: AuthorizationReason,
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    _bootstrap(paths, authentication_material)
    _grant(paths, authentication_material, Capability.PACKET_APPROVE, grant_scope)
    signed = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    with pytest.raises(AuthorizationRejected) as caught:
        mediate_signed_transition(
            paths=paths, signed_operation=signed, asserted_actor="display-only"
        )
    assert caught.value.decision.reason is expected_reason
    assert (
        caught.value.decision.brand_id,
        caught.value.decision.channel_id,
        caught.value.decision.destination_id,
    ) == (SCOPE_A.brand_id, SCOPE_A.channel_id, SCOPE_A.destination_id)
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.find_consumed_authenticated_operation(
        paths.database, signed.envelope.operation_id, "unused"
    ) is not None


def test_scoped_reject_and_release_require_independent_exact_grants(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    _grant(paths, authentication_material, Capability.PACKET_RELEASE)
    approve = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    mediate_signed_transition(
        paths=paths, signed_operation=approve, asserted_actor="approve-display"
    )
    release = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.RELEASE,
        RELEASE_REASON,
    )
    released = mediate_signed_transition(
        paths=paths, signed_operation=release, asserted_actor="release-display"
    )
    event = database.get_transition_event(paths.database, released.canonical_event_id)
    approval = database.get_approved_approval(paths.database, packet_id)
    assert event is not None and approval is not None
    assert event["authorization_destination_id"] == approval["destination_id"]
    assert database.get_packet(paths.database, packet_id)["state"] == "RELEASED"  # type: ignore[index]


@pytest.mark.parametrize("field", ["brand_id", "channel_id", "destination_id"])
def test_packet_scope_substitution_after_signing_invalidates_signature(
    field: str,
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    signed = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    tampered = signed.model_copy(
        update={
            "envelope": signed.envelope.model_copy(
                update={field: f"{field.removesuffix('_id')}-substituted"}
            )
        }
    )
    with pytest.raises(AuthenticationError):
        mediate_signed_transition(
            paths=paths, signed_operation=tampered, asserted_actor="display-only"
        )


@pytest.mark.parametrize("field", ["brand_id", "channel_id", "destination_id"])
def test_signed_grant_scope_substitution_invalidates_signature(
    field: str,
    workspace: WorkspacePaths,
    authentication_material: dict[str, object],
) -> None:
    _bootstrap(workspace, authentication_material)
    signed = _signed_policy(
        workspace,
        authentication_material,
        CapabilityPolicyOperation.GRANT,
        capability=Capability.PACKET_APPROVE,
        scope=SCOPE_A,
    )
    tampered = signed.model_copy(
        update={
            "envelope": signed.envelope.model_copy(
                update={field: f"{field.removesuffix('_id')}-substituted"}
            )
        }
    )
    with pytest.raises(AuthenticationError):
        mediate_signed_policy_operation(
            paths=workspace,
            signed_operation=tampered,
            asserted_actor="display-only",
        )


@pytest.mark.parametrize(
    "missing",
    ["brand_id", "channel_id", "destination_id"],
)
def test_operational_grant_requires_complete_scope(
    missing: str,
    workspace: WorkspacePaths,
    authentication_material: dict[str, object],
) -> None:
    values: dict[str, str | None] = {
        "brand_id": SCOPE_A.brand_id,
        "channel_id": SCOPE_A.channel_id,
        "destination_id": SCOPE_A.destination_id,
    }
    values[missing] = None
    with pytest.raises(ValueError, match="requires brand, channel, and destination"):
        prepare_policy_operation(
            paths=workspace,
            operation=CapabilityPolicyOperation.GRANT,
            principal_id=str(authentication_material["principal_id"]),
            subject_principal_id=str(authentication_material["principal_id"]),
            capability=Capability.PACKET_APPROVE,
            reason="Incomplete scope must fail.",
            **values,
        )


@pytest.mark.parametrize(
    "value",
    [
        "Brand-Upper",
        "*",
        "space value",
        "destination-token",
        "private-key-path",
        "all",
        "channel-any",
    ],
)
def test_scope_identifiers_reject_ambiguous_or_credential_shaped_values(
    value: str,
) -> None:
    with pytest.raises(ValidationError):
        PacketScope(
            brand_id="brand-test",
            channel_id="channel-test",
            destination_id=value,
        )


def test_legacy_unscoped_operational_grant_is_not_wildcard_authority(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    grant_id = _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    with database.connect(paths.database) as connection:
        connection.execute(
            """
            UPDATE capability_grants
            SET scope_version = NULL, brand_id = NULL,
                channel_id = NULL, destination_id = NULL
            WHERE grant_id = ?
            """,
            (grant_id,),
        )
    signed = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    with pytest.raises(AuthorizationRejected) as caught:
        mediate_signed_transition(
            paths=paths, signed_operation=signed, asserted_actor="display-only"
        )
    assert caught.value.decision.reason is AuthorizationReason.LEGACY_UNSCOPED_GRANT
    fresh_grant = _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    assert fresh_grant != grant_id
    fresh = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    mediate_signed_transition(
        paths=paths, signed_operation=fresh, asserted_actor="display-only"
    )


def test_legacy_policy_admin_grant_remains_effective_for_scoped_grants(
    workspace: WorkspacePaths, authentication_material: dict[str, object]
) -> None:
    admin_grant = _bootstrap(workspace, authentication_material)
    with database.connect(workspace.database) as connection:
        connection.execute(
            "UPDATE capability_grants SET scope_version = NULL WHERE grant_id = ?",
            (admin_grant,),
        )
    grant_id = _grant(
        workspace, authentication_material, Capability.PACKET_RELEASE, SCOPE_A
    )
    grant = database.get_capability_grant(workspace.database, grant_id)
    assert grant is not None and grant["destination_id"] == SCOPE_A.destination_id


def test_unscoped_legacy_packet_denies_and_consumes_prepared_proof(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    signed = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    with database.connect(paths.database) as connection:
        connection.execute(
            """
            UPDATE packets SET scope_version = NULL, brand_id = NULL,
                channel_id = NULL, destination_id = NULL WHERE packet_id = ?
            """,
            (packet_id,),
        )
    with pytest.raises(Exception) as caught:
        mediate_signed_transition(
            paths=paths, signed_operation=signed, asserted_actor="display-only"
        )
    decision = getattr(caught.value, "transition_result", None)
    assert decision is not None
    event = database.get_transition_event(
        paths.database, decision.canonical_event_id
    )
    assert event is not None
    assert event["authorization_reason_code"] == "SCOPE_REQUIRED"
    assert database.find_consumed_authenticated_operation(
        paths.database, signed.envelope.operation_id, "unused"
    ) is not None


def test_post_approval_scope_mutation_cannot_preserve_release_authority(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    _grant(paths, authentication_material, Capability.PACKET_RELEASE)
    mediate_signed_transition(
        paths=paths,
        signed_operation=_signed_packet(
            paths,
            authentication_material,
            packet_id,
            AuthorityOperation.APPROVE,
            APPROVAL_REASON,
        ),
        asserted_actor="approve-display",
    )
    release = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.RELEASE,
        RELEASE_REASON,
    )
    with database.connect(paths.database) as connection:
        connection.execute(
            "UPDATE packets SET destination_id = 'destination-other' WHERE packet_id = ?",
            (packet_id,),
        )
    with pytest.raises(Exception) as caught:
        mediate_signed_transition(
            paths=paths, signed_operation=release, asserted_actor="release-display"
        )
    result = getattr(caught.value, "transition_result", None)
    assert result is not None
    event = database.get_transition_event(paths.database, result.canonical_event_id)
    assert event is not None
    assert event["authorization_reason_code"] == "REQUEST_SCOPE_MISMATCH"
    assert database.get_packet(paths.database, packet_id)["state"] == "APPROVED"  # type: ignore[index]


def test_denied_destination_proof_does_not_revive_after_matching_grant(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    mediate_signed_transition(
        paths=paths,
        signed_operation=_signed_packet(
            paths,
            authentication_material,
            packet_id,
            AuthorityOperation.APPROVE,
            APPROVAL_REASON,
        ),
        asserted_actor="approve-display",
    )
    denied = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.RELEASE,
        RELEASE_REASON,
    )
    with pytest.raises(AuthorizationRejected):
        mediate_signed_transition(
            paths=paths, signed_operation=denied, asserted_actor="release-display"
        )
    _grant(paths, authentication_material, Capability.PACKET_RELEASE)
    with pytest.raises(ReplayDetected):
        mediate_signed_transition(
            paths=paths, signed_operation=denied, asserted_actor="release-display"
        )
    fresh = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.RELEASE,
        RELEASE_REASON,
    )
    mediate_signed_transition(
        paths=paths, signed_operation=fresh, asserted_actor="release-display"
    )


def test_revoking_one_destination_does_not_revoke_another_scope(
    workspace: WorkspacePaths, authentication_material: dict[str, object]
) -> None:
    _bootstrap(workspace, authentication_material)
    scope_d2 = _scope(destination_id="destination-two")
    grant_d1 = _grant(
        workspace, authentication_material, Capability.PACKET_APPROVE, SCOPE_A
    )
    grant_d2 = _grant(
        workspace, authentication_material, Capability.PACKET_APPROVE, scope_d2
    )
    revoke = _signed_policy(
        workspace,
        authentication_material,
        CapabilityPolicyOperation.REVOKE,
        grant_id=grant_d1,
    )
    mediate_signed_policy_operation(
        paths=workspace, signed_operation=revoke, asserted_actor="policy-display"
    )
    with database.connect(workspace.database) as connection:
        denied_d1 = CapabilityPolicyEvaluator.evaluate(
            connection,
            principal_id=str(authentication_material["principal_id"]),
            required_capability=Capability.PACKET_APPROVE,
            actual_prior_state=WorkflowState.AWAITING_APPROVAL,
            requested_state=WorkflowState.APPROVED,
            brand_id=SCOPE_A.brand_id,
            channel_id=SCOPE_A.channel_id,
            destination_id=SCOPE_A.destination_id,
        )
        allowed_d2 = CapabilityPolicyEvaluator.evaluate(
            connection,
            principal_id=str(authentication_material["principal_id"]),
            required_capability=Capability.PACKET_APPROVE,
            actual_prior_state=WorkflowState.AWAITING_APPROVAL,
            requested_state=WorkflowState.APPROVED,
            brand_id=scope_d2.brand_id,
            channel_id=scope_d2.channel_id,
            destination_id=scope_d2.destination_id,
        )
    assert denied_d1.reason is AuthorizationReason.GRANT_REVOKED
    assert allowed_d2.allowed and allowed_d2.matching_grant_id == grant_d2


def test_duplicate_exact_scope_grants_select_earliest_event_sequence(
    workspace: WorkspacePaths, authentication_material: dict[str, object]
) -> None:
    _bootstrap(workspace, authentication_material)
    first = _grant(
        workspace, authentication_material, Capability.PACKET_RELEASE, SCOPE_A
    )
    second = _grant(
        workspace, authentication_material, Capability.PACKET_RELEASE, SCOPE_A
    )
    with database.connect(workspace.database) as connection:
        decision = CapabilityPolicyEvaluator.evaluate(
            connection,
            principal_id=str(authentication_material["principal_id"]),
            required_capability=Capability.PACKET_RELEASE,
            actual_prior_state=WorkflowState.APPROVED,
            requested_state=WorkflowState.RELEASED,
            brand_id=SCOPE_A.brand_id,
            channel_id=SCOPE_A.channel_id,
            destination_id=SCOPE_A.destination_id,
        )
    assert first != second
    assert decision.allowed and decision.matching_grant_id == first


def test_concurrent_different_destination_grants_remain_distinct_and_linear(
    workspace: WorkspacePaths, authentication_material: dict[str, object]
) -> None:
    _bootstrap(workspace, authentication_material)
    scopes = [SCOPE_A, _scope(destination_id="destination-two")]
    signed = [
        _signed_policy(
            workspace,
            authentication_material,
            CapabilityPolicyOperation.GRANT,
            capability=Capability.PACKET_RELEASE,
            scope=scope,
        )
        for scope in scopes
    ]

    def submit(operation: SignedOperation) -> str:
        return mediate_signed_policy_operation(
            paths=workspace,
            signed_operation=operation,
            asserted_actor="concurrent-policy",
        ).grant_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        grant_ids = list(executor.map(submit, signed))
    assert len(set(grant_ids)) == 2
    grants = database.list_capability_grants(workspace.database)
    operational = [
        grant for grant in grants if grant["capability"] == "packet.release"
    ]
    assert {grant["destination_id"] for grant in operational} == {
        scope.destination_id for scope in scopes
    }
    result = verify_integrity(workspace.database, workspace.receipt_log)
    assert result.canonical_chain_valid and result.canonical_policy_valid


@pytest.mark.parametrize(
    "column",
    [
        "authorization_brand_id",
        "authorization_channel_id",
        "authorization_destination_id",
    ],
)
def test_scope_authorization_evidence_is_hash_covered(
    column: str,
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    result = mediate_signed_transition(
        paths=paths,
        signed_operation=_signed_packet(
            paths,
            authentication_material,
            packet_id,
            AuthorityOperation.APPROVE,
            APPROVAL_REASON,
        ),
        asserted_actor="display-only",
    )
    with database.connect(paths.database) as connection:
        connection.execute(
            f"UPDATE transition_events SET {column} = 'scope-tampered' "  # noqa: S608
            "WHERE event_id = ?",
            (result.canonical_event_id,),
        )
    integrity = verify_integrity(paths.database, paths.receipt_log)
    assert not integrity.canonical_chain_valid
    assert not integrity.canonical_policy_valid


def test_integrity_rejects_inconsistent_scope_authorization_reason(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    result = mediate_signed_transition(
        paths=paths,
        signed_operation=_signed_packet(
            paths,
            authentication_material,
            packet_id,
            AuthorityOperation.APPROVE,
            APPROVAL_REASON,
        ),
        asserted_actor="display-only",
    )
    with database.connect(paths.database) as connection:
        connection.execute(
            "UPDATE transition_events SET authorization_reason_code = 'FABRICATED' "
            "WHERE event_id = ?",
            (result.canonical_event_id,),
        )
    integrity = verify_integrity(paths.database, paths.receipt_log)
    assert not integrity.canonical_chain_valid
    assert not integrity.canonical_policy_valid
    assert any(
        failure.code == "invalid_authorization_reason"
        for failure in integrity.failures
    )


def test_integrity_detects_grant_packet_and_approval_scope_divergence(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    grant_id = _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    result = mediate_signed_transition(
        paths=paths,
        signed_operation=_signed_packet(
            paths,
            authentication_material,
            packet_id,
            AuthorityOperation.APPROVE,
            APPROVAL_REASON,
        ),
        asserted_actor="display-only",
    )
    with database.connect(paths.database) as connection:
        connection.execute(
            "UPDATE capability_grants SET destination_id = 'destination-other' "
            "WHERE grant_id = ?",
            (grant_id,),
        )
    grant_corrupt = verify_integrity(paths.database, paths.receipt_log)
    assert grant_corrupt.canonical_chain_valid
    assert any(f.code == "grant_event_mismatch" for f in grant_corrupt.failures)
    with database.connect(paths.database) as connection:
        connection.execute(
            "UPDATE capability_grants SET destination_id = ? WHERE grant_id = ?",
            (SCOPE_A.destination_id, grant_id),
        )
        connection.execute(
            "UPDATE packets SET destination_id = 'destination-other' WHERE packet_id = ?",
            (packet_id,),
        )
    packet_corrupt = verify_integrity(paths.database, paths.receipt_log)
    assert any(
        f.code in {"packet_scope_evidence_mismatch", "packet_event_scope_mismatch"}
        for f in packet_corrupt.failures
    )
    with database.connect(paths.database) as connection:
        connection.execute(
            "UPDATE packets SET destination_id = ? WHERE packet_id = ?",
            (SCOPE_A.destination_id, packet_id),
        )
        connection.execute(
            "UPDATE approvals SET destination_id = 'destination-other' "
            "WHERE transition_event_id = ?",
            (result.canonical_event_id,),
        )
    approval_corrupt = verify_integrity(paths.database, paths.receipt_log)
    assert any(f.code == "approval_scope_mismatch" for f in approval_corrupt.failures)


def test_schema4_to_5_migration_preserves_chain_policy_receipts_and_jsonl(
    workspace: WorkspacePaths,
    authentication_material: dict[str, object],
) -> None:
    _bootstrap(workspace, authentication_material)
    grant_id = _grant(
        workspace, authentication_material, Capability.PACKET_APPROVE, SCOPE_A
    )
    mediate_signed_policy_operation(
        paths=workspace,
        signed_operation=_signed_policy(
            workspace,
            authentication_material,
            CapabilityPolicyOperation.REVOKE,
            grant_id=grant_id,
        ),
        asserted_actor="migration-display",
    )
    with database.connect(workspace.database) as connection:
        connection.execute(
            """
            UPDATE capability_grants
            SET scope_version = NULL, brand_id = NULL,
                channel_id = NULL, destination_id = NULL
            WHERE grant_id = ?
            """,
            (grant_id,),
        )
        connection.execute("PRAGMA user_version = 4")
        events_before = [
            tuple(row)
            for row in connection.execute(
                """
                SELECT e.event_id, e.receipt_json, c.event_sequence,
                       c.previous_event_hash, c.event_hash
                FROM transition_events AS e
                JOIN transition_event_chain_entries AS c ON c.event_id = e.event_id
                ORDER BY c.event_sequence
                """
            ).fetchall()
        ]
        chain_before = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
        grants_before = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM capability_grants ORDER BY grant_id"
            ).fetchall()
        ]
        revocations_before = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM capability_revocations ORDER BY revocation_id"
            ).fetchall()
        ]
        policy_before = dict(
            connection.execute("SELECT * FROM capability_policy_state").fetchone()
        )
    jsonl_before = workspace.receipt_log.read_bytes()
    database_bytes_before_verify = workspace.database.read_bytes()
    schema4_result = verify_integrity(workspace.database, workspace.receipt_log)
    assert schema4_result.canonical_chain_valid
    assert not schema4_result.canonical_policy_valid
    assert workspace.database.read_bytes() == database_bytes_before_verify

    database.migrate_database(workspace.database)
    database.migrate_database(workspace.database)

    with database.connect(workspace.database) as connection:
        assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == 6
        assert [
            tuple(row)
            for row in connection.execute(
                """
                SELECT e.event_id, e.receipt_json, c.event_sequence,
                       c.previous_event_hash, c.event_hash
                FROM transition_events AS e
                JOIN transition_event_chain_entries AS c ON c.event_id = e.event_id
                ORDER BY c.event_sequence
                """
            ).fetchall()
        ] == events_before
        assert dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        ) == chain_before
        assert [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM capability_grants ORDER BY grant_id"
            ).fetchall()
        ] == grants_before
        assert [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM capability_revocations ORDER BY revocation_id"
            ).fetchall()
        ] == revocations_before
        assert dict(
            connection.execute("SELECT * FROM capability_policy_state").fetchone()
        ) == policy_before
    assert workspace.receipt_log.read_bytes() == jsonl_before
    legacy = database.get_capability_grant(workspace.database, grant_id)
    assert legacy is not None and legacy["scope_version"] is None


def test_literal_empty_schema4_layout_migrates_scope_columns_idempotently(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "schema4.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE packets (
                packet_id TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL,
                packet_path TEXT NOT NULL,
                manifest_hash TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            );
            CREATE TABLE transition_events (
                event_id TEXT PRIMARY KEY,
                command TEXT NOT NULL,
                asserted_actor TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                candidate_id TEXT,
                packet_id TEXT,
                prior_state TEXT,
                requested_state TEXT,
                resulting_state TEXT,
                outcome TEXT NOT NULL,
                reason TEXT NOT NULL,
                governed_hash TEXT,
                input_identifiers_json TEXT NOT NULL,
                file_hashes_json TEXT NOT NULL,
                occurred_at_utc TEXT NOT NULL,
                application_version TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                receipt_projected_at_utc TEXT,
                authentication_status TEXT,
                authenticated_principal_id TEXT,
                authentication_scheme TEXT,
                authentication_key_id TEXT,
                authentication_verifier_fingerprint TEXT,
                authentication_operation_id TEXT,
                authentication_envelope_hash TEXT,
                authentication_proof_hash TEXT,
                authenticated_at_utc TEXT,
                authorization_status TEXT,
                authorization_principal_id TEXT,
                authorization_required_capability TEXT,
                authorization_prior_state TEXT,
                authorization_requested_state TEXT,
                authorization_matching_grant_id TEXT,
                authorization_reason_code TEXT
            );
            CREATE TABLE approvals (
                approval_id TEXT PRIMARY KEY,
                packet_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                manifest_hash TEXT NOT NULL,
                prior_state TEXT NOT NULL,
                decided_at_utc TEXT NOT NULL,
                transition_event_id TEXT,
                authenticated_principal_id TEXT,
                authenticated_operation_id TEXT
            );
            CREATE TABLE capability_grants (
                grant_id TEXT PRIMARY KEY,
                subject_principal_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                expected_prior_state TEXT,
                requested_state TEXT,
                granted_by_principal_id TEXT NOT NULL,
                authenticated_operation_id TEXT NOT NULL,
                policy_event_id TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                application_version TEXT NOT NULL
            );
            CREATE INDEX idx_capability_grants_effective
            ON capability_grants(
                subject_principal_id, capability, expected_prior_state,
                requested_state, created_at_utc, grant_id
            );
            PRAGMA user_version = 4;
            """
        )

    database.migrate_database(database_path)
    database.migrate_database(database_path)

    with sqlite3.connect(database_path) as connection:
        assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == 6
        for table, expected in {
            "packets": {"scope_version", "brand_id", "channel_id", "destination_id"},
            "approvals": {"scope_version", "brand_id", "channel_id", "destination_id"},
            "capability_grants": {
                "scope_version",
                "brand_id",
                "channel_id",
                "destination_id",
            },
            "transition_events": {
                "authorization_scope_version",
                "authorization_brand_id",
                "authorization_channel_id",
                "authorization_destination_id",
            },
        }.items():
            columns = {
                str(row[1])
                for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            }
            assert expected <= columns
        index_sql = str(
            connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'index' "
                "AND name = 'idx_capability_grants_effective'"
            ).fetchone()[0]
        )
        assert all(
            name in index_sql
            for name in ("scope_version", "brand_id", "channel_id", "destination_id")
        )


def test_packet_scope_persistence_fault_removes_orphan_and_rolls_back(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, candidate_id = qualified_candidate
    with database.connect(paths.database) as connection:
        events_before = int(
            connection.execute("SELECT COUNT(*) FROM transition_events").fetchone()[0]
        )
        head_before = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )

    def fail_scope(*args: object, **kwargs: object) -> None:
        raise sqlite3.OperationalError("injected packet scope persistence failure")

    monkeypatch.setattr(database, "apply_candidate_transition", fail_scope)
    with pytest.raises(sqlite3.OperationalError, match="packet scope"):
        generate_packet(paths, candidate_id, content_inputs_path)
    assert list(paths.packets.iterdir()) == []
    assert database.get_candidate(paths.database, candidate_id)["state"] == "QUALIFIED"  # type: ignore[index]
    with database.connect(paths.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM transition_events").fetchone()[0] == events_before
        assert dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        ) == head_before


def test_scope_cli_generation_inspection_grants_and_preparation(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
    tmp_path: Path,
) -> None:
    paths, candidate_id = qualified_candidate
    runner = CliRunner()
    generated = runner.invoke(
        cli.app,
        [
            "generate",
            "--workspace",
            str(paths.root),
            "--candidate-id",
            candidate_id,
            "--content-inputs",
            str(content_inputs_path),
        ],
    )
    assert generated.exit_code == 0, generated.output
    generated_value = json.loads(generated.stdout)
    packet_id = str(generated_value["packet_id"])
    assert generated_value["scope"] == SCOPE_A.model_dump(mode="json")
    before_inspection = paths.database.read_bytes()
    inspected = runner.invoke(
        cli.app,
        [
            "packet-scope",
            "--workspace",
            str(paths.root),
            "--packet-id",
            packet_id,
        ],
    )
    assert inspected.exit_code == 0, inspected.output
    assert paths.database.read_bytes() == before_inspection
    assert json.loads(inspected.stdout)["destination_id"] == SCOPE_A.destination_id

    private_key = Path(str(authentication_material["private_key"]))
    principal_id = str(authentication_material["principal_id"])

    def prepare_sign_apply(
        operation: str, apply_command: str, suffix: str, *extra: str
    ) -> dict[str, object]:
        unsigned = tmp_path / f"{suffix}-unsigned.json"
        signed = tmp_path / f"{suffix}-signed.json"
        prepared = runner.invoke(
            cli.app,
            [
                "prepare-policy-operation",
                "--workspace",
                str(paths.root),
                "--operation",
                operation,
                "--principal-id",
                principal_id,
                "--reason",
                suffix,
                "--output",
                str(unsigned),
                *extra,
            ],
        )
        assert prepared.exit_code == 0, prepared.output
        signed_result = runner.invoke(
            cli.app,
            [
                "sign-operation",
                "--operation-file",
                str(unsigned),
                "--private-key",
                str(private_key),
                "--output",
                str(signed),
            ],
        )
        assert signed_result.exit_code == 0, signed_result.output
        applied = runner.invoke(
            cli.app,
            [
                apply_command,
                "--workspace",
                str(paths.root),
                "--actor",
                "cli-display",
                "--authenticated-operation",
                str(signed),
            ],
        )
        assert applied.exit_code == 0, applied.output
        return json.loads(applied.stdout)

    prepare_sign_apply(
        "bootstrap-capability-policy", "bootstrap-policy-admin", "bootstrap"
    )
    scope_args = (
        "--subject-principal-id",
        principal_id,
        "--brand-id",
        SCOPE_A.brand_id,
        "--channel-id",
        SCOPE_A.channel_id,
        "--destination-id",
        SCOPE_A.destination_id,
    )
    for capability in ("packet.approve", "packet.reject", "packet.release"):
        prepare_sign_apply(
            "grant-capability",
            "grant-capability",
            capability.replace(".", "-"),
            *scope_args,
            "--capability",
            capability,
        )
    unsigned_approve = tmp_path / "approve-unsigned.json"
    prepared_approve = runner.invoke(
        cli.app,
        [
            "prepare-operation",
            "--workspace",
            str(paths.root),
            "--operation",
            "approve",
            "--packet-id",
            packet_id,
            "--principal-id",
            principal_id,
            "--output",
            str(unsigned_approve),
        ],
    )
    assert prepared_approve.exit_code == 0, prepared_approve.output
    assert json.loads(unsigned_approve.read_text(encoding="utf-8"))[
        "destination_id"
    ] == SCOPE_A.destination_id
    signed_approve = tmp_path / "approve-signed.json"
    assert runner.invoke(
        cli.app,
        [
            "sign-operation",
            "--operation-file",
            str(unsigned_approve),
            "--private-key",
            str(private_key),
            "--output",
            str(signed_approve),
        ],
    ).exit_code == 0
    approved = runner.invoke(
        cli.app,
        [
            "approve",
            "--workspace",
            str(paths.root),
            "--packet-id",
            packet_id,
            "--actor",
            "cli-display",
            "--authenticated-operation",
            str(signed_approve),
        ],
    )
    assert approved.exit_code == 0, approved.output

    unsigned_release = tmp_path / "release-unsigned.json"
    signed_release = tmp_path / "release-signed.json"
    prepared_release = runner.invoke(
        cli.app,
        [
            "prepare-operation",
            "--workspace",
            str(paths.root),
            "--operation",
            "release",
            "--packet-id",
            packet_id,
            "--principal-id",
            principal_id,
            "--output",
            str(unsigned_release),
        ],
    )
    assert prepared_release.exit_code == 0, prepared_release.output
    assert runner.invoke(
        cli.app,
        [
            "sign-operation",
            "--operation-file",
            str(unsigned_release),
            "--private-key",
            str(private_key),
            "--output",
            str(signed_release),
        ],
    ).exit_code == 0
    released = runner.invoke(
        cli.app,
        [
            "release",
            "--workspace",
            str(paths.root),
            "--packet-id",
            packet_id,
            "--actor",
            "cli-display",
            "--authenticated-operation",
            str(signed_release),
        ],
    )
    assert released.exit_code == 0, released.output
    integrity = verify_integrity(paths.database, paths.receipt_log)
    assert (
        integrity.canonical_chain_valid
        and integrity.canonical_policy_valid
        and integrity.projection_valid
        and integrity.projection_complete
    )
