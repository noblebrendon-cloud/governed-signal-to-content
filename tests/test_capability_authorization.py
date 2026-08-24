from __future__ import annotations

import base64
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from typer.testing import CliRunner

from governed_signal_to_content import database
from governed_signal_to_content import cli
from governed_signal_to_content import transition_mediator
from governed_signal_to_content.authentication import (
    APPROVAL_REASON,
    RELEASE_REASON,
    AuthenticationError,
    AuthenticatedCapabilityPolicyRequest,
    ReplayDetected,
    OperationBindingError,
    authenticate_authority_request,
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
from governed_signal_to_content.hashing import sha256_bytes
from governed_signal_to_content.receipts import (
    new_receipt,
    project_transition_event,
    transition_event_from_receipt,
)
from governed_signal_to_content.models import (
    AuthorizationReason,
    AuthorityOperation,
    Capability,
    CapabilityPolicyOperation,
    SignedOperation,
    WorkflowState,
)
from governed_signal_to_content.packets import generate_packet
from governed_signal_to_content.transition_mediator import (
    mediate_signed_policy_operation,
    mediate_signed_transition,
)


TEST_SCOPE = {
    "brand_id": "brand-test",
    "channel_id": "channel-test",
    "destination_id": "destination-test",
}


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
    subject_principal_id: str | None = None,
    capability: Capability | None = None,
    grant_id: str | None = None,
    brand_id: str | None = None,
    channel_id: str | None = None,
    destination_id: str | None = None,
) -> SignedOperation:
    if (
        operation is CapabilityPolicyOperation.GRANT
        and capability is not None
        and capability is not Capability.POLICY_MANAGE_CAPABILITIES
    ):
        brand_id = brand_id or TEST_SCOPE["brand_id"]
        channel_id = channel_id or TEST_SCOPE["channel_id"]
        destination_id = destination_id or TEST_SCOPE["destination_id"]
    envelope = prepare_policy_operation(
        paths=paths,
        operation=operation,
        principal_id=str(authentication_material["principal_id"]),
        subject_principal_id=subject_principal_id,
        capability=capability,
        grant_id=grant_id,
        brand_id=brand_id,
        channel_id=channel_id,
        destination_id=destination_id,
        reason=f"test {operation.value}",
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
    result = mediate_signed_policy_operation(
        paths=paths,
        signed_operation=signed,
        asserted_actor="display-only",
        expected_operation=CapabilityPolicyOperation.BOOTSTRAP,
    )
    return result.grant_id


def _grant(
    paths: WorkspacePaths,
    authentication_material: dict[str, object],
    capability: Capability,
) -> str:
    signed = _signed_policy(
        paths,
        authentication_material,
        CapabilityPolicyOperation.GRANT,
        subject_principal_id=str(authentication_material["principal_id"]),
        capability=capability,
    )
    result = mediate_signed_policy_operation(
        paths=paths,
        signed_operation=signed,
        asserted_actor="display-only",
        expected_operation=CapabilityPolicyOperation.GRANT,
    )
    return result.grant_id


def _signed_packet(
    paths: WorkspacePaths,
    authentication_material: dict[str, object],
    packet_id: str,
    operation: AuthorityOperation,
    reason: str,
) -> SignedOperation:
    return sign_operation(
        prepare_operation(
            paths=paths,
            operation=operation,
            packet_id=packet_id,
            principal_id=str(authentication_material["principal_id"]),
            reason=reason,
        ),
        Path(str(authentication_material["private_key"])),
    )


def _seed_disposable_principal(
    paths: WorkspacePaths, tmp_path: Path, principal_id: str
) -> dict[str, object]:
    private_key = tmp_path / f"{principal_id}-private.pem"
    public_key = tmp_path / f"{principal_id}-public.pem"
    generate_signing_key(private_key, public_key)
    loaded = serialization.load_pem_public_key(public_key.read_bytes())
    assert isinstance(loaded, Ed25519PublicKey)
    raw = loaded.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = sha256_bytes(raw)
    with database.connect(paths.database) as connection:
        connection.execute(
            """
            INSERT INTO trusted_principals (
                principal_id, authentication_scheme, key_id, public_key_b64,
                verifier_fingerprint, bootstrapped_at_utc
            ) VALUES (?, 'ed25519', ?, ?, ?, '2026-01-01T00:00:00Z')
            """,
            (
                principal_id,
                f"ed25519:{fingerprint}",
                base64.b64encode(raw).decode("ascii"),
                fingerprint,
            ),
        )
    return {
        "principal_id": principal_id,
        "private_key": private_key,
        "public_key": public_key,
    }


def test_authenticated_packet_without_policy_is_denied_consumed_and_chained(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
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
    assert caught.value.decision.reason is AuthorizationReason.POLICY_NOT_BOOTSTRAPPED
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    consumed = database.find_consumed_authenticated_operation(
        paths.database, signed.envelope.operation_id, "unused"
    )
    assert consumed is not None and consumed["adjudication_outcome"] == "rejected"
    event = database.get_transition_event(
        paths.database, caught.value.transition_result.canonical_event_id
    )
    assert event is not None
    assert event["authorization_status"] == "denied"
    assert event["authorization_required_capability"] == "packet.approve"
    assert event["authorization_reason_code"] == "POLICY_NOT_BOOTSTRAPPED"
    assert verify_integrity(paths.database, paths.receipt_log).canonical_chain_valid
    with pytest.raises(ReplayDetected):
        mediate_signed_transition(
            paths=paths, signed_operation=signed, asserted_actor="display-only"
        )


def test_bootstrap_grants_only_policy_admin_and_operational_grant_authorizes(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    bootstrap_grant = _bootstrap(paths, authentication_material)
    grants = database.list_capability_grants(paths.database)
    assert [grant["capability"] for grant in grants] == [
        "policy.manage_capabilities"
    ]
    assert grants[0]["grant_id"] == bootstrap_grant

    denied = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    with pytest.raises(AuthorizationRejected) as caught:
        mediate_signed_transition(
            paths=paths, signed_operation=denied, asserted_actor="display-only"
        )
    assert caught.value.decision.reason is AuthorizationReason.CAPABILITY_MISMATCH

    approve_grant = _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    accepted = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    result = mediate_signed_transition(
        paths=paths, signed_operation=accepted, asserted_actor="display-only"
    )
    event = database.get_transition_event(paths.database, result.canonical_event_id)
    assert event is not None
    assert event["authorization_status"] == "allowed"
    assert event["authorization_matching_grant_id"] == approve_grant
    assert event["authorization_reason_code"] == "ACTIVE_GRANT"
    integrity = verify_integrity(paths.database, paths.receipt_log)
    assert integrity.canonical_chain_valid and integrity.canonical_policy_valid


def test_earliest_active_grant_is_selected_deterministically(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    first = _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    second = _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    assert first != second
    signed = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    result = mediate_signed_transition(
        paths=paths, signed_operation=signed, asserted_actor="display-only"
    )
    event = database.get_transition_event(paths.database, result.canonical_event_id)
    assert event is not None
    assert event["authorization_matching_grant_id"] == first


def test_reject_and_release_are_independently_default_deny(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    reject = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.REJECT,
        "Signed rejection without a grant.",
    )
    with pytest.raises(AuthorizationRejected) as rejected:
        mediate_signed_transition(
            paths=paths, signed_operation=reject, asserted_actor="display-only"
        )
    assert rejected.value.decision.required_capability == "packet.reject"
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]

    approve = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    mediate_signed_transition(
        paths=paths, signed_operation=approve, asserted_actor="display-only"
    )
    release = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.RELEASE,
        RELEASE_REASON,
    )
    with pytest.raises(AuthorizationRejected) as released:
        mediate_signed_transition(
            paths=paths, signed_operation=release, asserted_actor="display-only"
        )
    assert released.value.decision.required_capability == "packet.release"
    assert database.get_packet(paths.database, packet_id)["state"] == "APPROVED"  # type: ignore[index]


def test_policy_request_is_an_explicit_authenticated_union_variant(
    workspace: WorkspacePaths, authentication_material: dict[str, object]
) -> None:
    signed = _signed_policy(
        workspace, authentication_material, CapabilityPolicyOperation.BOOTSTRAP
    )
    authenticated = authenticate_authority_request(workspace.database, signed)
    assert isinstance(authenticated, AuthenticatedCapabilityPolicyRequest)
    assert authenticated.request.model_dump(mode="json") == signed.envelope.model_dump(
        mode="json"
    )


def test_request_kind_substitution_is_rejected_consumed_and_cannot_replay(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    policy = _signed_policy(
        paths, authentication_material, CapabilityPolicyOperation.BOOTSTRAP
    )
    with pytest.raises(OperationBindingError):
        mediate_signed_transition(
            paths=paths, signed_operation=policy, asserted_actor="wrong-adapter"
        )
    assert database.find_consumed_authenticated_operation(
        paths.database, policy.envelope.operation_id, "unused"
    ) is not None
    with pytest.raises(ReplayDetected):
        mediate_signed_policy_operation(
            paths=paths, signed_operation=policy, asserted_actor="correct-adapter"
        )

    packet = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    with pytest.raises(OperationBindingError):
        mediate_signed_policy_operation(
            paths=paths, signed_operation=packet, asserted_actor="wrong-adapter"
        )
    assert database.find_consumed_authenticated_operation(
        paths.database, packet.envelope.operation_id, "unused"
    ) is not None


@pytest.mark.parametrize(
    "changes",
    [
        {"subject_principal_id": "principal_substituted"},
        {"capability": Capability.PACKET_APPROVE},
        {"expected_prior_state": WorkflowState.AWAITING_APPROVAL},
        {"grant_id": f"grant_{'f' * 32}"},
        {"operation": CapabilityPolicyOperation.GRANT},
    ],
)
def test_policy_envelope_substitution_invalidates_signature(
    changes: dict[str, object],
    workspace: WorkspacePaths,
    authentication_material: dict[str, object],
) -> None:
    signed = _signed_policy(
        workspace, authentication_material, CapabilityPolicyOperation.BOOTSTRAP
    )
    tampered = signed.model_copy(
        update={"envelope": signed.envelope.model_copy(update=changes)}
    )
    with pytest.raises(AuthenticationError):
        mediate_signed_policy_operation(
            paths=workspace,
            signed_operation=tampered,
            asserted_actor="display-only",
        )
    assert database.get_capability_policy_state(workspace.database) is None


def test_grants_are_bound_to_exact_principal_and_non_admin_cannot_manage_policy(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
    tmp_path: Path,
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    second = _seed_disposable_principal(paths, tmp_path, "principal_second")
    wrong_principal_proof = _signed_packet(
        paths, second, packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON
    )
    with pytest.raises(AuthorizationRejected) as denied:
        mediate_signed_transition(
            paths=paths,
            signed_operation=wrong_principal_proof,
            asserted_actor="second-display",
        )
    assert denied.value.decision.reason is AuthorizationReason.NO_ACTIVE_GRANT

    grant_to_second = _signed_policy(
        paths,
        authentication_material,
        CapabilityPolicyOperation.GRANT,
        subject_principal_id=str(second["principal_id"]),
        capability=Capability.PACKET_APPROVE,
    )
    mediate_signed_policy_operation(
        paths=paths,
        signed_operation=grant_to_second,
        asserted_actor="admin-display",
    )
    fresh = _signed_packet(
        paths, second, packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON
    )
    mediate_signed_transition(
        paths=paths, signed_operation=fresh, asserted_actor="second-display"
    )

    attempted_policy_grant = _signed_policy(
        paths,
        second,
        CapabilityPolicyOperation.GRANT,
        subject_principal_id=str(second["principal_id"]),
        capability=Capability.PACKET_REJECT,
    )
    with pytest.raises(AuthorizationRejected) as non_admin:
        mediate_signed_policy_operation(
            paths=paths,
            signed_operation=attempted_policy_grant,
            asserted_actor="second-display",
        )
    assert non_admin.value.decision.reason is AuthorizationReason.CAPABILITY_MISMATCH


def test_revocation_removes_operational_authority_and_old_denial_stays_consumed(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    grant_id = _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    revoke = _signed_policy(
        paths,
        authentication_material,
        CapabilityPolicyOperation.REVOKE,
        grant_id=grant_id,
    )
    mediate_signed_policy_operation(
        paths=paths,
        signed_operation=revoke,
        asserted_actor="display-only",
        expected_operation=CapabilityPolicyOperation.REVOKE,
    )
    denied = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    with pytest.raises(AuthorizationRejected) as caught:
        mediate_signed_transition(
            paths=paths, signed_operation=denied, asserted_actor="display-only"
        )
    assert caught.value.decision.reason is AuthorizationReason.GRANT_REVOKED

    replacement = _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    assert replacement != grant_id
    with pytest.raises(ReplayDetected):
        mediate_signed_transition(
            paths=paths, signed_operation=denied, asserted_actor="display-only"
        )
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


def test_denied_release_proof_does_not_revive_after_later_grant(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    approve = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    mediate_signed_transition(
        paths=paths, signed_operation=approve, asserted_actor="display-only"
    )

    denied_release = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.RELEASE,
        RELEASE_REASON,
    )
    with pytest.raises(AuthorizationRejected):
        mediate_signed_transition(
            paths=paths,
            signed_operation=denied_release,
            asserted_actor="display-only",
        )
    _grant(paths, authentication_material, Capability.PACKET_RELEASE)
    with pytest.raises(ReplayDetected):
        mediate_signed_transition(
            paths=paths,
            signed_operation=denied_release,
            asserted_actor="display-only",
        )
    fresh_release = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.RELEASE,
        RELEASE_REASON,
    )
    mediate_signed_transition(
        paths=paths,
        signed_operation=fresh_release,
        asserted_actor="display-only",
    )
    assert database.get_packet(paths.database, packet_id)["state"] == "RELEASED"  # type: ignore[index]


def test_final_policy_admin_revocation_fails_closed(
    workspace: WorkspacePaths, authentication_material: dict[str, object]
) -> None:
    bootstrap_grant = _bootstrap(workspace, authentication_material)
    revoke = _signed_policy(
        workspace,
        authentication_material,
        CapabilityPolicyOperation.REVOKE,
        grant_id=bootstrap_grant,
    )
    with pytest.raises(AuthorizationRejected) as caught:
        mediate_signed_policy_operation(
            paths=workspace,
            signed_operation=revoke,
            asserted_actor="display-only",
            expected_operation=CapabilityPolicyOperation.REVOKE,
        )
    assert caught.value.decision.reason is AuthorizationReason.LAST_POLICY_ADMIN
    assert database.get_capability_grant(workspace.database, bootstrap_grant)["revocation_id"] is None  # type: ignore[index]


def test_second_bootstrap_is_permanently_denied_consumed_and_replay_safe(
    workspace: WorkspacePaths, authentication_material: dict[str, object]
) -> None:
    _bootstrap(workspace, authentication_material)
    second = _signed_policy(
        workspace, authentication_material, CapabilityPolicyOperation.BOOTSTRAP
    )
    with pytest.raises(AuthorizationRejected) as caught:
        mediate_signed_policy_operation(
            paths=workspace,
            signed_operation=second,
            asserted_actor="display-only",
        )
    assert caught.value.decision.reason is AuthorizationReason.POLICY_ALREADY_BOOTSTRAPPED
    assert database.find_consumed_authenticated_operation(
        workspace.database, second.envelope.operation_id, "unused"
    ) is not None
    with pytest.raises(ReplayDetected):
        mediate_signed_policy_operation(
            paths=workspace,
            signed_operation=second,
            asserted_actor="display-only",
        )


def test_unknown_capability_fails_closed_in_evaluator(
    workspace: WorkspacePaths, authentication_material: dict[str, object]
) -> None:
    _bootstrap(workspace, authentication_material)
    with database.connect(workspace.database, immediate=True) as connection:
        decision = CapabilityPolicyEvaluator.evaluate(
            connection,
            principal_id=str(authentication_material["principal_id"]),
            required_capability="packet.unknown",
            actual_prior_state=WorkflowState.AWAITING_APPROVAL,
            requested_state=WorkflowState.APPROVED,
            brand_id=TEST_SCOPE["brand_id"],
            channel_id=TEST_SCOPE["channel_id"],
            destination_id=TEST_SCOPE["destination_id"],
        )
    assert not decision.allowed
    assert decision.reason is AuthorizationReason.UNKNOWN_CAPABILITY


def test_policy_fault_rolls_back_event_proof_grant_and_chain(
    workspace: WorkspacePaths,
    authentication_material: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed = _signed_policy(
        workspace, authentication_material, CapabilityPolicyOperation.BOOTSTRAP
    )
    with database.connect(workspace.database) as connection:
        head_before = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )

    def fail_grant(*args: object, **kwargs: object) -> None:
        raise sqlite3.OperationalError("injected capability grant failure")

    monkeypatch.setattr(database, "_insert_capability_grant", fail_grant)
    with pytest.raises(sqlite3.OperationalError, match="capability grant"):
        mediate_signed_policy_operation(
            paths=workspace,
            signed_operation=signed,
            asserted_actor="display-only",
        )
    with database.connect(workspace.database) as connection:
        head_after = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
        assert connection.execute("SELECT COUNT(*) FROM capability_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM authenticated_operations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM transition_events").fetchone()[0] == 0
    assert head_after == head_before


def test_revocation_fault_rolls_back_event_proof_revocation_and_chain(
    workspace: WorkspacePaths,
    authentication_material: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bootstrap(workspace, authentication_material)
    grant_id = _grant(workspace, authentication_material, Capability.PACKET_APPROVE)
    signed = _signed_policy(
        workspace,
        authentication_material,
        CapabilityPolicyOperation.REVOKE,
        grant_id=grant_id,
    )
    with database.connect(workspace.database) as connection:
        head_before = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
        events_before = int(
            connection.execute("SELECT COUNT(*) FROM transition_events").fetchone()[0]
        )
        proofs_before = int(
            connection.execute("SELECT COUNT(*) FROM authenticated_operations").fetchone()[0]
        )

    def fail_revocation(*args: object, **kwargs: object) -> None:
        raise sqlite3.OperationalError("injected capability revocation failure")

    monkeypatch.setattr(database, "_insert_capability_revocation", fail_revocation)
    with pytest.raises(sqlite3.OperationalError, match="capability revocation"):
        mediate_signed_policy_operation(
            paths=workspace,
            signed_operation=signed,
            asserted_actor="display-only",
        )
    with database.connect(workspace.database) as connection:
        head_after = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
        assert connection.execute("SELECT COUNT(*) FROM capability_revocations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM transition_events").fetchone()[0] == events_before
        assert connection.execute("SELECT COUNT(*) FROM authenticated_operations").fetchone()[0] == proofs_before
    assert head_after == head_before


def test_authorization_evidence_mismatch_rolls_back_policy_operation(
    workspace: WorkspacePaths,
    authentication_material: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed = _signed_policy(
        workspace, authentication_material, CapabilityPolicyOperation.BOOTSTRAP
    )
    original = transition_mediator.transition_event_from_receipt

    def mismatch(*args: object, **kwargs: object) -> dict[str, object]:
        event = original(*args, **kwargs)  # type: ignore[arg-type]
        event["authorization_reason_code"] = "MISMATCH"
        return event

    monkeypatch.setattr(transition_mediator, "transition_event_from_receipt", mismatch)
    with pytest.raises(ValueError, match="authorization evidence mismatch"):
        mediate_signed_policy_operation(
            paths=workspace,
            signed_operation=signed,
            asserted_actor="display-only",
        )
    with database.connect(workspace.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM capability_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM authenticated_operations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM transition_events").fetchone()[0] == 0


def test_schema3_to_4_preserves_native_chain_and_receipt_bytes(tmp_path: Path) -> None:
    from governed_signal_to_content.config import workspace_paths

    paths = workspace_paths(tmp_path / "schema3-workspace")
    database.initialize_workspace(paths)
    receipt = new_receipt(
        command="schema3-native",
        actor="legacy-actor",
        input_identifiers={"candidate_id": "cand_schema3"},
        prior_state="DISCOVERED",
        requested_transition="EVIDENCE_PRESERVED",
        resulting_state="EVIDENCE_PRESERVED",
        outcome="accepted",
        reason="Pre-Slice-5 native event.",
    )
    event = transition_event_from_receipt(
        receipt, target_type="candidate", target_id="cand_schema3"
    )
    database.record_transition_event(paths.database, event)
    project_transition_event(paths.database, paths.receipt_log, receipt.run_id)
    before_event = database.get_transition_event(paths.database, receipt.run_id)
    assert before_event is not None
    with database.connect(paths.database) as connection:
        before_state = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
        connection.execute("DROP TABLE capability_policy_state")
        connection.execute("DROP TABLE capability_revocations")
        connection.execute("DROP TABLE capability_grants")
        connection.execute("PRAGMA user_version = 3")
    before_jsonl = paths.receipt_log.read_bytes()
    schema3_bytes = paths.database.read_bytes()
    schema3_result = verify_integrity(paths.database, paths.receipt_log)
    assert schema3_result.canonical_chain_valid
    assert not schema3_result.canonical_policy_valid
    assert paths.database.read_bytes() == schema3_bytes

    database.migrate_database(paths.database)
    database.migrate_database(paths.database)
    after_event = database.get_transition_event(paths.database, receipt.run_id)
    with database.connect(paths.database) as connection:
        after_state = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        assert connection.execute("SELECT COUNT(*) FROM capability_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM capability_policy_state").fetchone()[0] == 0
    assert after_event is not None
    for field in (
        "receipt_json",
        "event_hash",
        "previous_event_hash",
        "event_sequence",
    ):
        assert after_event[field] == before_event[field]
    assert after_state == before_state
    assert paths.receipt_log.read_bytes() == before_jsonl
    assert version == database.DATABASE_SCHEMA_VERSION
    assert after_event["authorization_status"] is None


def test_empty_schema3_to_4_migration_is_idempotent(tmp_path: Path) -> None:
    from governed_signal_to_content.config import workspace_paths

    paths = workspace_paths(tmp_path / "empty-schema3-workspace")
    database.initialize_workspace(paths)
    with database.connect(paths.database) as connection:
        chain_state_before = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
        connection.execute("DROP TABLE capability_policy_state")
        connection.execute("DROP TABLE capability_revocations")
        connection.execute("DROP TABLE capability_grants")
        connection.execute("PRAGMA user_version = 3")
    receipt_bytes_before = paths.receipt_log.read_bytes()

    database.migrate_database(paths.database)
    database.migrate_database(paths.database)

    with database.connect(paths.database) as connection:
        assert (
            int(connection.execute("PRAGMA user_version").fetchone()[0])
            == database.DATABASE_SCHEMA_VERSION
        )
        assert dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        ) == chain_state_before
        assert connection.execute("SELECT COUNT(*) FROM capability_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM capability_policy_state").fetchone()[0] == 0
    assert paths.receipt_log.read_bytes() == receipt_bytes_before
    result = verify_integrity(paths.database, paths.receipt_log)
    assert result.canonical_chain_valid and result.canonical_policy_valid


def test_competing_revocations_serialize_without_policy_or_chain_fork(
    workspace: WorkspacePaths, authentication_material: dict[str, object]
) -> None:
    _bootstrap(workspace, authentication_material)
    grant_id = _grant(workspace, authentication_material, Capability.PACKET_APPROVE)
    revocations = [
        _signed_policy(
            workspace,
            authentication_material,
            CapabilityPolicyOperation.REVOKE,
            grant_id=grant_id,
        )
        for _ in range(2)
    ]

    def submit(signed: SignedOperation) -> str:
        try:
            return mediate_signed_policy_operation(
                paths=workspace,
                signed_operation=signed,
                asserted_actor="concurrent",
                expected_operation=CapabilityPolicyOperation.REVOKE,
            ).outcome
        except AuthorizationRejected as error:
            return error.decision.reason.value

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(submit, revocations))
    assert sorted(results) == ["GRANT_ALREADY_REVOKED", "accepted"]
    integrity = verify_integrity(workspace.database, workspace.receipt_log)
    assert integrity.canonical_chain_valid and integrity.canonical_policy_valid
    with database.connect(workspace.database) as connection:
        rows = connection.execute(
            "SELECT event_sequence, previous_event_hash, event_hash "
            "FROM transition_event_chain_entries ORDER BY event_sequence"
        ).fetchall()
    assert [row["event_sequence"] for row in rows] == list(range(1, len(rows) + 1))
    assert all(
        rows[index]["previous_event_hash"] == rows[index - 1]["event_hash"]
        for index in range(1, len(rows))
    )


def test_stale_advisory_allow_cannot_commit_after_revocation(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    _bootstrap(paths, authentication_material)
    grant_id = _grant(paths, authentication_material, Capability.PACKET_APPROVE)
    signed = _signed_packet(
        paths,
        authentication_material,
        packet_id,
        AuthorityOperation.APPROVE,
        APPROVAL_REASON,
    )
    with database.connect(paths.database) as connection:
        stale = CapabilityPolicyEvaluator.evaluate(
            connection,
            principal_id=str(authentication_material["principal_id"]),
            required_capability=Capability.PACKET_APPROVE,
            actual_prior_state=WorkflowState.AWAITING_APPROVAL,
            requested_state=WorkflowState.APPROVED,
            brand_id=TEST_SCOPE["brand_id"],
            channel_id=TEST_SCOPE["channel_id"],
            destination_id=TEST_SCOPE["destination_id"],
        )
    assert stale.allowed and stale.matching_grant_id == grant_id
    revoke = _signed_policy(
        paths,
        authentication_material,
        CapabilityPolicyOperation.REVOKE,
        grant_id=grant_id,
    )
    mediate_signed_policy_operation(
        paths=paths,
        signed_operation=revoke,
        asserted_actor="display-only",
    )
    with pytest.raises(AuthorizationRejected) as caught:
        mediate_signed_transition(
            paths=paths, signed_operation=signed, asserted_actor="display-only"
        )
    assert caught.value.decision.reason is AuthorizationReason.GRANT_REVOKED
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]


def test_authorization_and_policy_tampering_are_reported_separately(
    workspace: WorkspacePaths, authentication_material: dict[str, object]
) -> None:
    _bootstrap(workspace, authentication_material)
    grant_id = _grant(workspace, authentication_material, Capability.PACKET_APPROVE)
    grant = database.get_capability_grant(workspace.database, grant_id)
    assert grant is not None
    with database.connect(workspace.database) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            """
            UPDATE capability_grants
            SET capability = 'packet.reject'
            WHERE grant_id = ?
            """,
            (grant_id,),
        )
    policy_corrupt = verify_integrity(workspace.database, workspace.receipt_log)
    assert policy_corrupt.canonical_chain_valid
    assert not policy_corrupt.canonical_policy_valid
    assert any(
        failure.code == "invalid_capability_scope"
        for failure in policy_corrupt.failures
    )

    with database.connect(workspace.database) as connection:
        connection.execute(
            "UPDATE transition_events SET authorization_reason_code = 'TAMPERED' "
            "WHERE event_id = ?",
            (grant["policy_event_id"],),
        )
    event_corrupt = verify_integrity(workspace.database, workspace.receipt_log)
    assert not event_corrupt.canonical_chain_valid


def test_policy_integrity_checks_exact_authenticated_operation_linkage(
    workspace: WorkspacePaths, authentication_material: dict[str, object]
) -> None:
    _bootstrap(workspace, authentication_material)
    grant_id = _grant(workspace, authentication_material, Capability.PACKET_APPROVE)
    grant = database.get_capability_grant(workspace.database, grant_id)
    assert grant is not None
    with database.connect(workspace.database) as connection:
        connection.execute(
            "UPDATE authenticated_operations SET envelope_json = '{}' "
            "WHERE operation_id = ?",
            (grant["authenticated_operation_id"],),
        )
    result = verify_integrity(workspace.database, workspace.receipt_log)
    assert result.canonical_chain_valid
    assert not result.canonical_policy_valid
    assert any(
        failure.code == "authenticated_operation_mismatch"
        for failure in result.failures
    )


def test_capability_policy_cli_bootstrap_grant_list_and_verify(
    workspace: WorkspacePaths,
    authentication_material: dict[str, object],
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    private_key = Path(str(authentication_material["private_key"]))
    principal_id = str(authentication_material["principal_id"])

    def prepare_sign_apply(operation: str, apply_command: str, *extra: str) -> dict[str, object]:
        unsigned = tmp_path / f"{operation}-unsigned.json"
        signed = tmp_path / f"{operation}-signed.json"
        prepared = runner.invoke(
            cli.app,
            [
                "prepare-policy-operation",
                "--workspace",
                str(workspace.root),
                "--operation",
                operation,
                "--principal-id",
                principal_id,
                "--reason",
                f"CLI {operation}",
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
                str(workspace.root),
                "--actor",
                "cli-display",
                "--authenticated-operation",
                str(signed),
            ],
        )
        assert applied.exit_code == 0, applied.output
        return json.loads(applied.stdout)

    prepare_sign_apply("bootstrap-capability-policy", "bootstrap-policy-admin")
    granted = prepare_sign_apply(
        "grant-capability",
        "grant-capability",
        "--subject-principal-id",
        principal_id,
        "--capability",
        "packet.approve",
        "--brand-id",
        TEST_SCOPE["brand_id"],
        "--channel-id",
        TEST_SCOPE["channel_id"],
        "--destination-id",
        TEST_SCOPE["destination_id"],
    )
    revoked = prepare_sign_apply(
        "revoke-capability",
        "revoke-capability",
        "--grant-id",
        str(granted["grant_id"]),
    )
    assert revoked["revocation_id"] is not None
    database_bytes_before_list = workspace.database.read_bytes()
    listing = runner.invoke(
        cli.app,
        ["list-capability-grants", "--workspace", str(workspace.root)],
    )
    assert listing.exit_code == 0
    assert workspace.database.read_bytes() == database_bytes_before_list
    listed = {
        grant["grant_id"]: grant for grant in json.loads(listing.stdout)["grants"]
    }
    assert listed[granted["grant_id"]]["active"] == 0
    verified = runner.invoke(
        cli.app, ["verify-integrity", "--workspace", str(workspace.root)]
    )
    assert verified.exit_code == 0, verified.output
