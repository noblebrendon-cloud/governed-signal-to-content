from __future__ import annotations

import base64
import json
import sqlite3
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Callable

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from typer.testing import CliRunner

from governed_signal_to_content import cli, database
from governed_signal_to_content.approvals import decide_packet, release_packet
from governed_signal_to_content.authentication import (
    APPROVAL_REASON,
    RELEASE_REASON,
    AuthenticationError,
    AuthenticationRequired,
    AuthenticatedTransitionRequest,
    OperationBindingError,
    ReplayDetected,
    authenticate_transition_request,
    canonical_envelope_json,
    load_signed_operation,
    write_json_exclusive,
)
from governed_signal_to_content.config import WorkspacePaths
from governed_signal_to_content.hashing import sha256_bytes
from governed_signal_to_content.models import (
    AuthorityOperation,
    SignedOperation,
    TransitionResult,
    WorkflowState,
)
from governed_signal_to_content.packets import PacketIntegrityError, generate_packet
from governed_signal_to_content.state_machine import (
    MediatedTransitionRequired,
    transition_packet,
)
from governed_signal_to_content.transition_mediator import (
    CanonicalTransitionService,
    mediate_signed_transition,
)


def _generate(
    qualified_candidate: tuple[WorkspacePaths, str], content_inputs_path: Path
) -> tuple[WorkspacePaths, str, str]:
    paths, candidate_id = qualified_candidate
    packet_id, _, _, _ = generate_packet(paths, candidate_id, content_inputs_path)
    return paths, candidate_id, packet_id


def _resign(
    signed: SignedOperation,
    private_key_path: Path,
    **changes: object,
) -> SignedOperation:
    envelope = signed.envelope.model_copy(update=changes)
    loaded = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=None
    )
    assert isinstance(loaded, Ed25519PrivateKey)
    signature = loaded.sign(canonical_envelope_json(envelope).encode("utf-8"))
    return SignedOperation(
        envelope=envelope,
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def test_verifier_constructs_exact_immutable_authenticated_transition_request(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    signed = signed_operation(
        packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON
    )
    authenticated = authenticate_transition_request(paths.database, signed)

    assert isinstance(authenticated, AuthenticatedTransitionRequest)
    assert authenticated.request.model_dump(mode="json") == signed.envelope.model_dump(
        mode="json"
    )
    assert authenticated.request.operation_id == signed.envelope.operation_id
    assert authenticated.request.target_id == packet_id
    assert authenticated.principal.operation_id == authenticated.request.operation_id
    assert authenticated.principal.envelope_hash == sha256_bytes(
        authenticated.envelope_json.encode("utf-8")
    )
    assert authenticated.principal.proof_hash == sha256_bytes(
        json.dumps(
            signed.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )

    with pytest.raises(ValidationError, match="frozen"):
        authenticated.request.target_id = "pkt_changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        authenticated.envelope_json = "changed"  # type: ignore[misc]


def test_malformed_transport_fake_flag_and_actor_text_never_create_trusted_request(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    tmp_path: Path,
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    malformed = tmp_path / "malformed-signed-operation.json"
    malformed.write_text('{"envelope":', encoding="utf-8")
    with pytest.raises(AuthenticationError, match="Malformed"):
        load_signed_operation(malformed)

    with pytest.raises(TypeError, match="authenticated"):
        mediate_signed_transition(  # type: ignore[call-arg]
            paths=paths,
            signed_operation=None,
            asserted_actor="Brendon",
            expected_operation=AuthorityOperation.APPROVE,
            expected_packet_id=packet_id,
            authenticated=True,
        )
    with pytest.raises(AuthenticationRequired):
        mediate_signed_transition(
            paths=paths,
            signed_operation=None,
            asserted_actor="Brendon",
            expected_operation=AuthorityOperation.APPROVE,
            expected_packet_id=packet_id,
            expected_reason=APPROVAL_REASON,
        )
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]


def test_mediated_approval_uses_authenticated_request_as_canonical_source(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    signed = signed_operation(
        packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON
    )
    result = mediate_signed_transition(
        paths=paths,
        signed_operation=signed,
        asserted_actor="display-only",
    )

    assert result.outcome == "accepted"
    assert result.request_id == signed.envelope.operation_id
    assert result.prior_state is signed.envelope.expected_prior_state
    assert result.resulting_state is signed.envelope.requested_state
    event = database.get_transition_event(paths.database, result.canonical_event_id)
    approval = database.get_approved_approval(paths.database, packet_id)
    consumed = database.find_consumed_authenticated_operation(
        paths.database, signed.envelope.operation_id, "unused"
    )
    assert event is not None and approval is not None and consumed is not None
    assert event["target_id"] == signed.envelope.target_id
    assert event["candidate_id"] == signed.envelope.candidate_id == candidate_id
    assert event["prior_state"] == signed.envelope.expected_prior_state.value
    assert event["requested_state"] == signed.envelope.requested_state.value
    assert event["reason"] == signed.envelope.reason
    assert event["governed_hash"] == signed.envelope.packet_manifest_hash
    assert approval["approval_id"] == signed.envelope.approval_id
    assert approval["decision"] == signed.envelope.approval_decision
    assert approval["reason"] == signed.envelope.reason
    assert consumed["envelope_json"] == canonical_envelope_json(signed.envelope)


def test_conflicting_compatibility_reason_is_rejected_consumed_and_explicit(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    signed = signed_operation(packet_id, AuthorityOperation.REJECT, "signed reason")
    with pytest.raises(OperationBindingError, match="reason") as caught:
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="display-only",
            approved=False,
            reason="conflicting caller reason",
            signed_operation=signed,
        )
    result = caught.value.transition_result
    assert isinstance(result, TransitionResult)
    assert result.outcome == "rejected"
    assert result.request_id == signed.envelope.operation_id
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.find_consumed_authenticated_operation(
        paths.database, signed.envelope.operation_id, "unused"
    ) is not None


@pytest.mark.parametrize(
    "changes",
    [
        {"candidate_id": "cand_authenticated_but_wrong"},
        {"expected_prior_state": WorkflowState.APPROVED},
        {"requested_state": WorkflowState.RELEASED},
        {"operation": AuthorityOperation.RELEASE},
        {"packet_manifest_hash": "0" * 64},
        {"approval_decision": WorkflowState.REJECTED.value},
    ],
)
def test_authenticated_semantic_or_object_drift_is_rejected_before_mutation(
    changes: dict[str, object],
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
    authentication_material: dict[str, object],
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    original = signed_operation(
        packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON
    )
    signed = _resign(
        original,
        Path(str(authentication_material["private_key"])),
        **changes,
    )
    authenticated = authenticate_transition_request(paths.database, signed)
    assert authenticated.request.model_dump(mode="json") == signed.envelope.model_dump(
        mode="json"
    )
    with pytest.raises((OperationBindingError, PacketIntegrityError)):
        mediate_signed_transition(
            paths=paths,
            signed_operation=signed,
            asserted_actor="display-only",
        )
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]


def test_valid_rejection_and_release_are_mediated(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    rejection = signed_operation(
        packet_id, AuthorityOperation.REJECT, "authenticated rejection"
    )
    rejected = mediate_signed_transition(
        paths=paths,
        signed_operation=rejection,
        asserted_actor="review display",
    )
    assert rejected.resulting_state is WorkflowState.REJECTED


def test_valid_release_uses_exact_authenticated_approval_binding(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    approval = signed_operation(
        packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON
    )
    mediate_signed_transition(
        paths=paths, signed_operation=approval, asserted_actor="review display"
    )
    release = signed_operation(packet_id, AuthorityOperation.RELEASE, RELEASE_REASON)
    result = mediate_signed_transition(
        paths=paths, signed_operation=release, asserted_actor="release display"
    )
    assert result.resulting_state is WorkflowState.RELEASED
    assert database.get_packet(paths.database, packet_id)["state"] == "RELEASED"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "RELEASED"  # type: ignore[index]


def test_supported_state_machine_and_database_paths_refuse_authority_bypass(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    with pytest.raises(MediatedTransitionRequired):
        transition_packet(
            database_path=paths.database,
            receipt_log=paths.receipt_log,
            packet_id=packet_id,
            requested=WorkflowState.APPROVED,
            command="direct-bypass",
            actor="Brendon",
            reason="must not mutate",
        )
    with pytest.raises(PermissionError, match="TransitionMediator"):
        database.apply_packet_transition(
            paths.database,
            packet_id=packet_id,
            candidate_id=candidate_id,
            prior_state=WorkflowState.AWAITING_APPROVAL.value,
            resulting_state=WorkflowState.APPROVED.value,
            event={},
        )
    with pytest.raises(ValueError, match="Unsupported"):
        database.update_candidate_fields(
            paths.database, candidate_id, state=WorkflowState.APPROVED.value
        )
    assert not hasattr(database, "update_packet_and_candidate_state")
    assert not hasattr(database, "insert_packet")
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]


def test_cli_authority_command_routes_through_mediator(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    signed = signed_operation(
        packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON
    )
    proof_path = tmp_path / "signed-approval.json"
    write_json_exclusive(proof_path, signed)
    calls: list[dict[str, object]] = []

    def spy(**kwargs: object) -> TransitionResult:
        calls.append(kwargs)
        return TransitionResult(
            request_id=signed.envelope.operation_id,
            outcome="accepted",
            prior_state=WorkflowState.AWAITING_APPROVAL,
            resulting_state=WorkflowState.APPROVED,
            canonical_event_id="event-spy",
        )

    monkeypatch.setattr(cli, "mediate_signed_transition", spy)
    result = CliRunner().invoke(
        cli.app,
        [
            "approve",
            "--workspace",
            str(paths.root),
            "--packet-id",
            packet_id,
            "--actor",
            "display-only",
            "--authenticated-operation",
            str(proof_path),
        ],
    )
    assert result.exit_code == 0
    assert '"run_id": "event-spy"' in result.stdout
    assert len(calls) == 1
    assert calls[0]["expected_operation"] is AuthorityOperation.APPROVE
    assert calls[0]["expected_packet_id"] == packet_id
    assert calls[0]["signed_operation"] == signed


def test_mediator_routes_admissible_request_to_canonical_service(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    signed = signed_operation(
        packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON
    )
    routed: list[AuthenticatedTransitionRequest] = []

    def spy(
        self: CanonicalTransitionService,
        mediated: object,
    ) -> TransitionResult:
        authenticated = mediated.authenticated  # type: ignore[attr-defined]
        routed.append(authenticated)
        return TransitionResult(
            request_id=authenticated.request.operation_id,
            outcome="accepted",
            prior_state=authenticated.request.expected_prior_state,
            resulting_state=authenticated.request.requested_state,
            canonical_event_id="event-routed",
        )

    monkeypatch.setattr(CanonicalTransitionService, "commit", spy)
    result = mediate_signed_transition(
        paths=paths, signed_operation=signed, asserted_actor="display-only"
    )
    assert result.canonical_event_id == "event-routed"
    assert len(routed) == 1
    assert routed[0].request.target_id == signed.envelope.target_id
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]


def test_artifact_invalid_authenticated_request_is_consumed_and_cannot_replay(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    signed = signed_operation(
        packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON
    )
    (paths.packets / packet_id / "01_linkedin_analysis.md").write_text(
        "mutated before mediation\n", encoding="utf-8", newline="\n"
    )
    with pytest.raises(PacketIntegrityError):
        mediate_signed_transition(
            paths=paths, signed_operation=signed, asserted_actor="display-only"
        )
    consumed = database.find_consumed_authenticated_operation(
        paths.database, signed.envelope.operation_id, "unused"
    )
    assert consumed is not None and consumed["adjudication_outcome"] == "rejected"
    with pytest.raises(ReplayDetected):
        mediate_signed_transition(
            paths=paths, signed_operation=signed, asserted_actor="display-only"
        )


def test_release_approval_mismatch_is_consumed_and_cannot_replay(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    decide_packet(
        paths=paths,
        packet_id=packet_id,
        actor="review display",
        approved=True,
        reason=APPROVAL_REASON,
        signed_operation=signed_operation(
            packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON
        ),
    )
    release = signed_operation(packet_id, AuthorityOperation.RELEASE, RELEASE_REASON)
    with database.connect(paths.database) as connection:
        connection.execute(
            "UPDATE approvals SET manifest_hash = ? WHERE packet_id = ?",
            ("0" * 64, packet_id),
        )
    with pytest.raises(PacketIntegrityError):
        release_packet(paths, packet_id, "release display", release)
    assert database.find_consumed_authenticated_operation(
        paths.database, release.envelope.operation_id, "unused"
    ) is not None
    with pytest.raises(ReplayDetected):
        release_packet(paths, packet_id, "release display", release)


def test_candidate_state_failure_rolls_back_packet_event_approval_and_consumption(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    signed = signed_operation(
        packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON
    )
    with database.connect(paths.database) as connection:
        connection.execute(
            """
            CREATE TRIGGER fail_mediated_candidate_state
            BEFORE UPDATE OF state ON candidates
            WHEN NEW.state = 'APPROVED'
            BEGIN
                SELECT RAISE(ABORT, 'simulated candidate-state failure');
            END
            """
        )
    with pytest.raises(sqlite3.IntegrityError, match="candidate-state"):
        mediate_signed_transition(
            paths=paths, signed_operation=signed, asserted_actor="display-only"
        )
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_approved_approval(paths.database, packet_id) is None
    assert database.find_consumed_authenticated_operation(
        paths.database, signed.envelope.operation_id, "unused"
    ) is None
    with database.connect(paths.database) as connection:
        accepted = int(
            connection.execute(
                "SELECT COUNT(*) FROM transition_events "
                "WHERE command = 'approve' AND outcome = 'accepted'"
            ).fetchone()[0]
        )
    assert accepted == 0
