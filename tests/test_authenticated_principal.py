from __future__ import annotations

import base64
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governed_signal_to_content import database
from governed_signal_to_content.approvals import decide_packet, release_packet
from governed_signal_to_content.authentication import (
    RELEASE_REASON,
    AuthenticationError,
    AuthenticationRequired,
    OperationBindingError,
    ReplayDetected,
    bootstrap_trusted_principal,
    canonical_envelope_json,
    generate_signing_key,
    prepare_operation,
    sign_operation,
)
from governed_signal_to_content.config import WorkspacePaths
from governed_signal_to_content.deduplication import (
    deduplicate_candidate,
    normalize_candidate,
)
from governed_signal_to_content.evidence import ingest_signal
from governed_signal_to_content.hashing import canonical_json
from governed_signal_to_content.models import (
    AuthorityOperation,
    SignedOperation,
    SignedOperationEnvelope,
    WorkflowState,
)
from governed_signal_to_content.packets import generate_packet
from governed_signal_to_content.qualification import qualify_candidate


APPROVE_REASON = "Authenticated exact approval."


def _signed_unchecked(
    envelope: SignedOperationEnvelope, private_key_path: Path
) -> SignedOperation:
    loaded = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=None
    )
    assert isinstance(loaded, Ed25519PrivateKey)
    signature = loaded.sign(canonical_envelope_json(envelope).encode("utf-8"))
    return SignedOperation(
        envelope=envelope,
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def _generate(
    qualified_candidate: tuple[WorkspacePaths, str], content_inputs_path: Path
) -> tuple[WorkspacePaths, str, str]:
    paths, candidate_id = qualified_candidate
    packet_id, _, _, _ = generate_packet(paths, candidate_id, content_inputs_path)
    return paths, candidate_id, packet_id


def _second_packet(
    paths: WorkspacePaths, tmp_path: Path, content_inputs_path: Path
) -> tuple[str, str]:
    candidate, _, _ = ingest_signal(
        paths=paths,
        title="Second authenticated target",
        source_url="https://example.com/second-authenticated-target",
        source_file=None,
    )
    normalize_candidate(paths, candidate.candidate_id)
    _, duplicate, _ = deduplicate_candidate(paths, candidate.candidate_id)
    assert not duplicate
    classification = tmp_path / "second-classification.json"
    classification.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "documented_facts": ["A second primary source exists."],
                "reasonable_inferences": [],
                "direct_similarities": [],
                "broader_industry_trends": [],
                "primary_sources": [
                    "https://example.com/second-authenticated-target"
                ],
                "structural_overlap_dimensions": ["identity"],
                "qualification_decision": True,
                "qualification_reason": "Second bounded target.",
            }
        ),
        encoding="utf-8",
        newline="\n",
    )
    qualify_candidate(paths, candidate.candidate_id, classification)
    packet_id, _, _, _ = generate_packet(
        paths, candidate.candidate_id, content_inputs_path
    )
    return candidate.candidate_id, packet_id


def _event_for_command(paths: WorkspacePaths, command: str) -> dict[str, object]:
    with database.connect(paths.database) as connection:
        row = connection.execute(
            """
            SELECT * FROM transition_events
            WHERE command = ? ORDER BY occurred_at_utc DESC, event_id DESC LIMIT 1
            """,
            (command,),
        ).fetchone()
    assert row is not None
    return dict(row)


def test_one_time_trusted_principal_bootstrap_and_private_key_custody(
    workspace: WorkspacePaths, tmp_path: Path
) -> None:
    first_private = tmp_path / "first-private.pem"
    first_public = tmp_path / "first-public.pem"
    second_private = tmp_path / "second-private.pem"
    second_public = tmp_path / "second-public.pem"
    generate_signing_key(first_private, first_public)
    principal = bootstrap_trusted_principal(
        workspace.database, "principal_bootstrap_owner", first_public
    )
    assert principal.authentication_scheme == "ed25519"
    stored = database.get_trusted_principal(
        workspace.database, "principal_bootstrap_owner"
    )
    assert stored is not None
    assert stored["key_id"] == principal.key_id

    generate_signing_key(second_private, second_public)
    with pytest.raises(PermissionError, match="bootstrap is closed"):
        bootstrap_trusted_principal(
            workspace.database, "principal_untrusted_second", second_public
        )

    database_bytes = workspace.database.read_bytes()
    private_bytes = first_private.read_bytes()
    assert private_bytes not in database_bytes
    assert b"PRIVATE KEY" not in database_bytes
    assert "PRIVATE KEY" not in workspace.receipt_log.read_text(encoding="utf-8")


def test_forged_asserted_actor_cannot_authenticate_approval(
    qualified_candidate: tuple[WorkspacePaths, str], content_inputs_path: Path
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    with pytest.raises(AuthenticationRequired):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="Brendon",
            approved=True,
            reason=APPROVE_REASON,
        )
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_approved_approval(paths.database, packet_id) is None
    event = _event_for_command(paths, "approve")
    assert event["asserted_actor"] == "Brendon"
    assert event["authentication_status"] == "failed"
    assert event["authenticated_principal_id"] is None
    assert event["authorization_status"] is None
    assert event["authorization_principal_id"] is None


def test_valid_authenticated_approval_and_release_bind_canonical_event(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    signed_approval = signed_operation(
        packet_id, AuthorityOperation.APPROVE, APPROVE_REASON
    )
    approval_event_id = decide_packet(
        paths=paths,
        packet_id=packet_id,
        actor="display-only-actor",
        approved=True,
        reason=APPROVE_REASON,
        signed_operation=signed_approval,
    )
    approval_event = database.get_transition_event(
        paths.database, approval_event_id
    )
    approval = database.get_approved_approval(paths.database, packet_id)
    assert approval_event is not None and approval is not None
    assert approval_event["asserted_actor"] == "display-only-actor"
    assert approval_event["authenticated_principal_id"] == "principal_test_reviewer"
    assert approval_event["authentication_scheme"] == "ed25519"
    assert approval_event["authentication_operation_id"] == signed_approval.envelope.operation_id
    assert approval["authenticated_principal_id"] == "principal_test_reviewer"
    assert approval["authenticated_operation_id"] == signed_approval.envelope.operation_id

    signed_release = signed_operation(
        packet_id, AuthorityOperation.RELEASE, RELEASE_REASON
    )
    release_event_id = release_packet(
        paths, packet_id, "another-display-actor", signed_release
    )
    release_event = database.get_transition_event(paths.database, release_event_id)
    assert release_event is not None
    assert release_event["authenticated_principal_id"] == "principal_test_reviewer"
    assert release_event["authentication_operation_id"] == signed_release.envelope.operation_id
    assert database.get_packet(paths.database, packet_id)["state"] == "RELEASED"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "RELEASED"  # type: ignore[index]


def test_wrong_private_key_and_unknown_principal_or_key_fail_closed(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
    tmp_path: Path,
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    envelope = prepare_operation(
        paths=paths,
        operation=AuthorityOperation.APPROVE,
        packet_id=packet_id,
        principal_id=str(authentication_material["principal_id"]),
        reason=APPROVE_REASON,
    )
    wrong_private = tmp_path / "wrong-private.pem"
    wrong_public = tmp_path / "wrong-public.pem"
    generate_signing_key(wrong_private, wrong_public)
    wrong_signature = _signed_unchecked(envelope, wrong_private)
    with pytest.raises(AuthenticationError, match="verification failed"):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="forged",
            approved=True,
            reason=APPROVE_REASON,
            signed_operation=wrong_signature,
        )

    private_key = Path(str(authentication_material["private_key"]))
    for changes, message in (
        ({"principal_id": "principal_unknown"}, "Unknown authenticated principal"),
        ({"key_id": "ed25519:" + "0" * 64}, "do not match"),
    ):
        changed = envelope.model_copy(
            update={**changes, "operation_id": f"op_{'1' if changes.get('principal_id') else '2'}" + "0" * 31}
        )
        signed = _signed_unchecked(changed, private_key)
        with pytest.raises(AuthenticationError, match=message):
            decide_packet(
                paths=paths,
                packet_id=packet_id,
                actor="forged",
                approved=True,
                reason=APPROVE_REASON,
                signed_operation=signed,
            )
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("principal_id", "principal_modified"),
        ("target_id", "pkt_modified"),
        ("candidate_id", "cand_modified"),
        ("expected_prior_state", WorkflowState.APPROVED),
        ("requested_state", WorkflowState.RELEASED),
        ("operation", AuthorityOperation.RELEASE),
        ("packet_manifest_hash", "0" * 64),
        ("approval_decision", WorkflowState.REJECTED.value),
        ("operation_id", f"op_{'f' * 32}"),
        ("approval_id", f"appr_{'f' * 32}"),
        ("approval_transition_event_id", "event_modified"),
        ("reason", "modified signed reason"),
    ],
)
def test_modifying_any_signed_operation_field_invalidates_authentication(
    field: str,
    value: object,
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    signed = signed_operation(packet_id, AuthorityOperation.APPROVE, APPROVE_REASON)
    tampered = signed.model_copy(
        update={"envelope": signed.envelope.model_copy(update={field: value})}
    )
    with pytest.raises(AuthenticationError):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted",
            approved=True,
            reason=APPROVE_REASON,
            signed_operation=tampered,
        )
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]


def test_exact_replay_is_rejected_and_does_not_mutate_state(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    signed = signed_operation(packet_id, AuthorityOperation.APPROVE, APPROVE_REASON)
    decide_packet(
        paths=paths,
        packet_id=packet_id,
        actor="asserted",
        approved=True,
        reason=APPROVE_REASON,
        signed_operation=signed,
    )
    with pytest.raises(ReplayDetected, match="already been consumed"):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted-again",
            approved=True,
            reason=APPROVE_REASON,
            signed_operation=signed,
        )
    assert database.get_packet(paths.database, packet_id)["state"] == "APPROVED"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "APPROVED"  # type: ignore[index]
    event = _event_for_command(paths, "approve")
    assert event["outcome"] == "rejected"
    assert event["authentication_status"] == "replay_rejected"
    assert event["authorization_status"] == "not_evaluated"
    assert event["authorization_reason_code"] == "REPLAY_REJECTED"


def test_canonical_envelope_serialization_is_order_and_format_independent(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    signed = signed_operation(packet_id, AuthorityOperation.APPROVE, APPROVE_REASON)
    value = signed.envelope.model_dump(mode="json")
    reversed_value = dict(reversed(list(value.items())))
    assert canonical_envelope_json(signed.envelope) == canonical_json(reversed_value)
    pretty = json.dumps(reversed_value, indent=4)
    assert canonical_json(json.loads(pretty)) == canonical_envelope_json(signed.envelope)


def test_packet_a_proof_cannot_authorize_packet_b(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
    tmp_path: Path,
) -> None:
    paths, _, packet_a = _generate(qualified_candidate, content_inputs_path)
    candidate_b, packet_b = _second_packet(paths, tmp_path, content_inputs_path)
    proof_a = signed_operation(packet_a, AuthorityOperation.APPROVE, APPROVE_REASON)
    with pytest.raises(OperationBindingError, match="binding mismatch"):
        decide_packet(
            paths=paths,
            packet_id=packet_b,
            actor="asserted",
            approved=True,
            reason=APPROVE_REASON,
            signed_operation=proof_a,
        )
    assert database.get_packet(paths.database, packet_b)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_b)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.find_consumed_authenticated_operation(
        paths.database, proof_a.envelope.operation_id, "unused"
    ) is not None


def test_approval_and_release_proofs_are_not_interchangeable(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    approval_proof = signed_operation(
        packet_id, AuthorityOperation.APPROVE, APPROVE_REASON
    )
    with pytest.raises(OperationBindingError):
        release_packet(paths, packet_id, "asserted", approval_proof)
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]

    fresh_approval = signed_operation(
        packet_id, AuthorityOperation.APPROVE, APPROVE_REASON
    )
    decide_packet(
        paths=paths,
        packet_id=packet_id,
        actor="asserted",
        approved=True,
        reason=APPROVE_REASON,
        signed_operation=fresh_approval,
    )
    release_proof = signed_operation(
        packet_id, AuthorityOperation.RELEASE, RELEASE_REASON
    )
    with pytest.raises(OperationBindingError):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted",
            approved=True,
            reason=RELEASE_REASON,
            signed_operation=release_proof,
        )
    assert database.get_packet(paths.database, packet_id)["state"] == "APPROVED"  # type: ignore[index]


def test_expired_and_malformed_proofs_fail_deterministically(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, _, packet_id = _generate(qualified_candidate, content_inputs_path)
    envelope = prepare_operation(
        paths=paths,
        operation=AuthorityOperation.APPROVE,
        packet_id=packet_id,
        principal_id=str(authentication_material["principal_id"]),
        reason=APPROVE_REASON,
    )
    now = datetime.now(timezone.utc)
    expired_envelope = envelope.model_copy(
        update={
            "operation_id": f"op_{'3' * 32}",
            "issued_at_utc": (now - timedelta(minutes=10)).isoformat(),
            "expires_at_utc": (now - timedelta(minutes=5)).isoformat(),
        }
    )
    private_key = Path(str(authentication_material["private_key"]))
    expired = _signed_unchecked(expired_envelope, private_key)
    with pytest.raises(AuthenticationError, match="expired"):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted",
            approved=True,
            reason=APPROVE_REASON,
            signed_operation=expired,
        )

    malformed = SignedOperation(envelope=envelope, signature_b64="not-base64!!")
    with pytest.raises(AuthenticationError, match="Malformed"):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted",
            approved=True,
            reason=APPROVE_REASON,
            signed_operation=malformed,
        )
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]


def test_authenticated_state_invalid_request_is_consumed_then_replay_rejected(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    envelope = prepare_operation(
        paths=paths,
        operation=AuthorityOperation.APPROVE,
        packet_id=packet_id,
        principal_id=str(authentication_material["principal_id"]),
        reason=APPROVE_REASON,
    ).model_copy(
        update={
            "operation_id": f"op_{'4' * 32}",
            "expected_prior_state": WorkflowState.APPROVED,
            "requested_state": WorkflowState.RELEASED,
        }
    )
    signed = _signed_unchecked(
        envelope, Path(str(authentication_material["private_key"]))
    )
    with pytest.raises(OperationBindingError):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted",
            approved=True,
            reason=APPROVE_REASON,
            signed_operation=signed,
        )
    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    consumed = database.find_consumed_authenticated_operation(
        paths.database, signed.envelope.operation_id, "unused"
    )
    assert consumed is not None
    assert consumed["adjudication_outcome"] == "rejected"
    with pytest.raises(ReplayDetected):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted",
            approved=True,
            reason=APPROVE_REASON,
            signed_operation=signed,
        )


def test_failed_authenticated_operation_persistence_rolls_back_everything(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, candidate_id, packet_id = _generate(
        qualified_candidate, content_inputs_path
    )
    signed = signed_operation(packet_id, AuthorityOperation.APPROVE, APPROVE_REASON)

    def fail_consumption(*args: object, **kwargs: object) -> None:
        raise OSError("simulated authenticated-operation persistence failure")

    monkeypatch.setattr(database, "insert_authenticated_operation", fail_consumption)
    with pytest.raises(OSError, match="authenticated-operation"):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted",
            approved=True,
            reason=APPROVE_REASON,
            signed_operation=signed,
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
                "SELECT COUNT(*) FROM transition_events WHERE command = 'approve' AND outcome = 'accepted'"
            ).fetchone()[0]
        )
    assert accepted == 0


def test_slice1_legacy_event_migration_keeps_asserted_actor_unauthenticated(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "slice1.sqlite"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE candidates (
                candidate_id TEXT PRIMARY KEY, title TEXT NOT NULL, source_url TEXT NOT NULL,
                normalized_url TEXT, source_identity TEXT NOT NULL,
                development_identifiers_json TEXT NOT NULL DEFAULT '[]', state TEXT NOT NULL,
                created_at_utc TEXT NOT NULL, normalized_json TEXT, classification_json TEXT
            );
            CREATE TABLE packets (
                packet_id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL REFERENCES candidates(candidate_id),
                packet_path TEXT NOT NULL, manifest_hash TEXT NOT NULL, state TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            );
            CREATE TABLE transition_events (
                event_id TEXT PRIMARY KEY, command TEXT NOT NULL, asserted_actor TEXT NOT NULL,
                target_type TEXT NOT NULL, target_id TEXT NOT NULL, candidate_id TEXT,
                packet_id TEXT, prior_state TEXT, requested_state TEXT, resulting_state TEXT,
                outcome TEXT NOT NULL, reason TEXT NOT NULL, governed_hash TEXT,
                input_identifiers_json TEXT NOT NULL, file_hashes_json TEXT NOT NULL,
                occurred_at_utc TEXT NOT NULL, application_version TEXT NOT NULL,
                receipt_json TEXT NOT NULL, receipt_projected_at_utc TEXT
            );
            CREATE TABLE approvals (
                approval_id TEXT PRIMARY KEY, packet_id TEXT NOT NULL REFERENCES packets(packet_id),
                actor TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL,
                manifest_hash TEXT NOT NULL, prior_state TEXT NOT NULL, decided_at_utc TEXT NOT NULL,
                transition_event_id TEXT
            );
            INSERT INTO candidates VALUES (
                'cand_legacy', 'Legacy', 'https://example.com/legacy', NULL, 'identity', '[]',
                'APPROVED', '2026-01-01T00:00:00Z', NULL, NULL
            );
            INSERT INTO packets VALUES (
                'pkt_legacy', 'cand_legacy', 'legacy/path', 'manifest', 'APPROVED',
                '2026-01-01T00:00:00Z'
            );
            INSERT INTO transition_events VALUES (
                'event_legacy', 'approve', 'Brendon', 'packet', 'pkt_legacy', 'cand_legacy',
                'pkt_legacy', 'AWAITING_APPROVAL', 'APPROVED', 'APPROVED', 'accepted',
                'legacy', 'manifest', '{}', '{}', '2026-01-01T00:00:00Z', '0.1.0',
                '{}', '2026-01-01T00:00:01Z'
            );
            INSERT INTO approvals VALUES (
                'appr_legacy', 'pkt_legacy', 'Brendon', 'APPROVED', 'legacy', 'manifest',
                'AWAITING_APPROVAL', '2026-01-01T00:00:00Z', 'event_legacy'
            );
            """
        )
    database.migrate_database(database_path)
    database.migrate_database(database_path)
    event = database.get_transition_event(database_path, "event_legacy")
    approval = database.get_approved_approval(database_path, "pkt_legacy")
    assert event is not None and approval is not None
    assert event["asserted_actor"] == "Brendon"
    assert event["authentication_status"] is None
    assert event["authenticated_principal_id"] is None
    assert approval["authenticated_principal_id"] is None
    with database.connect(database_path) as connection:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        operations = int(
            connection.execute("SELECT COUNT(*) FROM authenticated_operations").fetchone()[0]
        )
    assert version == database.DATABASE_SCHEMA_VERSION
    assert operations == 0
