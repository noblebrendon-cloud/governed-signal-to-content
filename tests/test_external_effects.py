from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import ValidationError

from governed_signal_to_content import database
from governed_signal_to_content.authentication import (
    APPROVAL_REASON,
    RELEASE_REASON,
    ReplayDetected,
    generate_signing_key,
    prepare_destination_binding_operation,
    prepare_executor_registration_operation,
    prepare_operation,
    prepare_policy_operation,
    sign_operation,
)
from governed_signal_to_content.authorization import AuthorizationRejected
from governed_signal_to_content.config import WorkspacePaths
from governed_signal_to_content.effect_executor import execute_claimed_effect
from governed_signal_to_content.effect_protocol import (
    calculate_effect_request_hash,
    calculate_idempotency_key,
)
from governed_signal_to_content.external_effects import (
    ExternalEffectClaimError,
    ExternalEffectIntegrityError,
    claim_external_effect,
    create_external_effect_request,
    mediate_execution_management,
    record_signed_executor_result,
)
from governed_signal_to_content.integrity import verify_integrity
from governed_signal_to_content.models import (
    AuthorityOperation,
    Capability,
    CapabilityPolicyOperation,
    DestinationBindingOperationEnvelope,
    ExecutorRegistrationOperationEnvelope,
    ExecutorResultEnvelope,
    ExternalEffectOutcome,
    PacketScope,
)
from governed_signal_to_content.packets import generate_packet
from governed_signal_to_content.transition_mediator import (
    mediate_signed_policy_operation,
    mediate_signed_transition,
)
from governed_signal_to_content.receipts import sanitize_for_receipt


class StaticCredentialResolver:
    def __init__(self) -> None:
        self.value = secrets.token_hex(24)

    def resolve(self, credential_ref: str) -> str:
        assert credential_ref == "cred_test-capture"
        return self.value


class MissingCredentialResolver:
    def resolve(self, credential_ref: str) -> str:
        from governed_signal_to_content.effect_executor import CredentialUnavailable

        raise CredentialUnavailable("missing test credential")


def _signed_policy(
    paths: WorkspacePaths,
    material: dict[str, object],
    operation: CapabilityPolicyOperation,
    *,
    capability: Capability | None = None,
    packet: dict[str, object] | None = None,
):
    envelope = prepare_policy_operation(
        paths=paths,
        operation=operation,
        principal_id=str(material["principal_id"]),
        subject_principal_id=(
            str(material["principal_id"])
            if operation is CapabilityPolicyOperation.GRANT
            else None
        ),
        capability=capability,
        brand_id=(
            None
            if packet is None or capability is Capability.EFFECT_MANAGE_BINDINGS
            else str(packet["brand_id"])
        ),
        channel_id=(
            None
            if packet is None or capability is Capability.EFFECT_MANAGE_BINDINGS
            else str(packet["channel_id"])
        ),
        destination_id=(
            None
            if packet is None or capability is Capability.EFFECT_MANAGE_BINDINGS
            else str(packet["destination_id"])
        ),
        reason="Slice 7 test policy operation.",
    )
    return sign_operation(envelope, Path(str(material["private_key"])))


def _prepare_released_effect_authority(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
    tmp_path: Path,
) -> tuple[WorkspacePaths, str, Path, Path]:
    paths, candidate_id = qualified_candidate
    packet_id, _, _, _ = generate_packet(paths, candidate_id, content_inputs_path)
    packet = database.get_packet(paths.database, packet_id)
    assert packet is not None
    mediate_signed_policy_operation(
        paths=paths,
        signed_operation=_signed_policy(
            paths,
            authentication_material,
            CapabilityPolicyOperation.BOOTSTRAP,
        ),
        asserted_actor="policy-display",
    )
    for capability in (
        Capability.PACKET_APPROVE,
        Capability.PACKET_RELEASE,
        Capability.EFFECT_MANAGE_BINDINGS,
    ):
        mediate_signed_policy_operation(
            paths=paths,
            signed_operation=_signed_policy(
                paths,
                authentication_material,
                CapabilityPolicyOperation.GRANT,
                capability=capability,
                packet=packet,
            ),
            asserted_actor="policy-display",
        )
    binding = prepare_destination_binding_operation(
        paths=paths,
        principal_id=str(authentication_material["principal_id"]),
        brand_id=str(packet["brand_id"]),
        channel_id=str(packet["channel_id"]),
        destination_id=str(packet["destination_id"]),
        adapter_id="test.capture",
        external_target_ref="capture.target-a",
        credential_ref="cred_test-capture",
        reason="Bind the disposable test capture destination.",
    )
    mediate_execution_management(
        paths=paths,
        signed_operation=sign_operation(
            binding, Path(str(authentication_material["private_key"]))
        ),
        asserted_actor="binding-display",
    )
    executor_private = tmp_path / "executor-private.pem"
    executor_public = tmp_path / "executor-public.pem"
    generate_signing_key(executor_private, executor_public)
    executor = prepare_executor_registration_operation(
        paths=paths,
        principal_id=str(authentication_material["principal_id"]),
        executor_id="executor_test-capture",
        executor_public_key_path=executor_public,
        allowed_adapter_ids=("test.capture",),
        reason="Register the disposable offline executor.",
    )
    mediate_execution_management(
        paths=paths,
        signed_operation=sign_operation(
            executor, Path(str(authentication_material["private_key"]))
        ),
        asserted_actor="executor-registration-display",
    )
    for operation, reason in (
        (AuthorityOperation.APPROVE, APPROVAL_REASON),
        (AuthorityOperation.RELEASE, RELEASE_REASON),
    ):
        mediate_signed_transition(
            paths=paths,
            signed_operation=sign_operation(
                prepare_operation(
                    paths=paths,
                    operation=operation,
                    packet_id=packet_id,
                    principal_id=str(authentication_material["principal_id"]),
                    reason=reason,
                ),
                Path(str(authentication_material["private_key"])),
            ),
            asserted_actor="reviewer-display",
        )
    return paths, packet_id, executor_private, tmp_path / "captures"


@pytest.mark.parametrize(
    ("changed_field", "changed_value"),
    [
        ("release_event_id", "other-release"),
        ("packet_id", "packet-b"),
        ("candidate_id", "candidate-b"),
        ("approval_id", "approval-b"),
        ("approval_event_id", "approval-event-b"),
        ("authenticated_principal_id", "principal-b"),
        ("authorizing_grant_id", "grant_" + "1" * 32),
        ("capability", "packet.other"),
        ("scope_version", "2.0"),
        ("brand_id", "brand-b"),
        ("channel_id", "channel-b"),
        ("destination_id", "destination-b"),
        ("destination_binding_id", "bind_" + "2" * 32),
        ("adapter_id", "other.adapter"),
        ("external_target_ref", "capture.target-b"),
        ("credential_ref", "cred_test-b"),
        ("packet_manifest_hash", "1" * 64),
        ("packet_receipt_hash", "2" * 64),
        ("release_event_hash", "3" * 64),
        ("release_event_sequence", 10),
        ("idempotency_key", "idem_" + "4" * 64),
        ("created_at_utc", "2026-01-01T00:00:01Z"),
        ("application_version", "0.1.1"),
    ],
)
def test_effect_hash_domains_and_semantic_sensitivity(
    changed_field: str, changed_value: object
) -> None:
    base = {
        "schema_version": "1.0",
        "effect_id": "effect_" + "a" * 32,
        "release_event_id": "release-event",
        "packet_id": "packet-a",
        "candidate_id": "candidate-a",
        "approval_id": "approval-a",
        "approval_event_id": "approval-event",
        "authenticated_principal_id": "principal-a",
        "authorizing_grant_id": "grant_" + "b" * 32,
        "capability": "packet.release",
        "scope_version": "1.0",
        "brand_id": "brand-a",
        "channel_id": "channel-a",
        "destination_id": "destination-a",
        "destination_binding_id": "bind_" + "c" * 32,
        "adapter_id": "test.capture",
        "external_target_ref": "capture.target-a",
        "credential_ref": "cred_test-a",
        "packet_manifest_hash": "d" * 64,
        "packet_receipt_hash": "e" * 64,
        "release_event_hash": "f" * 64,
        "release_event_sequence": 9,
        "idempotency_key": calculate_idempotency_key(
            "effect_" + "a" * 32, "f" * 64
        ),
        "created_at_utc": "2026-01-01T00:00:00Z",
        "application_version": "0.1.0",
        "request_event_id": "request-event-a",
    }
    first = calculate_effect_request_hash(base)
    assert first == calculate_effect_request_hash(dict(reversed(tuple(base.items()))))
    assert first != calculate_effect_request_hash(
        {**base, changed_field: changed_value}
    )
    assert first != base["idempotency_key"].removeprefix("idem_")


def test_models_reject_unknown_adapter_and_unsafe_result_semantics() -> None:
    with pytest.raises(ValidationError):
        DestinationBindingOperationEnvelope.model_validate(
            {
                "operation_id": "op_" + "a" * 32,
                "principal_id": "principal-a",
                "key_id": "key-a",
                "operation": "register-destination-binding",
                "target_id": "bind_" + "b" * 32,
                "brand_id": "brand-a",
                "channel_id": "channel-a",
                "destination_id": "destination-a",
                "adapter_id": "network.publish",
                "external_target_ref": "target-a",
                "credential_ref": "cred_test-a",
                "reason": "invalid adapter",
                "issued_at_utc": "2026-01-01T00:00:00Z",
                "expires_at_utc": "2026-01-01T00:01:00Z",
            }
        )
    with pytest.raises(ValidationError):
        ExecutorResultEnvelope(
            result_id="result_" + "a" * 32,
            executor_id="executor_test",
            executor_key_id="key",
            effect_id="effect_" + "b" * 32,
            dispatch_id="dispatch_" + "c" * 32,
            effect_request_hash="d" * 64,
            adapter_id="test.capture",
            brand_id="brand-a",
            channel_id="channel-a",
            destination_id="destination-a",
            destination_binding_id="bind_" + "e" * 32,
            artifact_hash="f" * 64,
            idempotency_key="idem_" + "0" * 64,
            outcome=ExternalEffectOutcome.SUCCEEDED,
            effect_may_have_occurred=False,
            retry_permitted=True,
            started_at_utc="2026-01-01T00:00:00Z",
            completed_at_utc="2026-01-01T00:00:01Z",
        )


def test_binding_default_denies_and_consumes_proof(
    workspace: WorkspacePaths,
    authentication_material: dict[str, object],
) -> None:
    envelope = prepare_destination_binding_operation(
        paths=workspace,
        principal_id=str(authentication_material["principal_id"]),
        brand_id="brand-test",
        channel_id="channel-test",
        destination_id="destination-test",
        adapter_id="test.capture",
        external_target_ref="capture.denied",
        credential_ref="cred_denied",
        reason="This must default deny.",
    )
    signed = sign_operation(envelope, Path(str(authentication_material["private_key"])))
    with pytest.raises(AuthorizationRejected):
        mediate_execution_management(
            paths=workspace, signed_operation=signed, asserted_actor="display"
        )
    with pytest.raises(ReplayDetected):
        mediate_execution_management(
            paths=workspace, signed_operation=signed, asserted_actor="display"
        )
    with database.connect(workspace.database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM authenticated_operations"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM external_destination_bindings"
        ).fetchone()[0] == 0


def test_complete_offline_effect_lifecycle_is_signed_chained_and_secret_free(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
    tmp_path: Path,
) -> None:
    paths, packet_id, executor_private, captures = _prepare_released_effect_authority(
        qualified_candidate, content_inputs_path, authentication_material, tmp_path
    )
    effect = create_external_effect_request(paths=paths, packet_id=packet_id)
    assert create_external_effect_request(paths=paths, packet_id=packet_id) == effect
    dispatch = claim_external_effect(paths=paths, effect_id=effect.effect_id)
    with pytest.raises(ExternalEffectClaimError):
        claim_external_effect(paths=paths, effect_id=effect.effect_id)
    before_execution = verify_integrity(paths.database, paths.receipt_log)
    assert before_execution.canonical_chain_valid, before_execution.failures
    assert before_execution.canonical_policy_valid, before_execution.failures
    assert before_execution.canonical_external_effect_valid, before_execution.failures
    resolver = StaticCredentialResolver()
    signed_result = execute_claimed_effect(
        workspace=paths.root,
        effect_id=effect.effect_id,
        dispatch_id=dispatch.dispatch_id,
        executor_id="executor_test-capture",
        executor_private_key_path=executor_private,
        capture_directory=captures,
        credential_resolver=resolver,
    )
    row = record_signed_executor_result(paths=paths, signed_result=signed_result)
    assert row["outcome"] == "SUCCEEDED"
    assert row["retry_permitted"] == 0
    assert record_signed_executor_result(paths=paths, signed_result=signed_result)[
        "result_id"
    ] == row["result_id"]
    capture_files = list(captures.iterdir())
    assert len(capture_files) == 1
    persisted = capture_files[0].read_text(encoding="utf-8")
    assert resolver.value not in persisted
    assert effect.credential_ref not in persisted
    verification = verify_integrity(paths.database, paths.receipt_log)
    assert verification.canonical_chain_valid
    assert verification.canonical_policy_valid
    assert verification.canonical_external_effect_valid, verification.failures
    assert verification.projection_valid
    assert verification.projection_complete
    assert verification.destination_bindings_checked == 1
    assert verification.effect_executors_checked == 1
    assert verification.external_effect_requests_checked == 1
    assert verification.external_effect_dispatches_checked == 1
    assert verification.external_effect_results_checked == 1
    receipts = paths.receipt_log.read_text(encoding="utf-8")
    assert resolver.value not in receipts
    assert "PRIVATE KEY" not in receipts


def test_result_tampering_and_artifact_change_are_detected(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
    tmp_path: Path,
) -> None:
    paths, packet_id, executor_private, captures = _prepare_released_effect_authority(
        qualified_candidate, content_inputs_path, authentication_material, tmp_path
    )
    effect = create_external_effect_request(paths=paths, packet_id=packet_id)
    dispatch = claim_external_effect(paths=paths, effect_id=effect.effect_id)
    packet = database.get_packet(paths.database, packet_id)
    assert packet is not None
    artifact = Path(str(packet["packet_path"])) / "01_linkedin_analysis.md"
    artifact.write_text("tampered\n", encoding="utf-8")
    with pytest.raises((ExternalEffectIntegrityError, ValueError)):
        execute_claimed_effect(
            workspace=paths.root,
            effect_id=effect.effect_id,
            dispatch_id=dispatch.dispatch_id,
            executor_id="executor_test-capture",
            executor_private_key_path=executor_private,
            capture_directory=captures,
            credential_resolver=StaticCredentialResolver(),
        )
    verification = verify_integrity(paths.database, paths.receipt_log)
    assert not verification.canonical_external_effect_valid


def test_confirmed_pre_effect_failure_permits_one_fresh_claim(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
    tmp_path: Path,
) -> None:
    paths, packet_id, executor_private, captures = _prepare_released_effect_authority(
        qualified_candidate, content_inputs_path, authentication_material, tmp_path
    )
    effect = create_external_effect_request(paths=paths, packet_id=packet_id)
    first = claim_external_effect(paths=paths, effect_id=effect.effect_id)
    failed = execute_claimed_effect(
        workspace=paths.root,
        effect_id=effect.effect_id,
        dispatch_id=first.dispatch_id,
        executor_id="executor_test-capture",
        executor_private_key_path=executor_private,
        capture_directory=captures,
        credential_resolver=MissingCredentialResolver(),
    )
    assert failed.envelope.outcome is ExternalEffectOutcome.FAILED
    assert not failed.envelope.effect_may_have_occurred
    assert failed.envelope.retry_permitted
    record_signed_executor_result(paths=paths, signed_result=failed)
    second = claim_external_effect(paths=paths, effect_id=effect.effect_id)
    assert second.attempt_number == 2
    with pytest.raises(ExternalEffectClaimError):
        claim_external_effect(paths=paths, effect_id=effect.effect_id)


def test_invalid_executor_signature_cannot_create_result_or_chain_event(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
    tmp_path: Path,
) -> None:
    paths, packet_id, executor_private, captures = _prepare_released_effect_authority(
        qualified_candidate, content_inputs_path, authentication_material, tmp_path
    )
    effect = create_external_effect_request(paths=paths, packet_id=packet_id)
    dispatch = claim_external_effect(paths=paths, effect_id=effect.effect_id)
    signed = execute_claimed_effect(
        workspace=paths.root,
        effect_id=effect.effect_id,
        dispatch_id=dispatch.dispatch_id,
        executor_id="executor_test-capture",
        executor_private_key_path=executor_private,
        capture_directory=captures,
        credential_resolver=StaticCredentialResolver(),
    )
    tampered = signed.model_copy(update={"signature_b64": "AAAA"})
    with database.connect(paths.database) as connection:
        before = connection.execute(
            "SELECT COUNT(*) FROM transition_events"
        ).fetchone()[0]
    with pytest.raises(ValueError):
        record_signed_executor_result(paths=paths, signed_result=tampered)
    with database.connect(paths.database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM external_effect_results"
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COUNT(*) FROM transition_events"
        ).fetchone()[0] == before


def test_binding_event_failure_rolls_back_proof_and_policy_row(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, _, _, _ = _prepare_released_effect_authority(
        qualified_candidate, content_inputs_path, authentication_material, tmp_path
    )
    envelope = prepare_destination_binding_operation(
        paths=paths,
        principal_id=str(authentication_material["principal_id"]),
        brand_id="brand-second",
        channel_id="channel-second",
        destination_id="destination-second",
        adapter_id="test.capture",
        external_target_ref="capture.target-second",
        credential_ref="cred_test-second",
        reason="Fault injection must roll back.",
    )
    signed = sign_operation(envelope, Path(str(authentication_material["private_key"])))
    with database.connect(paths.database) as connection:
        operations_before = connection.execute(
            "SELECT COUNT(*) FROM authenticated_operations"
        ).fetchone()[0]
        bindings_before = connection.execute(
            "SELECT COUNT(*) FROM external_destination_bindings"
        ).fetchone()[0]

    def fail_event(*args: object, **kwargs: object) -> None:
        raise RuntimeError("injected event failure")

    monkeypatch.setattr(database, "insert_transition_event", fail_event)
    with pytest.raises(RuntimeError, match="injected event failure"):
        mediate_execution_management(
            paths=paths, signed_operation=signed, asserted_actor="fault-display"
        )
    with database.connect(paths.database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM authenticated_operations"
        ).fetchone()[0] == operations_before
        assert connection.execute(
            "SELECT COUNT(*) FROM external_destination_bindings"
        ).fetchone()[0] == bindings_before


def test_two_writers_allocate_one_claim(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
    tmp_path: Path,
) -> None:
    paths, packet_id, _, _ = _prepare_released_effect_authority(
        qualified_candidate, content_inputs_path, authentication_material, tmp_path
    )
    effect = create_external_effect_request(paths=paths, packet_id=packet_id)

    def attempt() -> str:
        try:
            return claim_external_effect(paths=paths, effect_id=effect.effect_id).dispatch_id
        except ExternalEffectClaimError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: attempt(), range(2)))
    assert outcomes.count("rejected") == 1
    with database.connect(paths.database) as connection:
        rows = connection.execute(
            "SELECT attempt_number FROM external_effect_dispatches"
        ).fetchall()
    assert [row["attempt_number"] for row in rows] == [1]


def test_schema5_verification_is_read_only_and_reports_not_activated(
    workspace: WorkspacePaths,
) -> None:
    with database.connect(workspace.database) as connection:
        connection.execute("PRAGMA user_version = 5")
    before = workspace.database.read_bytes()
    result = verify_integrity(workspace.database, workspace.receipt_log)
    assert result.canonical_chain_valid
    assert result.canonical_policy_valid
    assert not result.canonical_external_effect_valid
    assert any(
        failure.code == "external_effect_not_activated" for failure in result.failures
    )
    assert workspace.database.read_bytes() == before


def test_schema6_migration_is_idempotent_and_preserves_existing_chain_bytes(
    workspace: WorkspacePaths,
) -> None:
    with database.connect(workspace.database) as connection:
        connection.execute("PRAGMA user_version = 5")
        before = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM transition_event_chain_entries ORDER BY event_sequence"
            ).fetchall()
        ]
    jsonl = workspace.receipt_log.read_bytes()
    database.migrate_database(workspace.database)
    database.migrate_database(workspace.database)
    with database.connect(workspace.database) as connection:
        after = [
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM transition_event_chain_entries ORDER BY event_sequence"
            ).fetchall()
        ]
        assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == 6
    assert before == after
    assert workspace.receipt_log.read_bytes() == jsonl


@pytest.mark.parametrize(
    ("field", "tampered_value"),
    [
        ("external_target_ref", "capture.tampered"),
        ("credential_ref", "cred_tampered"),
        ("packet_manifest_hash", "1" * 64),
        ("packet_receipt_hash", "2" * 64),
        ("release_event_hash", "3" * 64),
        ("release_event_sequence", 999),
        ("idempotency_key", "idem_" + "4" * 64),
        ("request_hash", "5" * 64),
    ],
)
def test_effect_ledger_column_tampering_is_detected_independently_of_chain(
    field: str,
    tampered_value: object,
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    authentication_material: dict[str, object],
    tmp_path: Path,
) -> None:
    paths, packet_id, _, _ = _prepare_released_effect_authority(
        qualified_candidate, content_inputs_path, authentication_material, tmp_path
    )
    effect = create_external_effect_request(paths=paths, packet_id=packet_id)
    with database.connect(paths.database) as connection:
        connection.execute(
            f"UPDATE external_effect_requests SET {field} = ? WHERE effect_id = ?",  # noqa: S608
            (tampered_value, effect.effect_id),
        )
    verification = verify_integrity(paths.database, paths.receipt_log)
    assert verification.canonical_chain_valid
    assert verification.canonical_policy_valid
    assert not verification.canonical_external_effect_valid
    assert any(
        failure.code == "external_effect_request_mismatch"
        for failure in verification.failures
    )


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        *(
            ("external_target_ref", value)
            for value in (
                "secret.value",
                "token.value",
                "credential.value",
                "password.value",
                "oauth.value",
                "api-key.value",
                "private-key.value",
                "session-key.value",
            )
        ),
        *(
            ("credential_ref", value)
            for value in (
                "cred_secret",
                "cred_token",
                "cred_credential",
                "cred_password",
                "cred_oauth",
                "cred_api-key",
                "cred_private-key",
                "cred_session-key",
            )
        ),
    ],
)
def test_binding_envelope_rejects_credential_material_shaped_references(
    field: str, unsafe_value: str
) -> None:
    values = {
        "operation_id": "op_" + "a" * 32,
        "principal_id": "principal-a",
        "key_id": "ed25519:key-a",
        "target_id": "bind_" + "b" * 32,
        "brand_id": "brand-a",
        "channel_id": "channel-a",
        "destination_id": "destination-a",
        "adapter_id": "test.capture",
        "external_target_ref": "capture.target-a",
        "credential_ref": "cred_capture-a",
        "reason": "Validate safe opaque references.",
        "issued_at_utc": "2026-01-01T00:00:00Z",
        "expires_at_utc": "2026-01-01T00:01:00Z",
    }
    with pytest.raises(ValidationError):
        DestinationBindingOperationEnvelope.model_validate(
            {**values, field: unsafe_value}
        )


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        (field, value)
        for field in ("brand_id", "channel_id", "destination_id")
        for value in (
            "all",
            "default",
            "global",
            "wildcard",
            "secret-scope",
            "token-scope",
            "api-key-scope",
            "private-key-scope",
        )
    ],
)
def test_packet_scope_rejects_wildcard_and_secret_shaped_components(
    field: str, unsafe_value: str
) -> None:
    with pytest.raises(ValidationError):
        PacketScope.model_validate(
            {
                "brand_id": "brand-a",
                "channel_id": "channel-a",
                "destination_id": "destination-a",
                field: unsafe_value,
            }
        )


@pytest.mark.parametrize(
    ("outcome", "valid_values", "invalid_update"),
    [
        ("SUCCEEDED", {"effect_may_have_occurred": True, "retry_permitted": False,
                       "remote_reference": "capture:one", "response_hash": "1" * 64},
         {"remote_reference": None}),
        ("SUCCEEDED", {"effect_may_have_occurred": True, "retry_permitted": False,
                       "remote_reference": "capture:one", "response_hash": "1" * 64},
         {"response_hash": None}),
        ("SUCCEEDED", {"effect_may_have_occurred": True, "retry_permitted": False,
                       "remote_reference": "capture:one", "response_hash": "1" * 64},
         {"error_code": "ERR"}),
        ("SUCCEEDED", {"effect_may_have_occurred": True, "retry_permitted": False,
                       "remote_reference": "capture:one", "response_hash": "1" * 64},
         {"effect_may_have_occurred": False}),
        ("SUCCEEDED", {"effect_may_have_occurred": True, "retry_permitted": False,
                       "remote_reference": "capture:one", "response_hash": "1" * 64},
         {"retry_permitted": True}),
        ("FAILED", {"effect_may_have_occurred": False, "retry_permitted": True,
                    "error_code": "FAILED_SAFE"}, {"error_code": None}),
        ("FAILED", {"effect_may_have_occurred": False, "retry_permitted": True,
                    "error_code": "FAILED_SAFE"}, {"remote_reference": "remote"}),
        ("FAILED", {"effect_may_have_occurred": False, "retry_permitted": True,
                    "error_code": "FAILED_SAFE"}, {"response_hash": "2" * 64}),
        ("FAILED", {"effect_may_have_occurred": False, "retry_permitted": True,
                    "error_code": "FAILED_SAFE"}, {"effect_may_have_occurred": True}),
        ("UNKNOWN", {"effect_may_have_occurred": True, "retry_permitted": False,
                     "error_code": "OUTCOME_UNKNOWN"}, {"error_code": None}),
        ("UNKNOWN", {"effect_may_have_occurred": True, "retry_permitted": False,
                     "error_code": "OUTCOME_UNKNOWN"}, {"effect_may_have_occurred": False}),
        ("UNKNOWN", {"effect_may_have_occurred": True, "retry_permitted": False,
                     "error_code": "OUTCOME_UNKNOWN"}, {"retry_permitted": True}),
    ],
)
def test_executor_result_semantics_fail_closed(
    outcome: str,
    valid_values: dict[str, object],
    invalid_update: dict[str, object],
) -> None:
    base: dict[str, object] = {
        "result_id": "result_" + "a" * 32,
        "executor_id": "executor_test",
        "executor_key_id": "ed25519:key",
        "effect_id": "effect_" + "b" * 32,
        "dispatch_id": "dispatch_" + "c" * 32,
        "effect_request_hash": "d" * 64,
        "adapter_id": "test.capture",
        "brand_id": "brand-a",
        "channel_id": "channel-a",
        "destination_id": "destination-a",
        "destination_binding_id": "bind_" + "e" * 32,
        "artifact_hash": "f" * 64,
        "idempotency_key": "idem_" + "0" * 64,
        "outcome": outcome,
        "started_at_utc": "2026-01-01T00:00:00Z",
        "completed_at_utc": "2026-01-01T00:00:01Z",
        **valid_values,
        **invalid_update,
    }
    with pytest.raises(ValidationError):
        ExecutorResultEnvelope.model_validate(base)


@pytest.mark.parametrize(
    "sensitive_key",
    [
        "authorization",
        "password",
        "secret",
        "token",
        "api_token",
        "credential_value",
        "client_secret",
        "refresh_token",
        "private_credential",
        "authorization_header",
    ],
)
def test_receipt_sanitizer_redacts_secret_values_but_not_opaque_reference(
    sensitive_key: str,
) -> None:
    sanitized = sanitize_for_receipt(
        {sensitive_key: "runtime-value", "credential_ref": "cred_capture-a"}
    )
    assert sanitized[sensitive_key] == "[REDACTED]"
    assert sanitized["credential_ref"] == "cred_capture-a"


@pytest.mark.parametrize(
    ("effect_id", "release_hash"),
    [
        ("effect_" + character * 32, character * 64)
        for character in "12345678"
    ],
)
def test_idempotency_key_is_stable_and_binds_effect_and_release(
    effect_id: str, release_hash: str
) -> None:
    key = calculate_idempotency_key(effect_id, release_hash)
    assert key == calculate_idempotency_key(effect_id, release_hash)
    assert key != calculate_idempotency_key(effect_id, "f" * 64)
    assert key.startswith("idem_") and len(key) == 69


@pytest.mark.parametrize(
    "allowed_adapter_ids",
    [
        (),
        ("test.capture", "test.capture"),
        ("network.publish",),
        ("test.capture", "network.publish"),
        ("network.publish", "test.capture"),
        ("test.capture", "test.capture", "test.capture"),
    ],
)
def test_executor_registration_rejects_empty_duplicate_or_unknown_adapter_sets(
    allowed_adapter_ids: tuple[str, ...]
) -> None:
    with pytest.raises(ValidationError):
        ExecutorRegistrationOperationEnvelope.model_validate(
            {
                "operation_id": "op_" + "a" * 32,
                "principal_id": "principal-a",
                "key_id": "ed25519:principal",
                "target_id": "executor_test",
                "executor_key_id": "ed25519:executor",
                "executor_public_key_b64": "AA==",
                "executor_verifier_fingerprint": "b" * 64,
                "allowed_adapter_ids": allowed_adapter_ids,
                "reason": "Validate fixed adapter registry.",
                "issued_at_utc": "2026-01-01T00:00:00Z",
                "expires_at_utc": "2026-01-01T00:01:00Z",
            }
        )
