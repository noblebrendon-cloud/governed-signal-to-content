"""Local Ed25519 principal verification and exact-operation authentication."""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, TypeAlias
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import TypeAdapter, ValidationError

from . import database
from .config import WorkspacePaths
from .hashing import canonical_json, sha256_bytes
from .models import (
    AuthenticatedPrincipal,
    AuthenticationEvidence,
    AuthorityOperation,
    CAPABILITY_STATE_SCOPES,
    Capability,
    CapabilityPolicyOperation,
    CapabilityPolicyOperationEnvelope,
    DestinationBindingOperationEnvelope,
    ExecutionManagementOperationEnvelope,
    ExecutorRegistrationOperationEnvelope,
    PacketScope,
    SignedOperation,
    SignedOperationEnvelope,
    TransitionRequest,
    TrustedPrincipal,
    WorkflowState,
)
from .packets import recompute_packet_manifest
from .receipts import utc_now


AUTHENTICATION_SCHEME = "ed25519"
DEFAULT_OPERATION_LIFETIME_SECONDS = 300
MAX_OPERATION_LIFETIME_SECONDS = 600
MAX_CLOCK_SKEW_SECONDS = 30
APPROVAL_REASON = "Explicit human approval recorded."
RELEASE_REASON = (
    "Locally authorized for downstream publication. No external platform was contacted "
    "and no content was posted."
)


class AuthenticationError(ValueError):
    def __init__(self, message: str, evidence: AuthenticationEvidence) -> None:
        self.evidence = evidence
        super().__init__(message)


class AuthenticationRequired(AuthenticationError):
    pass


class ReplayDetected(AuthenticationError):
    pass


class OperationBindingError(AuthenticationError):
    pass


@dataclass(frozen=True, slots=True)
class AuthenticatedTransitionRequest:
    """Verifier-produced immutable request plus cryptographic provenance.

    Python cannot make this object unforgeable to arbitrary hostile code already
    executing in the process. Supported application paths obtain it only from
    ``authenticate_transition_request`` and never accept a caller-created boolean.
    """

    request: TransitionRequest
    principal: AuthenticatedPrincipal
    envelope_json: str
    signature_b64: str

    def evidence(
        self,
        status: Literal["verified", "failed", "replay_rejected"] = "verified",
    ) -> AuthenticationEvidence:
        return AuthenticationEvidence(
            verification_status=status,
            authenticated_principal_id=self.principal.principal_id,
            authentication_scheme=self.principal.authentication_scheme,
            authentication_key_id=self.principal.key_id,
            verifier_fingerprint=self.principal.verifier_fingerprint,
            authentication_operation_id=self.principal.operation_id,
            authentication_envelope_hash=self.principal.envelope_hash,
            authentication_proof_hash=self.principal.proof_hash,
            authenticated_at_utc=self.principal.authenticated_at_utc,
        )

    def consumption_record(self) -> dict[str, object]:
        return {
            "operation_id": self.principal.operation_id,
            "principal_id": self.principal.principal_id,
            "authentication_scheme": self.principal.authentication_scheme,
            "key_id": self.principal.key_id,
            "verifier_fingerprint": self.principal.verifier_fingerprint,
            "envelope_hash": self.principal.envelope_hash,
            "proof_hash": self.principal.proof_hash,
            "envelope_json": self.envelope_json,
            "signature_b64": self.signature_b64,
            "verified_at_utc": self.principal.authenticated_at_utc,
            "consumed_at_utc": utc_now(),
        }


@dataclass(frozen=True, slots=True)
class AuthenticatedCapabilityPolicyRequest:
    """Verifier-produced immutable capability-policy request and provenance."""

    request: CapabilityPolicyOperationEnvelope
    principal: AuthenticatedPrincipal
    envelope_json: str
    signature_b64: str

    def evidence(
        self,
        status: Literal["verified", "failed", "replay_rejected"] = "verified",
    ) -> AuthenticationEvidence:
        return AuthenticationEvidence(
            verification_status=status,
            authenticated_principal_id=self.principal.principal_id,
            authentication_scheme=self.principal.authentication_scheme,
            authentication_key_id=self.principal.key_id,
            verifier_fingerprint=self.principal.verifier_fingerprint,
            authentication_operation_id=self.principal.operation_id,
            authentication_envelope_hash=self.principal.envelope_hash,
            authentication_proof_hash=self.principal.proof_hash,
            authenticated_at_utc=self.principal.authenticated_at_utc,
        )

    def consumption_record(self) -> dict[str, object]:
        return {
            "operation_id": self.principal.operation_id,
            "principal_id": self.principal.principal_id,
            "authentication_scheme": self.principal.authentication_scheme,
            "key_id": self.principal.key_id,
            "verifier_fingerprint": self.principal.verifier_fingerprint,
            "envelope_hash": self.principal.envelope_hash,
            "proof_hash": self.principal.proof_hash,
            "envelope_json": self.envelope_json,
            "signature_b64": self.signature_b64,
            "verified_at_utc": self.principal.authenticated_at_utc,
            "consumed_at_utc": utc_now(),
        }


@dataclass(frozen=True, slots=True)
class AuthenticatedExecutionManagementRequest:
    """Verifier-produced immutable destination/executor management request."""

    request: ExecutionManagementOperationEnvelope
    principal: AuthenticatedPrincipal
    envelope_json: str
    signature_b64: str

    def evidence(
        self,
        status: Literal["verified", "failed", "replay_rejected"] = "verified",
    ) -> AuthenticationEvidence:
        return AuthenticationEvidence(
            verification_status=status,
            authenticated_principal_id=self.principal.principal_id,
            authentication_scheme=self.principal.authentication_scheme,
            authentication_key_id=self.principal.key_id,
            verifier_fingerprint=self.principal.verifier_fingerprint,
            authentication_operation_id=self.principal.operation_id,
            authentication_envelope_hash=self.principal.envelope_hash,
            authentication_proof_hash=self.principal.proof_hash,
            authenticated_at_utc=self.principal.authenticated_at_utc,
        )

    def consumption_record(self) -> dict[str, object]:
        return {
            "operation_id": self.principal.operation_id,
            "principal_id": self.principal.principal_id,
            "authentication_scheme": self.principal.authentication_scheme,
            "key_id": self.principal.key_id,
            "verifier_fingerprint": self.principal.verifier_fingerprint,
            "envelope_hash": self.principal.envelope_hash,
            "proof_hash": self.principal.proof_hash,
            "envelope_json": self.envelope_json,
            "signature_b64": self.signature_b64,
            "verified_at_utc": self.principal.authenticated_at_utc,
            "consumed_at_utc": utc_now(),
        }


AuthenticatedAuthorityRequest: TypeAlias = (
    AuthenticatedTransitionRequest
    | AuthenticatedCapabilityPolicyRequest
    | AuthenticatedExecutionManagementRequest
)


# Compatibility name for Slice 2 callers. The represented value is now the
# authenticated semantic TransitionRequest used by the mediator.
VerifiedOperation = AuthenticatedTransitionRequest


def _utc_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"Invalid UTC timestamp: {value}") from error
    if parsed.tzinfo is None:
        raise ValueError(f"UTC timestamp lacks timezone: {value}")
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _raw_public_key(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _public_key_identity(public_key: Ed25519PublicKey) -> tuple[str, str, str]:
    raw = _raw_public_key(public_key)
    fingerprint = sha256_bytes(raw)
    return (
        f"ed25519:{fingerprint}",
        fingerprint,
        base64.b64encode(raw).decode("ascii"),
    )


def generate_signing_key(private_key_path: Path, public_key_path: Path) -> dict[str, str]:
    """Generate disposable/local key files without touching canonical storage."""
    private_key_path = private_key_path.expanduser().resolve()
    public_key_path = public_key_path.expanduser().resolve()
    if private_key_path == public_key_path:
        raise ValueError("Private and public key paths must differ")
    if private_key_path.exists() or public_key_path.exists():
        raise FileExistsError("Key output paths must not already exist")
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with private_key_path.open("xb") as stream:
        stream.write(private_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.chmod(private_key_path, 0o600)
        with public_key_path.open("xb") as stream:
            stream.write(public_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        # The private key remains at the explicit caller-selected path so it is
        # never silently destroyed after successful generation.
        raise
    key_id, fingerprint, _ = _public_key_identity(private_key.public_key())
    return {"key_id": key_id, "verifier_fingerprint": fingerprint}


def bootstrap_trusted_principal(
    database_path: Path, principal_id: str, public_key_path: Path
) -> TrustedPrincipal:
    try:
        loaded = serialization.load_pem_public_key(
            public_key_path.expanduser().resolve(strict=True).read_bytes()
        )
    except (OSError, ValueError) as error:
        raise ValueError(f"Invalid public verification key: {error}") from error
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("Trusted principal key must be an Ed25519 public key")
    key_id, fingerprint, public_key_b64 = _public_key_identity(loaded)
    principal = TrustedPrincipal(
        principal_id=principal_id,
        key_id=key_id,
        public_key_b64=public_key_b64,
        verifier_fingerprint=fingerprint,
        bootstrapped_at_utc=utc_now(),
    )
    database.bootstrap_trusted_principal(
        database_path, principal.model_dump(mode="json")
    )
    return principal


def canonical_envelope_json(
    envelope: (
        SignedOperationEnvelope
        | CapabilityPolicyOperationEnvelope
        | ExecutionManagementOperationEnvelope
    ),
) -> str:
    return canonical_json(envelope.model_dump(mode="json"))


def prepare_operation(
    *,
    paths: WorkspacePaths,
    operation: AuthorityOperation,
    packet_id: str,
    principal_id: str,
    reason: str,
    now: datetime | None = None,
) -> SignedOperationEnvelope:
    database.migrate_database(paths.database)
    principal = database.get_trusted_principal(paths.database, principal_id)
    if principal is None:
        raise KeyError(f"Unknown trusted principal: {principal_id}")
    packet = database.get_packet(paths.database, packet_id)
    if packet is None:
        raise KeyError(f"Unknown packet: {packet_id}")
    if packet.get("scope_version") != "1.0" or None in (
        packet.get("brand_id"),
        packet.get("channel_id"),
        packet.get("destination_id"),
    ):
        raise ValueError("Canonical packet scope is required before preparing an operation")
    scope = PacketScope(
        brand_id=packet["brand_id"],
        channel_id=packet["channel_id"],
        destination_id=packet["destination_id"],
    )
    state = WorkflowState(str(packet["state"]))
    expected_state = {
        AuthorityOperation.APPROVE: WorkflowState.AWAITING_APPROVAL,
        AuthorityOperation.REJECT: WorkflowState.AWAITING_APPROVAL,
        AuthorityOperation.RELEASE: WorkflowState.APPROVED,
    }[operation]
    requested_state = {
        AuthorityOperation.APPROVE: WorkflowState.APPROVED,
        AuthorityOperation.REJECT: WorkflowState.REJECTED,
        AuthorityOperation.RELEASE: WorkflowState.RELEASED,
    }[operation]
    if state is not expected_state:
        raise ValueError(
            f"Cannot prepare {operation.value}: packet state is {state.value}, "
            f"expected {expected_state.value}"
        )
    artifact_hashes, manifest_hash = recompute_packet_manifest(packet)
    if manifest_hash != str(packet["manifest_hash"]):
        raise ValueError("Cannot prepare operation for a packet with a changed manifest")
    approval = None
    if operation is AuthorityOperation.RELEASE:
        approval = database.get_approved_approval(paths.database, packet_id)
        if approval is None:
            raise ValueError("Cannot prepare release without a canonical approval")
        if str(approval["manifest_hash"]) != manifest_hash:
            raise ValueError("Cannot prepare release with a mismatched approval manifest")
        if (
            approval.get("scope_version") != scope.scope_version
            or approval.get("brand_id") != scope.brand_id
            or approval.get("channel_id") != scope.channel_id
            or approval.get("destination_id") != scope.destination_id
        ):
            raise ValueError("Cannot prepare release with mismatched approval scope")
    issued = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = issued + timedelta(seconds=DEFAULT_OPERATION_LIFETIME_SECONDS)
    return SignedOperationEnvelope(
        operation_id=f"op_{uuid4().hex}",
        principal_id=principal_id,
        key_id=str(principal["key_id"]),
        operation=operation,
        target_id=packet_id,
        candidate_id=str(packet["candidate_id"]),
        expected_prior_state=expected_state,
        requested_state=requested_state,
        packet_manifest_hash=manifest_hash,
        packet_receipt_hash=artifact_hashes["packet_receipt.json"],
        approval_decision=(
            WorkflowState.REJECTED.value
            if operation is AuthorityOperation.REJECT
            else WorkflowState.APPROVED.value
        ),
        approval_id=(
            str(approval["approval_id"])
            if approval is not None
            else f"appr_{uuid4().hex}"
        ),
        approval_transition_event_id=(
            None if approval is None else approval.get("transition_event_id")
        ),
        scope_version=scope.scope_version,
        brand_id=scope.brand_id,
        channel_id=scope.channel_id,
        destination_id=scope.destination_id,
        reason=reason,
        issued_at_utc=_utc_text(issued),
        expires_at_utc=_utc_text(expires),
    )


def prepare_policy_operation(
    *,
    paths: WorkspacePaths,
    operation: CapabilityPolicyOperation,
    principal_id: str,
    reason: str,
    subject_principal_id: str | None = None,
    capability: Capability | None = None,
    grant_id: str | None = None,
    brand_id: str | None = None,
    channel_id: str | None = None,
    destination_id: str | None = None,
    now: datetime | None = None,
) -> CapabilityPolicyOperationEnvelope:
    """Prepare one exact policy request from current canonical policy state."""
    database.migrate_database(paths.database)
    principal = database.get_trusted_principal(paths.database, principal_id)
    if principal is None:
        raise KeyError(f"Unknown trusted principal: {principal_id}")

    revocation_id: str | None = None
    if operation is CapabilityPolicyOperation.BOOTSTRAP:
        if subject_principal_id not in {None, principal_id}:
            raise ValueError("Policy bootstrap subject must be the requesting principal")
        if capability not in {None, Capability.POLICY_MANAGE_CAPABILITIES}:
            raise ValueError("Policy bootstrap grants only policy.manage_capabilities")
        if grant_id is not None:
            raise ValueError("Policy bootstrap grant ID is generated canonically")
        if any(value is not None for value in (brand_id, channel_id, destination_id)):
            raise ValueError("Policy bootstrap is not packet scoped")
        subject = principal_id
        selected_capability = Capability.POLICY_MANAGE_CAPABILITIES
        selected_grant_id = f"grant_{uuid4().hex}"
    elif operation is CapabilityPolicyOperation.GRANT:
        if subject_principal_id is None or capability is None:
            raise ValueError("Capability grant requires subject principal and capability")
        if database.get_trusted_principal(paths.database, subject_principal_id) is None:
            raise KeyError(f"Unknown trusted principal: {subject_principal_id}")
        if grant_id is not None:
            raise ValueError("Capability grant ID is generated canonically")
        subject = subject_principal_id
        selected_capability = capability
        selected_grant_id = f"grant_{uuid4().hex}"
        if selected_capability in {
            Capability.POLICY_MANAGE_CAPABILITIES,
            Capability.EFFECT_MANAGE_BINDINGS,
        }:
            if any(
                value is not None for value in (brand_id, channel_id, destination_id)
            ):
                raise ValueError("Management capability is not packet scoped")
            selected_scope: PacketScope | None = None
        else:
            if None in (brand_id, channel_id, destination_id):
                raise ValueError(
                    "Operational capability grant requires brand, channel, and destination"
                )
            selected_scope = PacketScope(
                brand_id=brand_id,
                channel_id=channel_id,
                destination_id=destination_id,
            )
    else:
        if grant_id is None:
            raise ValueError("Capability revocation requires an existing grant ID")
        existing = database.get_capability_grant(paths.database, grant_id)
        if existing is None:
            raise KeyError(f"Unknown capability grant: {grant_id}")
        subject = str(existing["subject_principal_id"])
        selected_capability = Capability(str(existing["capability"]))
        selected_grant_id = grant_id
        revocation_id = f"revoke_{uuid4().hex}"
        if any(value is not None for value in (brand_id, channel_id, destination_id)):
            raise ValueError("Revocation scope is derived from its exact canonical grant")
        selected_scope = (
            None
            if existing.get("scope_version") != "1.0"
            or None
            in (
                existing.get("brand_id"),
                existing.get("channel_id"),
                existing.get("destination_id"),
            )
            else PacketScope(
                brand_id=existing["brand_id"],
                channel_id=existing["channel_id"],
                destination_id=existing["destination_id"],
            )
        )

    if operation is CapabilityPolicyOperation.BOOTSTRAP:
        selected_scope = None

    expected_prior, requested = CAPABILITY_STATE_SCOPES[selected_capability]
    issued = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = issued + timedelta(seconds=DEFAULT_OPERATION_LIFETIME_SECONDS)
    return CapabilityPolicyOperationEnvelope(
        operation_id=f"op_{uuid4().hex}",
        principal_id=principal_id,
        key_id=str(principal["key_id"]),
        operation=operation,
        grant_id=selected_grant_id,
        revocation_id=revocation_id,
        subject_principal_id=subject,
        capability=selected_capability,
        expected_prior_state=expected_prior,
        requested_state=requested,
        scope_version="1.0",
        brand_id=None if selected_scope is None else selected_scope.brand_id,
        channel_id=None if selected_scope is None else selected_scope.channel_id,
        destination_id=(
            None if selected_scope is None else selected_scope.destination_id
        ),
        reason=reason,
        issued_at_utc=_utc_text(issued),
        expires_at_utc=_utc_text(expires),
    )


def prepare_destination_binding_operation(
    *,
    paths: WorkspacePaths,
    principal_id: str,
    brand_id: str,
    channel_id: str,
    destination_id: str,
    adapter_id: str,
    external_target_ref: str,
    credential_ref: str,
    reason: str,
    now: datetime | None = None,
) -> DestinationBindingOperationEnvelope:
    """Prepare one immutable, exact logical-to-technical destination binding."""
    database.migrate_database(paths.database)
    principal = database.get_trusted_principal(paths.database, principal_id)
    if principal is None:
        raise KeyError(f"Unknown trusted principal: {principal_id}")
    issued = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = issued + timedelta(seconds=DEFAULT_OPERATION_LIFETIME_SECONDS)
    return DestinationBindingOperationEnvelope(
        operation_id=f"op_{uuid4().hex}",
        principal_id=principal_id,
        key_id=str(principal["key_id"]),
        target_id=f"bind_{uuid4().hex}",
        brand_id=brand_id,
        channel_id=channel_id,
        destination_id=destination_id,
        adapter_id=adapter_id,  # type: ignore[arg-type]
        external_target_ref=external_target_ref,
        credential_ref=credential_ref,
        reason=reason,
        issued_at_utc=_utc_text(issued),
        expires_at_utc=_utc_text(expires),
    )


def prepare_executor_registration_operation(
    *,
    paths: WorkspacePaths,
    principal_id: str,
    executor_id: str,
    executor_public_key_path: Path,
    allowed_adapter_ids: tuple[str, ...],
    reason: str,
    now: datetime | None = None,
) -> ExecutorRegistrationOperationEnvelope:
    """Prepare signed registration of an executor public identity only."""
    database.migrate_database(paths.database)
    principal = database.get_trusted_principal(paths.database, principal_id)
    if principal is None:
        raise KeyError(f"Unknown trusted principal: {principal_id}")
    try:
        loaded = serialization.load_pem_public_key(
            executor_public_key_path.expanduser().resolve(strict=True).read_bytes()
        )
    except (OSError, ValueError) as error:
        raise ValueError(f"Invalid executor public verification key: {error}") from error
    if not isinstance(loaded, Ed25519PublicKey):
        raise ValueError("Executor identity key must be an Ed25519 public key")
    executor_key_id, fingerprint, public_key_b64 = _public_key_identity(loaded)
    issued = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires = issued + timedelta(seconds=DEFAULT_OPERATION_LIFETIME_SECONDS)
    return ExecutorRegistrationOperationEnvelope(
        operation_id=f"op_{uuid4().hex}",
        principal_id=principal_id,
        key_id=str(principal["key_id"]),
        target_id=executor_id,
        executor_key_id=executor_key_id,
        executor_public_key_b64=public_key_b64,
        executor_verifier_fingerprint=fingerprint,
        allowed_adapter_ids=allowed_adapter_ids,  # type: ignore[arg-type]
        reason=reason,
        issued_at_utc=_utc_text(issued),
        expires_at_utc=_utc_text(expires),
    )


def sign_operation(
    envelope: (
        SignedOperationEnvelope
        | CapabilityPolicyOperationEnvelope
        | ExecutionManagementOperationEnvelope
    ),
    private_key_path: Path,
) -> SignedOperation:
    try:
        loaded = serialization.load_pem_private_key(
            private_key_path.expanduser().resolve(strict=True).read_bytes(), password=None
        )
    except (OSError, ValueError, TypeError) as error:
        raise ValueError(f"Invalid private signing key: {error}") from error
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("Signing key must be an Ed25519 private key")
    key_id, _, _ = _public_key_identity(loaded.public_key())
    if key_id != envelope.key_id:
        raise ValueError("Private signing key does not match the envelope key ID")
    signature = loaded.sign(canonical_envelope_json(envelope).encode("utf-8"))
    return SignedOperation(
        envelope=envelope,
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def write_json_exclusive(path: Path, value: object) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")  # type: ignore[union-attr]
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def load_operation_envelope(
    path: Path,
) -> (
    SignedOperationEnvelope
    | CapabilityPolicyOperationEnvelope
    | ExecutionManagementOperationEnvelope
):
    try:
        value = json.loads(path.expanduser().resolve(strict=True).read_text(encoding="utf-8"))
        return TypeAdapter(
            SignedOperationEnvelope
            | CapabilityPolicyOperationEnvelope
            | DestinationBindingOperationEnvelope
            | ExecutorRegistrationOperationEnvelope
        ).validate_python(value)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as error:
        raise ValueError(f"Invalid operation envelope: {error}") from error


def _failed_evidence(signed_operation: SignedOperation | None) -> AuthenticationEvidence:
    if signed_operation is None:
        return AuthenticationEvidence(verification_status="failed")
    proof_json = canonical_json(signed_operation.model_dump(mode="json"))
    return AuthenticationEvidence(
        verification_status="failed",
        authentication_scheme=signed_operation.envelope.authentication_scheme,
        authentication_key_id=signed_operation.envelope.key_id,
        authentication_operation_id=signed_operation.envelope.operation_id,
        authentication_envelope_hash=sha256_bytes(
            canonical_envelope_json(signed_operation.envelope).encode("utf-8")
        ),
        authentication_proof_hash=sha256_bytes(proof_json.encode("utf-8")),
    )


def load_signed_operation(path: Path) -> SignedOperation:
    try:
        value = json.loads(path.expanduser().resolve(strict=True).read_text(encoding="utf-8"))
        return SignedOperation.model_validate(value)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as error:
        raise AuthenticationError(
            f"Malformed authenticated operation: {error}",
            AuthenticationEvidence(verification_status="failed"),
        ) from error


def authenticate_authority_request(
    database_path: Path,
    signed_operation: SignedOperation | None,
    *,
    now: datetime | None = None,
) -> AuthenticatedAuthorityRequest:
    database.migrate_database(database_path)
    if signed_operation is None:
        raise AuthenticationRequired(
            "Authority-sensitive transition requires an authenticated operation",
            _failed_evidence(None),
        )
    failed_evidence = _failed_evidence(signed_operation)
    envelope = signed_operation.envelope
    principal = database.get_trusted_principal(database_path, envelope.principal_id)
    if principal is None:
        raise AuthenticationError("Unknown authenticated principal", failed_evidence)
    if (
        str(principal["authentication_scheme"]) != envelope.authentication_scheme
        or str(principal["key_id"]) != envelope.key_id
    ):
        raise AuthenticationError("Principal and verification key do not match", failed_evidence)
    try:
        raw_public_key = base64.b64decode(str(principal["public_key_b64"]), validate=True)
        signature = base64.b64decode(signed_operation.signature_b64, validate=True)
    except (ValueError, binascii.Error) as error:
        raise AuthenticationError("Malformed Ed25519 authentication material", failed_evidence) from error
    if base64.b64encode(signature).decode("ascii") != signed_operation.signature_b64:
        raise AuthenticationError("Signature encoding is not canonical base64", failed_evidence)
    envelope_json = canonical_envelope_json(envelope)
    try:
        public_key = Ed25519PublicKey.from_public_bytes(raw_public_key)
        derived_key_id, derived_fingerprint, derived_public_key_b64 = _public_key_identity(
            public_key
        )
        if (
            derived_key_id != str(principal["key_id"])
            or derived_fingerprint != str(principal["verifier_fingerprint"])
            or derived_public_key_b64 != str(principal["public_key_b64"])
        ):
            raise ValueError("Stored verifier identity does not match its public key")
        public_key.verify(signature, envelope_json.encode("utf-8"))
    except (ValueError, InvalidSignature) as error:
        raise AuthenticationError("Ed25519 signature verification failed", failed_evidence) from error
    try:
        issued = _utc_datetime(envelope.issued_at_utc)
        expires = _utc_datetime(envelope.expires_at_utc)
    except ValueError as error:
        raise AuthenticationError(str(error), failed_evidence) from error
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    lifetime = (expires - issued).total_seconds()
    if lifetime <= 0 or lifetime > MAX_OPERATION_LIFETIME_SECONDS:
        raise AuthenticationError("Authenticated operation validity window is invalid", failed_evidence)
    if issued > current + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise AuthenticationError("Authenticated operation was issued in the future", failed_evidence)
    if current >= expires:
        raise AuthenticationError("Authenticated operation has expired", failed_evidence)
    proof_json = canonical_json(signed_operation.model_dump(mode="json"))
    authenticated_at = _utc_text(current)
    request: (
        TransitionRequest
        | CapabilityPolicyOperationEnvelope
        | ExecutionManagementOperationEnvelope
    )
    if isinstance(envelope, SignedOperationEnvelope):
        request = TransitionRequest.model_validate(envelope.model_dump(mode="json"))
    elif isinstance(envelope, CapabilityPolicyOperationEnvelope):
        request = CapabilityPolicyOperationEnvelope.model_validate(
            envelope.model_dump(mode="json")
        )
    elif isinstance(envelope, DestinationBindingOperationEnvelope):
        request = DestinationBindingOperationEnvelope.model_validate(
            envelope.model_dump(mode="json")
        )
    else:
        request = ExecutorRegistrationOperationEnvelope.model_validate(
            envelope.model_dump(mode="json")
        )
    request_json = canonical_envelope_json(request)
    if request_json != envelope_json:
        raise AuthenticationError(
            "Authenticated request normalization changed the signed envelope",
            failed_evidence,
        )
    authenticated = AuthenticatedPrincipal(
        principal_id=envelope.principal_id,
        authentication_scheme="ed25519",
        key_id=envelope.key_id,
        verifier_fingerprint=str(principal["verifier_fingerprint"]),
        operation_id=envelope.operation_id,
        envelope_hash=sha256_bytes(request_json.encode("utf-8")),
        proof_hash=sha256_bytes(proof_json.encode("utf-8")),
        authenticated_at_utc=authenticated_at,
    )
    if isinstance(request, TransitionRequest):
        authenticated_request: AuthenticatedAuthorityRequest = (
            AuthenticatedTransitionRequest(
                request=request,
                principal=authenticated,
                envelope_json=request_json,
                signature_b64=signed_operation.signature_b64,
            )
        )
    elif isinstance(request, CapabilityPolicyOperationEnvelope):
        authenticated_request = AuthenticatedCapabilityPolicyRequest(
            request=request,
            principal=authenticated,
            envelope_json=request_json,
            signature_b64=signed_operation.signature_b64,
        )
    else:
        authenticated_request = AuthenticatedExecutionManagementRequest(
            request=request,
            principal=authenticated,
            envelope_json=request_json,
            signature_b64=signed_operation.signature_b64,
        )
    if database.find_consumed_authenticated_operation(
        database_path, envelope.operation_id, authenticated.proof_hash
    ) is not None:
        raise ReplayDetected(
            f"Authenticated operation has already been consumed: {envelope.operation_id}",
            authenticated_request.evidence("replay_rejected"),
        )
    return authenticated_request


def authenticate_transition_request(
    database_path: Path,
    signed_operation: SignedOperation | None,
    *,
    now: datetime | None = None,
) -> AuthenticatedTransitionRequest:
    authenticated = authenticate_authority_request(
        database_path, signed_operation, now=now
    )
    if not isinstance(authenticated, AuthenticatedTransitionRequest):
        raise OperationBindingError(
            "Authenticated operation is not a packet transition",
            authenticated.evidence(),
        )
    return authenticated


def verify_signed_operation(
    database_path: Path,
    signed_operation: SignedOperation | None,
    *,
    now: datetime | None = None,
) -> AuthenticatedTransitionRequest:
    """Backward-compatible Slice 2 name for verifier-controlled construction."""
    return authenticate_transition_request(
        database_path, signed_operation, now=now
    )
