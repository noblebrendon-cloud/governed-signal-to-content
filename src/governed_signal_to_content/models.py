"""Validated records crossing the governed workflow boundary."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator


SCOPE_VERSION = "1.0"
SCOPE_ID_PATTERN = r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$"
SENSITIVE_SCOPE_COMPONENTS = frozenset(
    {
        "cookie",
        "credential",
        "oauth",
        "password",
        "secret",
        "token",
    }
)
RESERVED_SCOPE_COMPONENTS = frozenset(
    {"all", "any", "default", "global", "none", "null", "wildcard"}
)


class WorkflowState(str, Enum):
    DISCOVERED = "DISCOVERED"
    EVIDENCE_PRESERVED = "EVIDENCE_PRESERVED"
    NORMALIZED = "NORMALIZED"
    DUPLICATE_CHECKED = "DUPLICATE_CHECKED"
    QUALIFIED = "QUALIFIED"
    PACKET_GENERATED = "PACKET_GENERATED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    RELEASED = "RELEASED"
    SUPPRESSED = "SUPPRESSED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FrozenStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthorityOperation(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    RELEASE = "release"


class Capability(str, Enum):
    PACKET_APPROVE = "packet.approve"
    PACKET_REJECT = "packet.reject"
    PACKET_RELEASE = "packet.release"
    POLICY_MANAGE_CAPABILITIES = "policy.manage_capabilities"
    EFFECT_MANAGE_BINDINGS = "effect.manage_bindings"


class CapabilityPolicyOperation(str, Enum):
    BOOTSTRAP = "bootstrap-capability-policy"
    GRANT = "grant-capability"
    REVOKE = "revoke-capability"


class ExecutionManagementOperation(str, Enum):
    REGISTER_DESTINATION_BINDING = "register-destination-binding"
    REGISTER_EFFECT_EXECUTOR = "register-effect-executor"


class ExternalEffectOutcome(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class AuthorizationStatus(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    NOT_EVALUATED = "not_evaluated"


class AuthorizationReason(str, Enum):
    ACTIVE_GRANT = "ACTIVE_GRANT"
    BOOTSTRAP_ALLOWED = "BOOTSTRAP_ALLOWED"
    NO_ACTIVE_GRANT = "NO_ACTIVE_GRANT"
    CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
    STATE_SCOPE_MISMATCH = "STATE_SCOPE_MISMATCH"
    GRANT_REVOKED = "GRANT_REVOKED"
    UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
    POLICY_NOT_BOOTSTRAPPED = "POLICY_NOT_BOOTSTRAPPED"
    POLICY_ALREADY_BOOTSTRAPPED = "POLICY_ALREADY_BOOTSTRAPPED"
    UNKNOWN_SUBJECT_PRINCIPAL = "UNKNOWN_SUBJECT_PRINCIPAL"
    UNKNOWN_GRANT = "UNKNOWN_GRANT"
    GRANT_BINDING_MISMATCH = "GRANT_BINDING_MISMATCH"
    GRANT_ALREADY_REVOKED = "GRANT_ALREADY_REVOKED"
    LAST_POLICY_ADMIN = "LAST_POLICY_ADMIN"
    REQUEST_BINDING_REJECTED = "REQUEST_BINDING_REJECTED"
    REPLAY_REJECTED = "REPLAY_REJECTED"
    SCOPE_REQUIRED = "SCOPE_REQUIRED"
    REQUEST_SCOPE_MISMATCH = "REQUEST_SCOPE_MISMATCH"
    BRAND_SCOPE_MISMATCH = "BRAND_SCOPE_MISMATCH"
    CHANNEL_SCOPE_MISMATCH = "CHANNEL_SCOPE_MISMATCH"
    DESTINATION_SCOPE_MISMATCH = "DESTINATION_SCOPE_MISMATCH"
    NO_ACTIVE_SCOPED_GRANT = "NO_ACTIVE_SCOPED_GRANT"
    LEGACY_UNSCOPED_GRANT = "LEGACY_UNSCOPED_GRANT"


class PacketScope(FrozenStrictModel):
    scope_version: Literal["1.0"] = "1.0"
    brand_id: str = Field(min_length=1, max_length=64, pattern=SCOPE_ID_PATTERN)
    channel_id: str = Field(min_length=1, max_length=64, pattern=SCOPE_ID_PATTERN)
    destination_id: str = Field(
        min_length=1, max_length=64, pattern=SCOPE_ID_PATTERN
    )

    @model_validator(mode="after")
    def reject_credential_shaped_identifiers(self) -> PacketScope:
        for field, value in (
            ("brand_id", self.brand_id),
            ("channel_id", self.channel_id),
            ("destination_id", self.destination_id),
        ):
            normalized = value.replace("_", "-").replace(".", "-")
            components = frozenset(normalized.split("-"))
            if components & RESERVED_SCOPE_COMPONENTS:
                raise ValueError(
                    f"{field} contains a wildcard-like or ambiguous component"
                )
            if components & SENSITIVE_SCOPE_COMPONENTS or any(
                phrase in normalized
                for phrase in ("api-key", "private-key", "session-key")
            ):
                raise ValueError(
                    f"{field} contains a credential-related component and is not a logical scope ID"
                )
        return self


class TrustedPrincipal(FrozenStrictModel):
    principal_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    authentication_scheme: Literal["ed25519"] = "ed25519"
    key_id: str
    public_key_b64: str
    verifier_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    bootstrapped_at_utc: str


class SignedOperationEnvelope(FrozenStrictModel):
    schema_version: Literal["1.0"] = "1.0"
    operation_id: str = Field(pattern=r"^op_[0-9a-f]{32}$")
    principal_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    authentication_scheme: Literal["ed25519"] = "ed25519"
    key_id: str
    operation: AuthorityOperation
    target_type: Literal["packet"] = "packet"
    target_id: str
    candidate_id: str
    expected_prior_state: WorkflowState
    requested_state: WorkflowState
    packet_manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    packet_receipt_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_decision: Literal["APPROVED", "REJECTED"]
    approval_id: str
    approval_transition_event_id: str | None = None
    scope_version: Literal["1.0"] | None = None
    brand_id: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=SCOPE_ID_PATTERN
    )
    channel_id: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=SCOPE_ID_PATTERN
    )
    destination_id: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=SCOPE_ID_PATTERN
    )
    reason: str = Field(min_length=1)
    issued_at_utc: str
    expires_at_utc: str

    @model_validator(mode="after")
    def require_complete_packet_scope(self) -> SignedOperationEnvelope:
        values = (self.brand_id, self.channel_id, self.destination_id)
        if self.scope_version is None:
            if any(value is not None for value in values):
                raise ValueError("Legacy packet request cannot contain partial scope")
            return self
        if not all(value is not None for value in values):
            raise ValueError("Scoped packet request requires brand, channel, and destination")
        PacketScope(
            brand_id=self.brand_id,
            channel_id=self.channel_id,
            destination_id=self.destination_id,
        )
        return self


CAPABILITY_STATE_SCOPES: dict[
    Capability, tuple[WorkflowState | None, WorkflowState | None]
] = {
    Capability.PACKET_APPROVE: (
        WorkflowState.AWAITING_APPROVAL,
        WorkflowState.APPROVED,
    ),
    Capability.PACKET_REJECT: (
        WorkflowState.AWAITING_APPROVAL,
        WorkflowState.REJECTED,
    ),
    Capability.PACKET_RELEASE: (
        WorkflowState.APPROVED,
        WorkflowState.RELEASED,
    ),
    Capability.POLICY_MANAGE_CAPABILITIES: (None, None),
    Capability.EFFECT_MANAGE_BINDINGS: (None, None),
}


class CapabilityPolicyOperationEnvelope(FrozenStrictModel):
    schema_version: Literal["1.0"] = "1.0"
    operation_id: str = Field(pattern=r"^op_[0-9a-f]{32}$")
    principal_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    authentication_scheme: Literal["ed25519"] = "ed25519"
    key_id: str
    operation: CapabilityPolicyOperation
    target_type: Literal["capability_policy"] = "capability_policy"
    target_id: Literal["capability_policy"] = "capability_policy"
    grant_id: str = Field(pattern=r"^grant_[0-9a-f]{32}$")
    revocation_id: str | None = Field(
        default=None, pattern=r"^revoke_[0-9a-f]{32}$"
    )
    subject_principal_id: str = Field(
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
    )
    capability: Capability
    expected_prior_state: WorkflowState | None = None
    requested_state: WorkflowState | None = None
    scope_version: Literal["1.0"] | None = None
    brand_id: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=SCOPE_ID_PATTERN
    )
    channel_id: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=SCOPE_ID_PATTERN
    )
    destination_id: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=SCOPE_ID_PATTERN
    )
    reason: str = Field(min_length=1)
    issued_at_utc: str
    expires_at_utc: str

    @model_validator(mode="after")
    def require_canonical_policy_semantics(self) -> CapabilityPolicyOperationEnvelope:
        expected_scope = CAPABILITY_STATE_SCOPES[self.capability]
        if (self.expected_prior_state, self.requested_state) != expected_scope:
            raise ValueError("Capability policy state scope is not canonical")
        scope_values = (self.brand_id, self.channel_id, self.destination_id)
        if self.scope_version is None:
            if any(value is not None for value in scope_values):
                raise ValueError("Legacy policy operation cannot contain partial scope")
        elif self.capability in {
            Capability.POLICY_MANAGE_CAPABILITIES,
            Capability.EFFECT_MANAGE_BINDINGS,
        }:
            if any(value is not None for value in scope_values):
                raise ValueError("Policy-management capability is not packet scoped")
        elif not all(value is not None for value in scope_values):
            if any(value is not None for value in scope_values) or (
                self.operation is not CapabilityPolicyOperation.REVOKE
            ):
                raise ValueError(
                    "Operational capability grant requires brand, channel, and destination"
                )
        else:
            PacketScope(
                brand_id=self.brand_id,
                channel_id=self.channel_id,
                destination_id=self.destination_id,
            )
        if self.operation is CapabilityPolicyOperation.BOOTSTRAP:
            if (
                self.principal_id != self.subject_principal_id
                or self.capability is not Capability.POLICY_MANAGE_CAPABILITIES
                or self.revocation_id is not None
            ):
                raise ValueError("Capability-policy bootstrap semantics are invalid")
        elif self.operation is CapabilityPolicyOperation.GRANT:
            if self.revocation_id is not None:
                raise ValueError("Capability grant must not contain a revocation ID")
        elif self.revocation_id is None:
            raise ValueError("Capability revocation requires a revocation ID")
        return self


class DestinationBindingOperationEnvelope(FrozenStrictModel):
    schema_version: Literal["1.0"] = "1.0"
    operation_id: str = Field(pattern=r"^op_[0-9a-f]{32}$")
    principal_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    authentication_scheme: Literal["ed25519"] = "ed25519"
    key_id: str
    operation: Literal[
        ExecutionManagementOperation.REGISTER_DESTINATION_BINDING
    ] = ExecutionManagementOperation.REGISTER_DESTINATION_BINDING
    target_type: Literal["external_destination_binding"] = (
        "external_destination_binding"
    )
    target_id: str = Field(pattern=r"^bind_[0-9a-f]{32}$")
    scope_version: Literal["1.0"] = "1.0"
    brand_id: str = Field(min_length=1, max_length=64, pattern=SCOPE_ID_PATTERN)
    channel_id: str = Field(min_length=1, max_length=64, pattern=SCOPE_ID_PATTERN)
    destination_id: str = Field(
        min_length=1, max_length=64, pattern=SCOPE_ID_PATTERN
    )
    adapter_id: Literal["test.capture"] = "test.capture"
    external_target_ref: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:[._:-][a-z0-9]+)*$",
    )
    credential_ref: str = Field(
        min_length=6,
        max_length=64,
        pattern=r"^cred_[a-z0-9]+(?:[._-][a-z0-9]+)*$",
    )
    reason: str = Field(min_length=1)
    issued_at_utc: str
    expires_at_utc: str

    @model_validator(mode="after")
    def validate_binding_semantics(self) -> DestinationBindingOperationEnvelope:
        PacketScope(
            brand_id=self.brand_id,
            channel_id=self.channel_id,
            destination_id=self.destination_id,
        )
        for field, value in (
            ("external_target_ref", self.external_target_ref),
            ("credential_ref", self.credential_ref),
        ):
            normalized = (
                value.replace("_", "-").replace(".", "-").replace(":", "-")
            )
            components = frozenset(normalized.split("-"))
            if components & SENSITIVE_SCOPE_COMPONENTS or any(
                phrase in normalized
                for phrase in ("api-key", "private-key", "session-key")
            ):
                raise ValueError(
                    f"{field} contains credential material rather than a reference"
                )
        return self


class ExecutorRegistrationOperationEnvelope(FrozenStrictModel):
    schema_version: Literal["1.0"] = "1.0"
    operation_id: str = Field(pattern=r"^op_[0-9a-f]{32}$")
    principal_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    authentication_scheme: Literal["ed25519"] = "ed25519"
    key_id: str
    operation: Literal[ExecutionManagementOperation.REGISTER_EFFECT_EXECUTOR] = (
        ExecutionManagementOperation.REGISTER_EFFECT_EXECUTOR
    )
    target_type: Literal["trusted_effect_executor"] = "trusted_effect_executor"
    target_id: str = Field(pattern=r"^executor_[a-z0-9]+(?:[._-][a-z0-9]+)*$")
    executor_authentication_scheme: Literal["ed25519"] = "ed25519"
    executor_key_id: str
    executor_public_key_b64: str
    executor_verifier_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    allowed_adapter_ids: tuple[Literal["test.capture"], ...] = Field(min_length=1)
    reason: str = Field(min_length=1)
    issued_at_utc: str
    expires_at_utc: str

    @model_validator(mode="after")
    def require_canonical_adapter_set(self) -> ExecutorRegistrationOperationEnvelope:
        if tuple(sorted(set(self.allowed_adapter_ids))) != self.allowed_adapter_ids:
            raise ValueError(
                "Executor adapter IDs must be unique and canonically sorted"
            )
        return self


ExecutionManagementOperationEnvelope = (
    DestinationBindingOperationEnvelope | ExecutorRegistrationOperationEnvelope
)


class SignedOperation(FrozenStrictModel):
    schema_version: Literal["1.0"] = "1.0"
    envelope: (
        SignedOperationEnvelope
        | CapabilityPolicyOperationEnvelope
        | DestinationBindingOperationEnvelope
        | ExecutorRegistrationOperationEnvelope
    )
    signature_b64: str


class TransitionRequest(SignedOperationEnvelope):
    """Immutable semantic request preserving every signed envelope field."""


class AuthenticationEvidence(FrozenStrictModel):
    verification_status: Literal["verified", "failed", "replay_rejected"]
    authenticated_principal_id: str | None = None
    authentication_scheme: str | None = None
    authentication_key_id: str | None = None
    verifier_fingerprint: str | None = None
    authentication_operation_id: str | None = None
    authentication_envelope_hash: str | None = None
    authentication_proof_hash: str | None = None
    authenticated_at_utc: str | None = None


class AuthenticatedPrincipal(FrozenStrictModel):
    principal_id: str
    authentication_scheme: Literal["ed25519"]
    key_id: str
    verifier_fingerprint: str
    verification_status: Literal["verified"] = "verified"
    operation_id: str
    envelope_hash: str
    proof_hash: str
    authenticated_at_utc: str


class AuthorizationDecision(FrozenStrictModel):
    status: AuthorizationStatus
    principal_id: str
    required_capability: str
    actual_prior_state: WorkflowState | None = None
    requested_state: WorkflowState | None = None
    scope_version: Literal["1.0"] | None = None
    brand_id: str | None = None
    channel_id: str | None = None
    destination_id: str | None = None
    matching_grant_id: str | None = None
    reason: AuthorizationReason

    @model_validator(mode="after")
    def require_coherent_scope(self) -> AuthorizationDecision:
        scope_values = (self.brand_id, self.channel_id, self.destination_id)
        if self.scope_version is None:
            if any(value is not None for value in scope_values):
                raise ValueError("Authorization scope requires a scope version")
            return self
        if any(value is not None for value in scope_values) and not all(
            value is not None for value in scope_values
        ):
            raise ValueError("Authorization scope must be entirely present or absent")
        if all(value is not None for value in scope_values):
            PacketScope(
                brand_id=self.brand_id,
                channel_id=self.channel_id,
                destination_id=self.destination_id,
            )
        return self

    @property
    def allowed(self) -> bool:
        return self.status is AuthorizationStatus.ALLOWED


class TransitionResult(FrozenStrictModel):
    request_id: str
    outcome: Literal["accepted", "rejected"]
    prior_state: WorkflowState
    resulting_state: WorkflowState
    canonical_event_id: str
    rejection_reason: str | None = None


class CapabilityPolicyResult(FrozenStrictModel):
    request_id: str
    operation: CapabilityPolicyOperation
    outcome: Literal["accepted", "rejected"]
    canonical_event_id: str
    grant_id: str
    revocation_id: str | None = None
    rejection_reason: str | None = None


class ExecutionManagementResult(FrozenStrictModel):
    request_id: str
    operation: ExecutionManagementOperation
    outcome: Literal["accepted", "rejected"]
    canonical_event_id: str
    target_id: str
    rejection_reason: str | None = None


class ExternalEffectRequest(FrozenStrictModel):
    schema_version: Literal["1.0"] = "1.0"
    effect_id: str = Field(pattern=r"^effect_[0-9a-f]{32}$")
    release_event_id: str
    packet_id: str
    candidate_id: str
    approval_id: str
    approval_event_id: str
    authenticated_principal_id: str
    authorizing_grant_id: str = Field(pattern=r"^grant_[0-9a-f]{32}$")
    capability: Literal["packet.release"] = "packet.release"
    scope_version: Literal["1.0"] = "1.0"
    brand_id: str
    channel_id: str
    destination_id: str
    destination_binding_id: str = Field(pattern=r"^bind_[0-9a-f]{32}$")
    adapter_id: Literal["test.capture"]
    external_target_ref: str
    credential_ref: str = Field(
        pattern=r"^cred_[a-z0-9]+(?:[._-][a-z0-9]+)*$"
    )
    packet_manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    packet_receipt_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    release_event_sequence: int = Field(ge=1)
    idempotency_key: str = Field(pattern=r"^idem_[0-9a-f]{64}$")
    request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at_utc: str
    application_version: str
    request_event_id: str

    @model_validator(mode="after")
    def validate_effect_scope(self) -> ExternalEffectRequest:
        PacketScope(
            brand_id=self.brand_id,
            channel_id=self.channel_id,
            destination_id=self.destination_id,
        )
        return self


class ExternalEffectDispatch(FrozenStrictModel):
    schema_version: Literal["1.0"] = "1.0"
    dispatch_id: str = Field(pattern=r"^dispatch_[0-9a-f]{32}$")
    effect_id: str = Field(pattern=r"^effect_[0-9a-f]{32}$")
    effect_request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    attempt_number: int = Field(ge=1)
    claimed_at_utc: str
    application_version: str
    dispatch_event_id: str


class ExecutorResultEnvelope(FrozenStrictModel):
    schema_version: Literal["1.0"] = "1.0"
    result_id: str = Field(pattern=r"^result_[0-9a-f]{32}$")
    executor_id: str = Field(
        pattern=r"^executor_[a-z0-9]+(?:[._-][a-z0-9]+)*$"
    )
    executor_key_id: str
    effect_id: str = Field(pattern=r"^effect_[0-9a-f]{32}$")
    dispatch_id: str = Field(pattern=r"^dispatch_[0-9a-f]{32}$")
    effect_request_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    adapter_id: Literal["test.capture"]
    scope_version: Literal["1.0"] = "1.0"
    brand_id: str
    channel_id: str
    destination_id: str
    destination_binding_id: str = Field(pattern=r"^bind_[0-9a-f]{32}$")
    artifact_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    idempotency_key: str = Field(pattern=r"^idem_[0-9a-f]{64}$")
    outcome: ExternalEffectOutcome
    effect_may_have_occurred: bool
    retry_permitted: bool
    remote_reference: str | None = Field(default=None, max_length=256)
    response_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    error_code: str | None = Field(
        default=None, pattern=r"^[A-Z][A-Z0-9_]{0,63}$"
    )
    started_at_utc: str
    completed_at_utc: str

    @model_validator(mode="after")
    def require_result_semantics(self) -> ExecutorResultEnvelope:
        if self.outcome is ExternalEffectOutcome.SUCCEEDED:
            if (
                self.remote_reference is None
                or self.response_hash is None
                or self.error_code is not None
                or not self.effect_may_have_occurred
                or self.retry_permitted
            ):
                raise ValueError("Successful executor result semantics are invalid")
        elif self.outcome is ExternalEffectOutcome.FAILED:
            if (
                self.error_code is None
                or self.remote_reference is not None
                or self.response_hash is not None
                or self.effect_may_have_occurred
            ):
                raise ValueError("Failed executor result semantics are invalid")
        elif (
            self.error_code is None
            or self.retry_permitted
            or not self.effect_may_have_occurred
        ):
            raise ValueError("Unknown executor result semantics are invalid")
        PacketScope(
            brand_id=self.brand_id,
            channel_id=self.channel_id,
            destination_id=self.destination_id,
        )
        return self


class SignedExecutorResult(FrozenStrictModel):
    schema_version: Literal["1.0"] = "1.0"
    envelope: ExecutorResultEnvelope
    signature_b64: str


class EvidenceRecord(StrictModel):
    schema_version: str = "1.0"
    evidence_id: str
    candidate_id: str
    source_url: HttpUrl
    original_filename: str | None = None
    preserved_path: str | None = None
    sha256: str
    byte_size: int | None = Field(default=None, ge=0)
    ingested_at_utc: str
    content_preserved: bool


class CandidateRecord(StrictModel):
    schema_version: str = "1.0"
    candidate_id: str
    title: str = Field(min_length=1)
    source_url: HttpUrl
    normalized_url: str | None = None
    source_identity: str
    development_identifiers: list[str] = Field(default_factory=list)
    state: WorkflowState
    created_at_utc: str


class Classification(StrictModel):
    schema_version: str = "1.0"
    documented_facts: list[str] = Field(min_length=1)
    reasonable_inferences: list[str]
    direct_similarities: list[str]
    broader_industry_trends: list[str]
    primary_sources: list[HttpUrl] = Field(min_length=1)
    structural_overlap_dimensions: list[str] = Field(min_length=1)
    qualification_decision: bool
    qualification_reason: str = Field(min_length=1)


class ContentInputs(StrictModel):
    schema_version: str = "1.0"
    linkedin_analysis: str = Field(min_length=1)
    csg_facebook_post: str = Field(min_length=1)
    mermaid_diagram: str = Field(min_length=1)
    governed_operating_layers_essay: str = Field(min_length=1)
    repository_note: str = Field(min_length=1)
    sources: list[HttpUrl] = Field(min_length=1)
    scope: PacketScope


class RunReceipt(StrictModel):
    schema_version: str = "1.0"
    run_id: str
    command: str
    timestamp_utc: str
    actor: str
    input_identifiers: dict[str, Any]
    prior_state: str | None
    requested_transition: str | None
    resulting_state: str | None
    outcome: str
    reason: str
    file_hashes: dict[str, str] = Field(default_factory=dict)
    application_version: str
    authentication_status: str | None = None
    authenticated_principal_id: str | None = None
    authentication_scheme: str | None = None
    authentication_key_id: str | None = None
    authentication_verifier_fingerprint: str | None = None
    authentication_operation_id: str | None = None
    authentication_envelope_hash: str | None = None
    authentication_proof_hash: str | None = None
    authenticated_at_utc: str | None = None
    authorization_status: Literal["allowed", "denied", "not_evaluated"] | None = None
    authorization_principal_id: str | None = None
    authorization_required_capability: str | None = None
    authorization_prior_state: str | None = None
    authorization_requested_state: str | None = None
    authorization_scope_version: Literal["1.0"] | None = None
    authorization_brand_id: str | None = None
    authorization_channel_id: str | None = None
    authorization_destination_id: str | None = None
    authorization_matching_grant_id: str | None = None
    authorization_reason_code: str | None = None
    chain_version: Literal["1.0"] | None = None
    chain_origin: Literal["native"] | None = None
    event_sequence: int | None = Field(default=None, ge=1)
    previous_event_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    event_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def require_complete_chain_identity(self) -> RunReceipt:
        chain_values = (
            self.chain_version,
            self.chain_origin,
            self.event_sequence,
            self.previous_event_hash,
            self.event_hash,
        )
        if any(value is not None for value in chain_values) and not all(
            value is not None for value in chain_values
        ):
            raise ValueError("Receipt chain identity must be entirely present or absent")
        return self

    @model_validator(mode="after")
    def require_coherent_authorization_evidence(self) -> RunReceipt:
        required = (
            self.authorization_principal_id,
            self.authorization_required_capability,
            self.authorization_reason_code,
        )
        if self.authorization_status is None:
            if any(
                value is not None
                for value in (
                    *required,
                    self.authorization_prior_state,
                    self.authorization_requested_state,
                    self.authorization_scope_version,
                    self.authorization_brand_id,
                    self.authorization_channel_id,
                    self.authorization_destination_id,
                    self.authorization_matching_grant_id,
                )
            ):
                raise ValueError(
                    "Authorization evidence cannot exist without authorization status"
                )
            return self
        if not all(value is not None for value in required):
            raise ValueError("Authorization evidence is incomplete")
        if self.authentication_status not in {"verified", "replay_rejected"}:
            raise ValueError(
                "Authorization evidence requires authenticated or replay provenance"
            )
        if self.authorization_principal_id != self.authenticated_principal_id:
            raise ValueError(
                "Authorization principal must equal the authenticated principal"
            )
        scope_values = (
            self.authorization_brand_id,
            self.authorization_channel_id,
            self.authorization_destination_id,
        )
        if self.authorization_scope_version is None:
            if any(value is not None for value in scope_values):
                raise ValueError("Authorization scope requires a scope version")
        elif any(value is not None for value in scope_values) and not all(
            value is not None for value in scope_values
        ):
            raise ValueError("Authorization scope must be entirely present or absent")
        if (
            self.authorization_status == AuthorizationStatus.DENIED.value
            and self.authorization_matching_grant_id is not None
        ):
            raise ValueError("Denied authorization cannot claim a matching grant")
        return self


class IntegrityFailure(FrozenStrictModel):
    scope: Literal[
        "canonical_chain",
        "canonical_policy",
        "canonical_external_effect",
        "projection",
    ]
    code: str
    message: str
    event_id: str | None = None
    event_sequence: int | None = None
    receipt_line: int | None = None


class IntegrityVerificationResult(FrozenStrictModel):
    database_schema_version: int
    chain_version: str | None
    activation_hash: str | None
    canonical_chain_valid: bool
    native_chain_start_event_id: str | None
    events_checked: int
    legacy_events_checked: int
    native_events_checked: int
    canonical_policy_valid: bool = True
    capability_grants_checked: int = 0
    capability_revocations_checked: int = 0
    authorization_events_checked: int = 0
    canonical_external_effect_valid: bool = True
    destination_bindings_checked: int = 0
    effect_executors_checked: int = 0
    external_effect_requests_checked: int = 0
    external_effect_dispatches_checked: int = 0
    external_effect_results_checked: int = 0
    projection_valid: bool
    projection_complete: bool
    receipts_checked: int
    pending_projection_count: int
    legacy_unbound_receipt_count: int
    failures: tuple[IntegrityFailure, ...] = ()
