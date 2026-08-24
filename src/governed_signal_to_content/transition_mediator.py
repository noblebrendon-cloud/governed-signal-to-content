"""Single supported mediation boundary for authority-sensitive transitions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from . import database
from .authentication import (
    AuthenticationError,
    AuthenticatedCapabilityPolicyRequest,
    AuthenticatedTransitionRequest,
    OperationBindingError,
    ReplayDetected,
    authenticate_authority_request,
)
from .authorization import (
    AuthorizationRejected,
    REQUIRED_CAPABILITIES,
    not_evaluated_decision,
)
from .config import WorkspacePaths
from .models import (
    AuthorizationDecision,
    AuthorizationReason,
    AuthorityOperation,
    Capability,
    CapabilityPolicyResult,
    CapabilityPolicyOperation,
    CapabilityPolicyOperationEnvelope,
    SignedOperation,
    SignedOperationEnvelope,
    TransitionRequest,
    TransitionResult,
    WorkflowState,
)
from .packets import PacketIntegrityError, recompute_packet_manifest
from .receipts import (
    new_receipt,
    project_transition_event,
    transition_event_from_receipt,
)
from .state_machine import InvalidTransition, record_rejected_transition, validate_transition


class ApprovalProjectionError(OSError):
    """The canonical decision committed, but its human-readable export failed."""


@dataclass(frozen=True, slots=True)
class AdapterConstraints:
    """Non-authoritative compatibility assertions supplied by an application adapter."""

    operation: AuthorityOperation | None = None
    packet_id: str | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class _MediatedTransition:
    """Immutable handoff created after all current Slice 3 mediation checks."""

    authenticated: AuthenticatedTransitionRequest
    asserted_actor: str
    artifact_hashes: tuple[tuple[str, str], ...]


OPERATION_SEMANTICS = {
    AuthorityOperation.APPROVE: (
        WorkflowState.AWAITING_APPROVAL,
        WorkflowState.APPROVED,
        WorkflowState.APPROVED.value,
    ),
    AuthorityOperation.REJECT: (
        WorkflowState.AWAITING_APPROVAL,
        WorkflowState.REJECTED,
        WorkflowState.REJECTED.value,
    ),
    AuthorityOperation.RELEASE: (
        WorkflowState.APPROVED,
        WorkflowState.RELEASED,
        WorkflowState.APPROVED.value,
    ),
}


def _attach_rejection_result(
    error: Exception,
    *,
    request_id: str,
    prior: WorkflowState,
    event_id: str,
    reason: str,
) -> None:
    """Retain an explicit deterministic result without changing legacy exception types."""
    error.transition_result = TransitionResult(  # type: ignore[attr-defined]
        request_id=request_id,
        outcome="rejected",
        prior_state=prior,
        resulting_state=prior,
        canonical_event_id=event_id,
        rejection_reason=reason,
    )


def _operation_requested_state(operation: AuthorityOperation | None) -> WorkflowState:
    if operation is None:
        return WorkflowState.APPROVED
    return OPERATION_SEMANTICS[operation][1]


def _packet_scope_identifiers(request: TransitionRequest) -> dict[str, object]:
    if request.scope_version is None:
        return {}
    return {
        "scope_version": request.scope_version,
        "brand_id": request.brand_id,
        "channel_id": request.channel_id,
        "destination_id": request.destination_id,
    }


def _policy_scope_identifiers(
    request: CapabilityPolicyOperationEnvelope,
) -> dict[str, object]:
    return {
        "scope_version": request.scope_version,
        "brand_id": request.brand_id,
        "channel_id": request.channel_id,
        "destination_id": request.destination_id,
    }


def _record_policy_binding_rejection(
    paths: WorkspacePaths,
    authenticated: AuthenticatedCapabilityPolicyRequest,
    *,
    asserted_actor: str,
    error: OperationBindingError,
) -> CapabilityPolicyResult:
    request = authenticated.request
    decision = not_evaluated_decision(
        principal_id=authenticated.principal.principal_id,
        required_capability=Capability.POLICY_MANAGE_CAPABILITIES,
        reason=AuthorizationReason.REQUEST_BINDING_REJECTED,
    )
    receipt = new_receipt(
        command=request.operation.value,
        actor=asserted_actor,
        input_identifiers={
            "authentication_operation_id": request.operation_id,
            "policy_grant_id": request.grant_id,
            "subject_principal_id": request.subject_principal_id,
            "capability": request.capability.value,
            "expected_prior_state": (
                None
                if request.expected_prior_state is None
                else request.expected_prior_state.value
            ),
            "requested_state": (
                None
                if request.requested_state is None
                else request.requested_state.value
            ),
            **_policy_scope_identifiers(request),
            **(
                {}
                if request.revocation_id is None
                else {"policy_revocation_id": request.revocation_id}
            ),
        },
        prior_state=None,
        requested_transition=None,
        resulting_state=None,
        outcome="rejected",
        reason=str(error),
        authentication=authenticated.evidence(),
        authorization=decision,
    )
    event = transition_event_from_receipt(
        receipt,
        target_type=request.target_type,
        target_id=request.target_id,
    )
    database.record_transition_event(
        paths.database,
        event,
        authenticated_operation=authenticated.consumption_record(),
    )
    canonical = project_transition_event(paths.database, paths.receipt_log, receipt.run_id)
    return CapabilityPolicyResult(
        request_id=request.operation_id,
        operation=request.operation,
        outcome="rejected",
        canonical_event_id=canonical.run_id,
        grant_id=request.grant_id,
        revocation_id=request.revocation_id,
        rejection_reason=str(error),
    )


class CanonicalTransitionService:
    """Narrow transaction-time authorization and packet adjudication boundary."""

    def __init__(self, paths: WorkspacePaths) -> None:
        self._paths = paths

    def commit(
        self,
        mediated: _MediatedTransition,
    ) -> TransitionResult:
        authenticated = mediated.authenticated
        asserted_actor = mediated.asserted_actor
        artifact_hashes = dict(mediated.artifact_hashes)
        request = authenticated.request
        def event_factory(
            decision: AuthorizationDecision, accepted: bool, denial_reason: str
        ) -> dict[str, object]:
            receipt = new_receipt(
                command=request.operation.value,
                actor=asserted_actor,
                input_identifiers={
                    "packet_id": request.target_id,
                    "candidate_id": request.candidate_id,
                    "authentication_operation_id": request.operation_id,
                    "approval_id": request.approval_id,
                    "approval_decision": request.approval_decision,
                    **_packet_scope_identifiers(request),
                    **(
                        {}
                        if request.approval_transition_event_id is None
                        else {
                            "approval_transition_event_id": (
                                request.approval_transition_event_id
                            )
                        }
                    ),
                },
                prior_state=(
                    request.expected_prior_state.value
                    if decision.actual_prior_state is None
                    else decision.actual_prior_state.value
                ),
                requested_transition=request.requested_state.value,
                resulting_state=(
                    request.requested_state.value
                    if accepted
                    else (
                        request.expected_prior_state.value
                        if decision.actual_prior_state is None
                        else decision.actual_prior_state.value
                    )
                ),
                outcome="accepted" if accepted else "rejected",
                reason=request.reason if accepted else denial_reason,
                file_hashes={
                    **artifact_hashes,
                    "packet_manifest": request.packet_manifest_hash,
                },
                authentication=authenticated.evidence(),
                authorization=decision,
            )
            return transition_event_from_receipt(
                receipt,
                target_type=request.target_type,
                target_id=request.target_id,
                governed_hash=request.packet_manifest_hash,
            )

        def approval_factory(event_id: str, occurred_at_utc: str) -> dict[str, object]:
            return {
                "schema_version": "1.0",
                "approval_id": request.approval_id,
                "packet_id": request.target_id,
                "actor": asserted_actor,
                "decision": request.approval_decision,
                "reason": request.reason,
                "manifest_hash": request.packet_manifest_hash,
                "prior_state": request.expected_prior_state.value,
                "decided_at_utc": occurred_at_utc,
                "transition_event_id": event_id,
                "authenticated_principal_id": authenticated.principal.principal_id,
                "authenticated_operation_id": request.operation_id,
                "scope_version": request.scope_version,
                "brand_id": request.brand_id,
                "channel_id": request.channel_id,
                "destination_id": request.destination_id,
            }
        is_release = request.operation is AuthorityOperation.RELEASE
        stored, decision, accepted = database._commit_authority_transition(
            self._paths.database,
            operation=request.operation.value,
            packet_id=request.target_id,
            candidate_id=request.candidate_id,
            prior_state=request.expected_prior_state.value,
            resulting_state=request.requested_state.value,
            event_factory=event_factory,
            authenticated_operation=authenticated.consumption_record(),
            approval_factory=(
                approval_factory
                if request.operation
                in {AuthorityOperation.APPROVE, AuthorityOperation.REJECT}
                else None
            ),
            required_packet_manifest=request.packet_manifest_hash,
            required_approval_manifest=(
                request.packet_manifest_hash if is_release else None
            ),
            required_approval_id=request.approval_id if is_release else None,
            required_approval_event_id=(
                request.approval_transition_event_id if is_release else None
            ),
            request_scope_version=request.scope_version,
            request_brand_id=request.brand_id,
            request_channel_id=request.channel_id,
            request_destination_id=request.destination_id,
        )
        event_id = str(stored["event_id"])
        receipt = project_transition_event(
            self._paths.database, self._paths.receipt_log, event_id
        )
        if not accepted:
            error = AuthorizationRejected(decision)  # type: ignore[arg-type]
            _attach_rejection_result(
                error,
                request_id=request.operation_id,
                prior=(
                    request.expected_prior_state
                    if decision.actual_prior_state is None  # type: ignore[union-attr]
                    else decision.actual_prior_state  # type: ignore[union-attr]
                ),
                event_id=event_id,
                reason=str(error),
            )
            raise error
        if request.operation in {AuthorityOperation.APPROVE, AuthorityOperation.REJECT}:
            approval = approval_factory(event_id, receipt.timestamp_utc)
            projection = {**approval, "run_id": receipt.run_id}
            output = self._paths.approvals / f"{request.approval_id}.json"
            try:
                with output.open("x", encoding="utf-8", newline="\n") as stream:
                    stream.write(
                        json.dumps(
                            projection,
                            ensure_ascii=False,
                            indent=2,
                            sort_keys=True,
                        )
                        + "\n"
                    )
            except OSError as error:
                raise ApprovalProjectionError(
                    f"Canonical approval {request.approval_id} committed; "
                    f"JSON approval projection failed: {error}"
                ) from error
        return TransitionResult(
            request_id=request.operation_id,
            outcome="accepted",
            prior_state=request.expected_prior_state,
            resulting_state=request.requested_state,
            canonical_event_id=event_id,
        )


class CapabilityPolicyService:
    """Canonical transaction boundary for authenticated policy mutations."""

    def __init__(self, paths: WorkspacePaths) -> None:
        self._paths = paths

    def commit(
        self,
        authenticated: AuthenticatedCapabilityPolicyRequest,
        *,
        asserted_actor: str,
    ) -> CapabilityPolicyResult:
        request = authenticated.request

        def event_factory(
            decision: AuthorizationDecision, accepted: bool, denial_reason: str
        ) -> dict[str, object]:
            identifiers: dict[str, object] = {
                "authentication_operation_id": request.operation_id,
                "policy_grant_id": request.grant_id,
                "subject_principal_id": request.subject_principal_id,
                "capability": request.capability.value,
                "expected_prior_state": (
                    None
                    if request.expected_prior_state is None
                    else request.expected_prior_state.value
                ),
                "requested_state": (
                    None if request.requested_state is None else request.requested_state.value
                ),
                **_policy_scope_identifiers(request),
            }
            if request.revocation_id is not None:
                identifiers["policy_revocation_id"] = request.revocation_id
            receipt = new_receipt(
                command=request.operation.value,
                actor=asserted_actor,
                input_identifiers=identifiers,
                prior_state=None,
                requested_transition=None,
                resulting_state=None,
                outcome="accepted" if accepted else "rejected",
                reason=request.reason if accepted else denial_reason,
                authentication=authenticated.evidence(),
                authorization=decision,
            )
            return transition_event_from_receipt(
                receipt,
                target_type=request.target_type,
                target_id=request.target_id,
            )

        stored, decision, accepted = database._commit_capability_policy_operation(
            self._paths.database,
            request=request.model_dump(mode="json"),
            authenticated_operation=authenticated.consumption_record(),
            event_factory=event_factory,
        )
        event_id = str(stored["event_id"])
        project_transition_event(self._paths.database, self._paths.receipt_log, event_id)
        result = CapabilityPolicyResult(
            request_id=request.operation_id,
            operation=request.operation,
            outcome="accepted" if accepted else "rejected",
            canonical_event_id=event_id,
            grant_id=request.grant_id,
            revocation_id=request.revocation_id,
            rejection_reason=None if accepted else f"Authorization denied: {decision.reason.value}",  # type: ignore[union-attr]
        )
        if not accepted:
            error = AuthorizationRejected(decision)  # type: ignore[arg-type]
            error.policy_result = result  # type: ignore[attr-defined]
            raise error
        return result


class CapabilityPolicyMediator:
    """Authenticate and mediate the capability-policy request variant."""

    def __init__(self, paths: WorkspacePaths) -> None:
        self._paths = paths
        self._committer = CapabilityPolicyService(paths)

    def mediate_signed(
        self,
        signed_operation: SignedOperation | None,
        *,
        asserted_actor: str,
        expected_operation: CapabilityPolicyOperation | None = None,
    ) -> CapabilityPolicyResult:
        try:
            authenticated = authenticate_authority_request(
                self._paths.database, signed_operation
            )
        except AuthenticationError as error:
            self._record_authentication_rejection(
                error,
                signed_operation=signed_operation,
                asserted_actor=asserted_actor,
            )
            raise
        if not isinstance(authenticated, AuthenticatedCapabilityPolicyRequest):
            error = OperationBindingError(
                "Authenticated operation is not a capability-policy request",
                authenticated.evidence(),
            )
            packet = database.get_packet(
                self._paths.database, authenticated.request.target_id
            )
            prior = (
                authenticated.request.expected_prior_state
                if packet is None
                else WorkflowState(str(packet["state"]))
            )
            TransitionMediator(self._paths)._reject_authenticated(
                error,
                authenticated,
                asserted_actor=asserted_actor,
                prior=prior,
            )
            raise error  # pragma: no cover - rejection helper always raises
        if (
            expected_operation is not None
            and authenticated.request.operation is not expected_operation
        ):
            error = OperationBindingError(
                "Capability-policy operation does not match the application adapter",
                authenticated.evidence(),
            )
            error.policy_result = _record_policy_binding_rejection(  # type: ignore[attr-defined]
                self._paths,
                authenticated,
                asserted_actor=asserted_actor,
                error=error,
            )
            raise error
        return self._committer.commit(authenticated, asserted_actor=asserted_actor)

    def _record_authentication_rejection(
        self,
        error: AuthenticationError,
        *,
        signed_operation: SignedOperation | None,
        asserted_actor: str,
    ) -> None:
        envelope = None if signed_operation is None else signed_operation.envelope
        if not isinstance(envelope, CapabilityPolicyOperationEnvelope):
            return
        identifiers: dict[str, object] = {
            "authentication_operation_id": envelope.operation_id,
            "policy_grant_id": envelope.grant_id,
            "subject_principal_id": envelope.subject_principal_id,
            "capability": envelope.capability.value,
            "expected_prior_state": (
                None
                if envelope.expected_prior_state is None
                else envelope.expected_prior_state.value
            ),
            "requested_state": (
                None
                if envelope.requested_state is None
                else envelope.requested_state.value
            ),
            **_policy_scope_identifiers(envelope),
        }
        if envelope.revocation_id is not None:
            identifiers["policy_revocation_id"] = envelope.revocation_id
        receipt = new_receipt(
            command=envelope.operation.value,
            actor=asserted_actor,
            input_identifiers=identifiers,
            prior_state=None,
            requested_transition=None,
            resulting_state=None,
            outcome="rejected",
            reason=str(error),
            authentication=error.evidence,
            authorization=(
                None
                if not isinstance(error, ReplayDetected)
                or error.evidence.authenticated_principal_id is None
                else not_evaluated_decision(
                    principal_id=error.evidence.authenticated_principal_id,
                    required_capability=Capability.POLICY_MANAGE_CAPABILITIES,
                    reason=AuthorizationReason.REPLAY_REJECTED,
                )
            ),
        )
        event = transition_event_from_receipt(
            receipt,
            target_type="capability_policy",
            target_id="capability_policy",
        )
        database.record_transition_event(self._paths.database, event)
        project_transition_event(
            self._paths.database, self._paths.receipt_log, receipt.run_id
        )


class TransitionMediator:
    """Authenticate, adjudicate, and route one exact request to canonical commit."""

    def __init__(self, paths: WorkspacePaths) -> None:
        self._paths = paths
        self._committer = CanonicalTransitionService(paths)

    def mediate_signed(
        self,
        signed_operation: SignedOperation | None,
        *,
        asserted_actor: str,
        constraints: AdapterConstraints | None = None,
    ) -> TransitionResult:
        constraints = constraints or AdapterConstraints()
        try:
            authenticated = authenticate_authority_request(
                self._paths.database, signed_operation
            )
        except AuthenticationError as error:
            self._record_authentication_rejection(
                error,
                signed_operation=signed_operation,
                asserted_actor=asserted_actor,
                constraints=constraints,
            )
            raise
        if isinstance(authenticated, AuthenticatedCapabilityPolicyRequest):
            error = OperationBindingError(
                "Authenticated operation is not a packet transition",
                authenticated.evidence(),
            )
            error.policy_result = _record_policy_binding_rejection(  # type: ignore[attr-defined]
                self._paths,
                authenticated,
                asserted_actor=asserted_actor,
                error=error,
            )
            raise error
        return self._mediate_authenticated(
            authenticated,
            asserted_actor=asserted_actor,
            constraints=constraints,
        )

    def _record_authentication_rejection(
        self,
        error: AuthenticationError,
        *,
        signed_operation: SignedOperation | None,
        asserted_actor: str,
        constraints: AdapterConstraints,
    ) -> None:
        envelope = None if signed_operation is None else signed_operation.envelope
        if envelope is not None and not isinstance(envelope, SignedOperationEnvelope):
            return
        trusted_envelope = isinstance(error, ReplayDetected)
        packet_id = (
            envelope.target_id
            if trusted_envelope and envelope is not None
            else constraints.packet_id
            or (None if envelope is None else envelope.target_id)
        )
        if packet_id is None:
            return
        packet = database.get_packet(self._paths.database, packet_id)
        if packet is None:
            return
        prior = WorkflowState(str(packet["state"]))
        operation = constraints.operation or (
            None if envelope is None else envelope.operation
        )
        requested = (
            _operation_requested_state(operation)
            if envelope is None
            else envelope.requested_state
        )
        input_identifiers = {
            "packet_id": packet_id,
            "candidate_id": str(packet["candidate_id"]),
        }
        if trusted_envelope and envelope is not None:
            input_identifiers.update(
                {
                    "authentication_operation_id": envelope.operation_id,
                    "approval_id": envelope.approval_id,
                    "approval_decision": envelope.approval_decision,
                    **_packet_scope_identifiers(envelope),
                }
            )
            if envelope.approval_transition_event_id is not None:
                input_identifiers["approval_transition_event_id"] = (
                    envelope.approval_transition_event_id
                )
        receipt = record_rejected_transition(
            database_path=self._paths.database,
            receipt_log=self._paths.receipt_log,
            command="authenticate" if operation is None else operation.value,
            actor=asserted_actor,
            input_identifiers=input_identifiers,
            prior_state=prior,
            requested=requested,
            reason=str(error),
            authentication=error.evidence,
            authorization=(
                None
                if not trusted_envelope
                or envelope is None
                or error.evidence.authenticated_principal_id is None
                else not_evaluated_decision(
                    principal_id=error.evidence.authenticated_principal_id,
                    required_capability=REQUIRED_CAPABILITIES[envelope.operation][0],
                    actual_prior_state=prior,
                    requested_state=envelope.requested_state,
                    brand_id=envelope.brand_id,
                    channel_id=envelope.channel_id,
                    destination_id=envelope.destination_id,
                    reason=AuthorizationReason.REPLAY_REJECTED,
                )
            ),
        )
        request_id = (
            error.evidence.authentication_operation_id
            or ("untrusted" if envelope is None else envelope.operation_id)
        )
        _attach_rejection_result(
            error,
            request_id=request_id,
            prior=prior,
            event_id=receipt.run_id,
            reason=str(error),
        )

    def _reject_authenticated(
        self,
        error: Exception,
        authenticated: AuthenticatedTransitionRequest,
        *,
        asserted_actor: str,
        prior: WorkflowState,
        file_hashes: dict[str, str] | None = None,
    ) -> None:
        request = authenticated.request
        governed_hash = (
            request.packet_manifest_hash
            if file_hashes is None
            else file_hashes.get(
                "packet_manifest_recomputed", request.packet_manifest_hash
            )
        )

        def event_factory(decision: AuthorizationDecision) -> dict[str, object]:
            receipt = new_receipt(
                command=request.operation.value,
                actor=asserted_actor,
                input_identifiers={
                    "packet_id": request.target_id,
                    "candidate_id": request.candidate_id,
                    "authentication_operation_id": request.operation_id,
                    "approval_id": request.approval_id,
                    "approval_decision": request.approval_decision,
                    **_packet_scope_identifiers(request),
                    **(
                        {}
                        if request.approval_transition_event_id is None
                        else {
                            "approval_transition_event_id": (
                                request.approval_transition_event_id
                            )
                        }
                    ),
                },
                prior_state=prior.value,
                requested_transition=request.requested_state.value,
                resulting_state=prior.value,
                outcome="rejected",
                reason=str(error),
                file_hashes=file_hashes,
                authentication=authenticated.evidence(),
                authorization=decision,
            )
            return transition_event_from_receipt(
                receipt,
                target_type=request.target_type,
                target_id=request.target_id,
                governed_hash=governed_hash,
            )

        stored, _ = database.record_authenticated_authorization_rejection(
            self._paths.database,
            operation=request.operation.value,
            principal_id=authenticated.principal.principal_id,
            actual_prior_state=prior.value,
            requested_state=request.requested_state.value,
            packet_id=request.target_id,
            request_scope_version=request.scope_version,
            request_brand_id=request.brand_id,
            request_channel_id=request.channel_id,
            request_destination_id=request.destination_id,
            authenticated_operation=authenticated.consumption_record(),
            event_factory=event_factory,
        )
        receipt = project_transition_event(
            self._paths.database,
            self._paths.receipt_log,
            str(stored["event_id"]),
        )
        _attach_rejection_result(
            error,
            request_id=request.operation_id,
            prior=prior,
            event_id=receipt.run_id,
            reason=str(error),
        )
        raise error

    def _binding_error(
        self,
        reason: str,
        authenticated: AuthenticatedTransitionRequest,
        *,
        asserted_actor: str,
        prior: WorkflowState,
        file_hashes: dict[str, str] | None = None,
    ) -> None:
        self._reject_authenticated(
            OperationBindingError(reason, authenticated.evidence()),
            authenticated,
            asserted_actor=asserted_actor,
            prior=prior,
            file_hashes=file_hashes,
        )

    def _mediate_authenticated(
        self,
        authenticated: AuthenticatedTransitionRequest,
        *,
        asserted_actor: str,
        constraints: AdapterConstraints,
    ) -> TransitionResult:
        request = authenticated.request
        semantic_prior, semantic_requested, semantic_decision = OPERATION_SEMANTICS[
            request.operation
        ]
        adapter_mismatches: list[str] = []
        if constraints.operation is not None and constraints.operation is not request.operation:
            adapter_mismatches.append("operation")
        if constraints.packet_id is not None and constraints.packet_id != request.target_id:
            adapter_mismatches.append("packet_id")
        if constraints.reason is not None and constraints.reason != request.reason:
            adapter_mismatches.append("reason")

        packet = database.get_packet(self._paths.database, request.target_id)
        prior = (
            request.expected_prior_state
            if packet is None
            else WorkflowState(str(packet["state"]))
        )
        if adapter_mismatches:
            self._binding_error(
                "Application adapter binding mismatch with authenticated request: "
                + ", ".join(sorted(adapter_mismatches)),
                authenticated,
                asserted_actor=asserted_actor,
                prior=prior,
            )

        provenance_mismatches: list[str] = []
        if request.operation_id != authenticated.principal.operation_id:
            provenance_mismatches.append("operation_id")
        if request.principal_id != authenticated.principal.principal_id:
            provenance_mismatches.append("principal_id")
        if request.key_id != authenticated.principal.key_id:
            provenance_mismatches.append("key_id")
        if request.authentication_scheme != authenticated.principal.authentication_scheme:
            provenance_mismatches.append("authentication_scheme")
        if provenance_mismatches:
            self._binding_error(
                "Authenticated request provenance mismatch: "
                + ", ".join(sorted(provenance_mismatches)),
                authenticated,
                asserted_actor=asserted_actor,
                prior=prior,
            )

        semantic_mismatches: list[str] = []
        if request.expected_prior_state is not semantic_prior:
            semantic_mismatches.append("expected_prior_state")
        if request.requested_state is not semantic_requested:
            semantic_mismatches.append("requested_state")
        if request.approval_decision != semantic_decision:
            semantic_mismatches.append("approval_decision")
        if (
            request.operation is not AuthorityOperation.RELEASE
            and request.approval_transition_event_id is not None
        ):
            semantic_mismatches.append("approval_transition_event_id")
        if request.operation is not AuthorityOperation.RELEASE and (
            not request.approval_id.startswith("appr_")
            or len(request.approval_id) != len("appr_") + 32
        ):
            semantic_mismatches.append("approval_id")
        if semantic_mismatches:
            self._binding_error(
                "Authenticated request semantics are invalid: "
                + ", ".join(sorted(semantic_mismatches)),
                authenticated,
                asserted_actor=asserted_actor,
                prior=prior,
            )

        if packet is None:
            self._binding_error(
                f"Authenticated request targets unknown packet: {request.target_id}",
                authenticated,
                asserted_actor=asserted_actor,
                prior=prior,
            )
        assert packet is not None
        candidate = database.get_candidate(self._paths.database, request.candidate_id)
        identity_mismatches: list[str] = []
        if str(packet["candidate_id"]) != request.candidate_id:
            identity_mismatches.append("candidate_id")
        if candidate is None:
            identity_mismatches.append("candidate_missing")
        elif str(candidate["state"]) != prior.value:
            identity_mismatches.append("candidate_state")
        if identity_mismatches:
            self._binding_error(
                "Authenticated request object binding mismatch: "
                + ", ".join(sorted(identity_mismatches)),
                authenticated,
                asserted_actor=asserted_actor,
                prior=prior,
            )
        if prior is not request.expected_prior_state:
            self._binding_error(
                f"Authenticated request expected {request.expected_prior_state.value} "
                f"but current packet state is {prior.value}",
                authenticated,
                asserted_actor=asserted_actor,
                prior=prior,
            )
        try:
            validate_transition(prior, request.requested_state)
        except InvalidTransition as error:
            self._reject_authenticated(
                error,
                authenticated,
                asserted_actor=asserted_actor,
                prior=prior,
            )

        artifact_hashes = self._verify_artifacts(
            authenticated,
            packet=packet,
            asserted_actor=asserted_actor,
            prior=prior,
        )
        if request.operation is AuthorityOperation.RELEASE:
            self._verify_release_approval(
                authenticated,
                asserted_actor=asserted_actor,
                prior=prior,
                artifact_hashes=artifact_hashes,
            )
        return self._committer.commit(
            _MediatedTransition(
                authenticated=authenticated,
                asserted_actor=asserted_actor,
                artifact_hashes=tuple(sorted(artifact_hashes.items())),
            )
        )

    def _verify_artifacts(
        self,
        authenticated: AuthenticatedTransitionRequest,
        *,
        packet: dict[str, object],
        asserted_actor: str,
        prior: WorkflowState,
    ) -> dict[str, str]:
        request = authenticated.request
        stored_manifest = str(packet["manifest_hash"])
        try:
            artifact_hashes, recomputed_manifest = recompute_packet_manifest(packet)
        except PacketIntegrityError as error:
            reason = f"Packet integrity verification failed: {error}"
            hashes = dict(error.artifact_hashes)
            if error.manifest_hash is not None:
                hashes["packet_manifest_recomputed"] = error.manifest_hash
            hashes["packet_manifest_stored"] = stored_manifest
            rejected = PacketIntegrityError(
                reason,
                artifact_hashes=error.artifact_hashes,
                manifest_hash=error.manifest_hash,
            )
            self._reject_authenticated(
                rejected,
                authenticated,
                asserted_actor=asserted_actor,
                prior=prior,
                file_hashes=hashes,
            )
        if (
            recomputed_manifest != stored_manifest
            or request.packet_manifest_hash != recomputed_manifest
            or request.packet_receipt_hash != artifact_hashes["packet_receipt.json"]
        ):
            hashes = {
                **artifact_hashes,
                "packet_manifest_recomputed": recomputed_manifest,
                "packet_manifest_stored": stored_manifest,
                "packet_manifest_signed": request.packet_manifest_hash,
                "packet_receipt_signed": request.packet_receipt_hash,
            }
            self._binding_error(
                "Authenticated request does not bind the current packet identity",
                authenticated,
                asserted_actor=asserted_actor,
                prior=prior,
                file_hashes=hashes,
            )
        return artifact_hashes

    def _verify_release_approval(
        self,
        authenticated: AuthenticatedTransitionRequest,
        *,
        asserted_actor: str,
        prior: WorkflowState,
        artifact_hashes: dict[str, str],
    ) -> None:
        request = authenticated.request
        approval = database.get_approved_approval(
            self._paths.database, request.target_id
        )
        approval_event_id = (
            None
            if approval is None or approval.get("transition_event_id") is None
            else str(approval["transition_event_id"])
        )
        approval_receipt_hash: str | None = None
        if approval_event_id is not None:
            approval_event = database.get_transition_event(
                self._paths.database, approval_event_id
            )
            if approval_event is not None:
                approved_file_hashes = json.loads(
                    str(approval_event["file_hashes_json"])
                )
                approval_receipt_hash = approved_file_hashes.get(
                    "packet_receipt.json"
                )
        mismatches: list[str] = []
        if approval is None:
            mismatches.append("approval_missing")
        else:
            if str(approval["approval_id"]) != request.approval_id:
                mismatches.append("approval_id")
            if approval_event_id != request.approval_transition_event_id:
                mismatches.append("approval_transition_event_id")
            if str(approval["manifest_hash"]) != request.packet_manifest_hash:
                mismatches.append("approval_manifest")
            if str(approval["decision"]) != WorkflowState.APPROVED.value:
                mismatches.append("approval_decision")
        if (
            approval_event_id is not None
            and approval_receipt_hash != artifact_hashes["packet_receipt.json"]
        ):
            mismatches.append("approval_packet_receipt")
        if mismatches:
            hashes = {
                **artifact_hashes,
                "packet_manifest_signed": request.packet_manifest_hash,
            }
            self._reject_authenticated(
                PacketIntegrityError(
                    "Release approval binding mismatch: "
                    + ", ".join(sorted(mismatches))
                ),
                authenticated,
                asserted_actor=asserted_actor,
                prior=prior,
                file_hashes=hashes,
            )


def mediate_signed_transition(
    *,
    paths: WorkspacePaths,
    signed_operation: SignedOperation | None,
    asserted_actor: str,
    expected_operation: AuthorityOperation | None = None,
    expected_packet_id: str | None = None,
    expected_reason: str | None = None,
) -> TransitionResult:
    """Supported application entry point for all authority-sensitive transitions."""
    return TransitionMediator(paths).mediate_signed(
        signed_operation,
        asserted_actor=asserted_actor,
        constraints=AdapterConstraints(
            operation=expected_operation,
            packet_id=expected_packet_id,
            reason=expected_reason,
        ),
    )


def mediate_signed_policy_operation(
    *,
    paths: WorkspacePaths,
    signed_operation: SignedOperation | None,
    asserted_actor: str,
    expected_operation: CapabilityPolicyOperation | None = None,
) -> CapabilityPolicyResult:
    """Supported application entry point for capability-policy mutations."""
    return CapabilityPolicyMediator(paths).mediate_signed(
        signed_operation,
        asserted_actor=asserted_actor,
        expected_operation=expected_operation,
    )
