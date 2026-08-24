"""Deterministic principal, capability, and workflow-state authorization."""

from __future__ import annotations

import sqlite3

from .models import (
    AuthorizationDecision,
    AuthorizationReason,
    AuthorizationStatus,
    AuthorityOperation,
    Capability,
    WorkflowState,
)


REQUIRED_CAPABILITIES: dict[
    AuthorityOperation, tuple[Capability, WorkflowState, WorkflowState]
] = {
    AuthorityOperation.APPROVE: (
        Capability.PACKET_APPROVE,
        WorkflowState.AWAITING_APPROVAL,
        WorkflowState.APPROVED,
    ),
    AuthorityOperation.REJECT: (
        Capability.PACKET_REJECT,
        WorkflowState.AWAITING_APPROVAL,
        WorkflowState.REJECTED,
    ),
    AuthorityOperation.RELEASE: (
        Capability.PACKET_RELEASE,
        WorkflowState.APPROVED,
        WorkflowState.RELEASED,
    ),
}


class AuthorizationError(PermissionError):
    """An authenticated request could not be authorized."""


class AuthorizationRejected(AuthorizationError):
    def __init__(self, decision: AuthorizationDecision) -> None:
        self.decision = decision
        super().__init__(f"Authorization denied: {decision.reason.value}")


def derive_required_capability(
    operation: AuthorityOperation,
    actual_prior_state: WorkflowState,
    requested_state: WorkflowState,
) -> Capability:
    capability, expected_prior, expected_requested = REQUIRED_CAPABILITIES[operation]
    if (
        actual_prior_state is not expected_prior
        or requested_state is not expected_requested
    ):
        raise ValueError(
            "Authority operation does not match its canonical capability/state semantics"
        )
    return capability


def _decision(
    *,
    status: AuthorizationStatus,
    principal_id: str,
    required_capability: str,
    actual_prior_state: WorkflowState | None,
    requested_state: WorkflowState | None,
    reason: AuthorizationReason,
    scope_version: str | None = "1.0",
    brand_id: str | None = None,
    channel_id: str | None = None,
    destination_id: str | None = None,
    matching_grant_id: str | None = None,
) -> AuthorizationDecision:
    return AuthorizationDecision(
        status=status,
        principal_id=principal_id,
        required_capability=required_capability,
        actual_prior_state=actual_prior_state,
        requested_state=requested_state,
        scope_version=scope_version,
        brand_id=brand_id,
        channel_id=channel_id,
        destination_id=destination_id,
        matching_grant_id=matching_grant_id,
        reason=reason,
    )


def denied_decision(
    *,
    principal_id: str,
    required_capability: Capability | str,
    reason: AuthorizationReason,
    actual_prior_state: WorkflowState | None = None,
    requested_state: WorkflowState | None = None,
    brand_id: str | None = None,
    channel_id: str | None = None,
    destination_id: str | None = None,
) -> AuthorizationDecision:
    capability_value = (
        required_capability.value
        if isinstance(required_capability, Capability)
        else str(required_capability)
    )
    return _decision(
        status=AuthorizationStatus.DENIED,
        principal_id=principal_id,
        required_capability=capability_value,
        actual_prior_state=actual_prior_state,
        requested_state=requested_state,
        brand_id=brand_id,
        channel_id=channel_id,
        destination_id=destination_id,
        reason=reason,
    )


def bootstrap_decision(principal_id: str) -> AuthorizationDecision:
    return _decision(
        status=AuthorizationStatus.ALLOWED,
        principal_id=principal_id,
        required_capability=Capability.POLICY_MANAGE_CAPABILITIES.value,
        actual_prior_state=None,
        requested_state=None,
        scope_version="1.0",
        reason=AuthorizationReason.BOOTSTRAP_ALLOWED,
    )


def not_evaluated_decision(
    *,
    principal_id: str,
    required_capability: Capability,
    reason: AuthorizationReason,
    actual_prior_state: WorkflowState | None = None,
    requested_state: WorkflowState | None = None,
    brand_id: str | None = None,
    channel_id: str | None = None,
    destination_id: str | None = None,
) -> AuthorizationDecision:
    return _decision(
        status=AuthorizationStatus.NOT_EVALUATED,
        principal_id=principal_id,
        required_capability=required_capability.value,
        actual_prior_state=actual_prior_state,
        requested_state=requested_state,
        brand_id=brand_id,
        channel_id=channel_id,
        destination_id=destination_id,
        reason=reason,
    )


class CapabilityPolicyEvaluator:
    """Evaluate only canonical grants visible in one SQLite transaction."""

    @staticmethod
    def evaluate(
        connection: sqlite3.Connection,
        *,
        principal_id: str,
        required_capability: Capability | str,
        actual_prior_state: WorkflowState | None,
        requested_state: WorkflowState | None,
        brand_id: str | None = None,
        channel_id: str | None = None,
        destination_id: str | None = None,
    ) -> AuthorizationDecision:
        try:
            capability = (
                required_capability
                if isinstance(required_capability, Capability)
                else Capability(str(required_capability))
            )
        except ValueError:
            return denied_decision(
                principal_id=principal_id,
                required_capability=str(required_capability),
                reason=AuthorizationReason.UNKNOWN_CAPABILITY,
                actual_prior_state=actual_prior_state,
                requested_state=requested_state,
                brand_id=brand_id,
                channel_id=channel_id,
                destination_id=destination_id,
            )

        packet_scoped = capability in {
            Capability.PACKET_APPROVE,
            Capability.PACKET_REJECT,
            Capability.PACKET_RELEASE,
        }
        if packet_scoped and None in (brand_id, channel_id, destination_id):
            return denied_decision(
                principal_id=principal_id,
                required_capability=capability,
                reason=AuthorizationReason.SCOPE_REQUIRED,
                actual_prior_state=actual_prior_state,
                requested_state=requested_state,
            )
        if not packet_scoped and any(
            value is not None for value in (brand_id, channel_id, destination_id)
        ):
            return denied_decision(
                principal_id=principal_id,
                required_capability=capability,
                reason=AuthorizationReason.REQUEST_SCOPE_MISMATCH,
                actual_prior_state=actual_prior_state,
                requested_state=requested_state,
            )

        policy_state = connection.execute(
            "SELECT singleton_id FROM capability_policy_state WHERE singleton_id = 1"
        ).fetchone()
        if policy_state is None:
            return denied_decision(
                principal_id=principal_id,
                required_capability=capability,
                reason=AuthorizationReason.POLICY_NOT_BOOTSTRAPPED,
                actual_prior_state=actual_prior_state,
                requested_state=requested_state,
                brand_id=brand_id,
                channel_id=channel_id,
                destination_id=destination_id,
            )

        rows = connection.execute(
            """
            SELECT g.*, c.event_sequence,
                   CASE WHEN r.revocation_id IS NULL THEN 0 ELSE 1 END AS revoked
            FROM capability_grants AS g
            JOIN transition_event_chain_entries AS c
              ON c.event_id = g.policy_event_id
            LEFT JOIN capability_revocations AS r ON r.grant_id = g.grant_id
            WHERE g.subject_principal_id = ?
            ORDER BY c.event_sequence, g.grant_id
            """,
            (principal_id,),
        ).fetchall()
        if not rows:
            return denied_decision(
                principal_id=principal_id,
                required_capability=capability,
                reason=AuthorizationReason.NO_ACTIVE_GRANT,
                actual_prior_state=actual_prior_state,
                requested_state=requested_state,
                brand_id=brand_id,
                channel_id=channel_id,
                destination_id=destination_id,
            )

        capability_rows = [row for row in rows if row["capability"] == capability.value]
        if not capability_rows:
            return denied_decision(
                principal_id=principal_id,
                required_capability=capability,
                reason=AuthorizationReason.CAPABILITY_MISMATCH,
                actual_prior_state=actual_prior_state,
                requested_state=requested_state,
                brand_id=brand_id,
                channel_id=channel_id,
                destination_id=destination_id,
            )
        exact_rows = [
            row
            for row in capability_rows
            if row["expected_prior_state"]
            == (None if actual_prior_state is None else actual_prior_state.value)
            and row["requested_state"]
            == (None if requested_state is None else requested_state.value)
        ]
        if not exact_rows:
            return denied_decision(
                principal_id=principal_id,
                required_capability=capability,
                reason=AuthorizationReason.STATE_SCOPE_MISMATCH,
                actual_prior_state=actual_prior_state,
                requested_state=requested_state,
                brand_id=brand_id,
                channel_id=channel_id,
                destination_id=destination_id,
            )
        if packet_scoped:
            legacy_rows = [
                row
                for row in exact_rows
                if row["scope_version"] is None
                and row["brand_id"] is None
                and row["channel_id"] is None
                and row["destination_id"] is None
            ]
            scoped_rows = [row for row in exact_rows if row["scope_version"] == "1.0"]
            if not scoped_rows and legacy_rows:
                return denied_decision(
                    principal_id=principal_id,
                    required_capability=capability,
                    reason=AuthorizationReason.LEGACY_UNSCOPED_GRANT,
                    actual_prior_state=actual_prior_state,
                    requested_state=requested_state,
                    brand_id=brand_id,
                    channel_id=channel_id,
                    destination_id=destination_id,
                )
            brand_rows = [row for row in scoped_rows if row["brand_id"] == brand_id]
            if not brand_rows:
                return denied_decision(
                    principal_id=principal_id,
                    required_capability=capability,
                    reason=AuthorizationReason.BRAND_SCOPE_MISMATCH,
                    actual_prior_state=actual_prior_state,
                    requested_state=requested_state,
                    brand_id=brand_id,
                    channel_id=channel_id,
                    destination_id=destination_id,
                )
            channel_rows = [
                row for row in brand_rows if row["channel_id"] == channel_id
            ]
            if not channel_rows:
                return denied_decision(
                    principal_id=principal_id,
                    required_capability=capability,
                    reason=AuthorizationReason.CHANNEL_SCOPE_MISMATCH,
                    actual_prior_state=actual_prior_state,
                    requested_state=requested_state,
                    brand_id=brand_id,
                    channel_id=channel_id,
                    destination_id=destination_id,
                )
            exact_scope_rows = [
                row
                for row in channel_rows
                if row["destination_id"] == destination_id
            ]
            if not exact_scope_rows:
                return denied_decision(
                    principal_id=principal_id,
                    required_capability=capability,
                    reason=AuthorizationReason.DESTINATION_SCOPE_MISMATCH,
                    actual_prior_state=actual_prior_state,
                    requested_state=requested_state,
                    brand_id=brand_id,
                    channel_id=channel_id,
                    destination_id=destination_id,
                )
        else:
            exact_scope_rows = exact_rows
        active_rows = [row for row in exact_scope_rows if not bool(row["revoked"])]
        if not active_rows:
            return denied_decision(
                principal_id=principal_id,
                required_capability=capability,
                reason=AuthorizationReason.GRANT_REVOKED,
                actual_prior_state=actual_prior_state,
                requested_state=requested_state,
                brand_id=brand_id,
                channel_id=channel_id,
                destination_id=destination_id,
            )
        return _decision(
            status=AuthorizationStatus.ALLOWED,
            principal_id=principal_id,
            required_capability=capability.value,
            actual_prior_state=actual_prior_state,
            requested_state=requested_state,
            brand_id=brand_id,
            channel_id=channel_id,
            destination_id=destination_id,
            matching_grant_id=str(active_rows[0]["grant_id"]),
            reason=AuthorizationReason.ACTIVE_GRANT,
        )
