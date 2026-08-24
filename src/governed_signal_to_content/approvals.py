"""Compatibility facades into the mediated authority-transition boundary."""

from __future__ import annotations

from pathlib import Path

from .authentication import RELEASE_REASON, load_signed_operation
from .config import WorkspacePaths
from .models import AuthorityOperation, SignedOperation
from .transition_mediator import (
    ApprovalProjectionError,
    mediate_signed_transition,
)


def decide_packet(
    *,
    paths: WorkspacePaths,
    packet_id: str,
    actor: str,
    approved: bool,
    reason: str,
    signed_operation: SignedOperation | None = None,
) -> str:
    """Route legacy approval/rejection callers through the TransitionMediator."""
    operation = AuthorityOperation.APPROVE if approved else AuthorityOperation.REJECT
    result = mediate_signed_transition(
        paths=paths,
        signed_operation=signed_operation,
        asserted_actor=actor,
        expected_operation=operation,
        expected_packet_id=packet_id,
        expected_reason=reason,
    )
    return result.canonical_event_id


def release_packet(
    paths: WorkspacePaths,
    packet_id: str,
    actor: str,
    signed_operation: SignedOperation | None = None,
) -> str:
    """Route legacy release callers through the TransitionMediator."""
    result = mediate_signed_transition(
        paths=paths,
        signed_operation=signed_operation,
        asserted_actor=actor,
        expected_operation=AuthorityOperation.RELEASE,
        expected_packet_id=packet_id,
        expected_reason=RELEASE_REASON,
    )
    return result.canonical_event_id


def load_authenticated_operation(path: Path | None) -> SignedOperation | None:
    if path is None:
        return None
    return load_signed_operation(path)


__all__ = [
    "ApprovalProjectionError",
    "decide_packet",
    "load_authenticated_operation",
    "release_packet",
]
