from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import pytest

from governed_signal_to_content import database
from governed_signal_to_content.authentication import AuthenticationRequired, RELEASE_REASON
from governed_signal_to_content.approvals import decide_packet, release_packet
from governed_signal_to_content.config import WorkspacePaths
from governed_signal_to_content.packets import generate_packet
from governed_signal_to_content.models import AuthorityOperation, SignedOperation


def test_approval_required_before_release(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    workspace, candidate_id = qualified_candidate
    packet_id, _, _, _ = generate_packet(workspace, candidate_id, content_inputs_path)
    with pytest.raises(AuthenticationRequired):
        release_packet(workspace, packet_id, "release-actor")
    assert database.get_packet(workspace.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    approval_reason = "Reviewed exact manifest."
    decide_packet(
        paths=workspace,
        packet_id=packet_id,
        actor="human-reviewer",
        approved=True,
        reason=approval_reason,
        signed_operation=signed_operation(
            packet_id, AuthorityOperation.APPROVE, approval_reason
        ),
    )
    release_packet(
        workspace,
        packet_id,
        "release-actor",
        signed_operation(packet_id, AuthorityOperation.RELEASE, RELEASE_REASON),
    )
    assert database.get_packet(workspace.database, packet_id)["state"] == "RELEASED"  # type: ignore[index]


def test_rejection_path_is_terminal(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    workspace, candidate_id = qualified_candidate
    packet_id, _, _, _ = generate_packet(workspace, candidate_id, content_inputs_path)
    decide_packet(
        paths=workspace,
        packet_id=packet_id,
        actor="human-reviewer",
        approved=False,
        reason="Sources need clarification.",
        signed_operation=signed_operation(
            packet_id, AuthorityOperation.REJECT, "Sources need clarification."
        ),
    )
    assert database.get_packet(workspace.database, packet_id)["state"] == "REJECTED"  # type: ignore[index]
    with pytest.raises(AuthenticationRequired):
        release_packet(workspace, packet_id, "release-actor")


def test_approval_records_actor_manifest_and_prior_state(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    workspace, candidate_id = qualified_candidate
    packet_id, _, _, manifest_hash = generate_packet(
        workspace, candidate_id, content_inputs_path
    )
    decide_packet(
        paths=workspace,
        packet_id=packet_id,
        actor="Brendon R. Coleman",
        approved=True,
        reason="Explicit review.",
        signed_operation=signed_operation(
            packet_id, AuthorityOperation.APPROVE, "Explicit review."
        ),
    )
    files = list(workspace.approvals.glob("*.json"))
    assert len(files) == 1
    approval = json.loads(files[0].read_text(encoding="utf-8"))
    assert approval["actor"] == "Brendon R. Coleman"
    assert approval["manifest_hash"] == manifest_hash
    assert approval["prior_state"] == "AWAITING_APPROVAL"
