from __future__ import annotations

import json
from pathlib import Path

import pytest

from governed_signal_to_content import database
from governed_signal_to_content.approvals import decide_packet, release_packet
from governed_signal_to_content.config import WorkspacePaths
from governed_signal_to_content.packets import generate_packet
from governed_signal_to_content.state_machine import InvalidTransition


def test_approval_required_before_release(
    qualified_candidate: tuple[WorkspacePaths, str], content_inputs_path: Path
) -> None:
    workspace, candidate_id = qualified_candidate
    packet_id, _, _, _ = generate_packet(workspace, candidate_id, content_inputs_path)
    with pytest.raises(InvalidTransition):
        release_packet(workspace, packet_id, "release-actor")
    assert database.get_packet(workspace.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    decide_packet(
        paths=workspace,
        packet_id=packet_id,
        actor="human-reviewer",
        approved=True,
        reason="Reviewed exact manifest.",
    )
    release_packet(workspace, packet_id, "release-actor")
    assert database.get_packet(workspace.database, packet_id)["state"] == "RELEASED"  # type: ignore[index]


def test_rejection_path_is_terminal(
    qualified_candidate: tuple[WorkspacePaths, str], content_inputs_path: Path
) -> None:
    workspace, candidate_id = qualified_candidate
    packet_id, _, _, _ = generate_packet(workspace, candidate_id, content_inputs_path)
    decide_packet(
        paths=workspace,
        packet_id=packet_id,
        actor="human-reviewer",
        approved=False,
        reason="Sources need clarification.",
    )
    assert database.get_packet(workspace.database, packet_id)["state"] == "REJECTED"  # type: ignore[index]
    with pytest.raises(InvalidTransition):
        release_packet(workspace, packet_id, "release-actor")


def test_approval_records_actor_manifest_and_prior_state(
    qualified_candidate: tuple[WorkspacePaths, str], content_inputs_path: Path
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
    )
    files = list(workspace.approvals.glob("*.json"))
    assert len(files) == 1
    approval = json.loads(files[0].read_text(encoding="utf-8"))
    assert approval["actor"] == "Brendon R. Coleman"
    assert approval["manifest_hash"] == manifest_hash
    assert approval["prior_state"] == "AWAITING_APPROVAL"
