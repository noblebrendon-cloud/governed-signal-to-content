"""Human approval, rejection, and local release authorization."""

from __future__ import annotations

import json
from uuid import uuid4

from . import database
from .config import WorkspacePaths
from .models import WorkflowState
from .receipts import utc_now
from .state_machine import transition_packet


def decide_packet(
    *,
    paths: WorkspacePaths,
    packet_id: str,
    actor: str,
    approved: bool,
    reason: str,
) -> str:
    packet = database.get_packet(paths.database, packet_id)
    if packet is None:
        raise KeyError(f"Unknown packet: {packet_id}")
    prior = str(packet["state"])
    target = WorkflowState.APPROVED if approved else WorkflowState.REJECTED
    receipt = transition_packet(
        database_path=paths.database,
        receipt_log=paths.receipt_log,
        packet_id=packet_id,
        requested=target,
        command="approve" if approved else "reject",
        actor=actor,
        reason=reason,
        file_hashes={"packet_manifest": str(packet["manifest_hash"])},
    )
    approval = {
        "schema_version": "1.0",
        "approval_id": f"appr_{uuid4().hex}",
        "packet_id": packet_id,
        "actor": actor,
        "decision": target.value,
        "reason": reason,
        "manifest_hash": str(packet["manifest_hash"]),
        "prior_state": prior,
        "decided_at_utc": utc_now(),
        "run_id": receipt.run_id,
    }
    database.insert_approval(paths.database, approval)
    output = paths.approvals / f"{approval['approval_id']}.json"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(approval, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return receipt.run_id


def release_packet(paths: WorkspacePaths, packet_id: str, actor: str) -> str:
    packet = database.get_packet(paths.database, packet_id)
    if packet is None:
        raise KeyError(f"Unknown packet: {packet_id}")
    receipt = transition_packet(
        database_path=paths.database,
        receipt_log=paths.receipt_log,
        packet_id=packet_id,
        requested=WorkflowState.RELEASED,
        command="release",
        actor=actor,
        reason=(
            "Locally authorized for downstream publication. No external platform was contacted "
            "and no content was posted."
        ),
        file_hashes={"packet_manifest": str(packet["manifest_hash"])},
    )
    return receipt.run_id
