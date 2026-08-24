from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Callable

import pytest

from governed_signal_to_content import database, receipts
from governed_signal_to_content.authentication import RELEASE_REASON
from governed_signal_to_content.approvals import decide_packet, release_packet
from governed_signal_to_content.config import WorkspacePaths
from governed_signal_to_content.evidence import ingest_signal
from governed_signal_to_content.models import (
    AuthorityOperation,
    SignedOperation,
    WorkflowState,
)
from governed_signal_to_content.packets import PacketIntegrityError, generate_packet
from governed_signal_to_content.receipts import ReceiptProjectionError
from governed_signal_to_content.state_machine import InvalidTransition, transition_candidate


def _events(paths: WorkspacePaths, command: str | None = None) -> list[dict[str, object]]:
    with database.connect(paths.database) as connection:
        if command is None:
            rows = connection.execute(
                "SELECT * FROM transition_events ORDER BY occurred_at_utc, event_id"
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT * FROM transition_events
                WHERE command = ? ORDER BY occurred_at_utc, event_id
                """,
                (command,),
            ).fetchall()
    return [dict(row) for row in rows]


def _generate(
    qualified_candidate: tuple[WorkspacePaths, str], content_inputs_path: Path
) -> tuple[WorkspacePaths, str, str, str]:
    paths, candidate_id = qualified_candidate
    packet_id, _, _, manifest_hash = generate_packet(
        paths, candidate_id, content_inputs_path
    )
    return paths, candidate_id, packet_id, manifest_hash


def test_untouched_approval_and_release_are_bound_and_paired(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id, manifest_hash = _generate(
        qualified_candidate, content_inputs_path
    )

    approval_reason = "Reviewed exact materialized packet."
    approval_run_id = decide_packet(
        paths=paths,
        packet_id=packet_id,
        actor="asserted-human-reviewer",
        approved=True,
        reason=approval_reason,
        signed_operation=signed_operation(
            packet_id, AuthorityOperation.APPROVE, approval_reason
        ),
    )
    approval = database.get_approved_approval(paths.database, packet_id)
    assert approval is not None
    assert approval["manifest_hash"] == manifest_hash
    assert approval["transition_event_id"] == approval_run_id
    approval_event = database.get_transition_event(paths.database, approval_run_id)
    assert approval_event is not None
    assert approval_event["outcome"] == "accepted"
    assert approval_event["governed_hash"] == manifest_hash
    assert approval_event["asserted_actor"] == "asserted-human-reviewer"

    release_run_id = release_packet(
        paths,
        packet_id,
        "asserted-release-actor",
        signed_operation(packet_id, AuthorityOperation.RELEASE, RELEASE_REASON),
    )
    assert database.get_packet(paths.database, packet_id)["state"] == "RELEASED"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "RELEASED"  # type: ignore[index]
    release_event = database.get_transition_event(paths.database, release_run_id)
    assert release_event is not None
    assert release_event["governed_hash"] == manifest_hash


def test_artifact_mutation_before_approval_fails_closed(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id, _ = _generate(
        qualified_candidate, content_inputs_path
    )
    approval_reason = "Must not commit."
    signed = signed_operation(packet_id, AuthorityOperation.APPROVE, approval_reason)
    (paths.packets / packet_id / "01_linkedin_analysis.md").write_text(
        "changed before approval\n", encoding="utf-8", newline="\n"
    )

    with pytest.raises(PacketIntegrityError, match="integrity verification failed"):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted-human-reviewer",
            approved=True,
            reason=approval_reason,
            signed_operation=signed,
        )

    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_approved_approval(paths.database, packet_id) is None
    event = _events(paths, "approve")[-1]
    assert event["outcome"] == "rejected"
    assert event["resulting_state"] == "AWAITING_APPROVAL"
    hashes = json.loads(str(event["file_hashes_json"]))
    assert event["governed_hash"] == hashes["packet_manifest_recomputed"]


def test_artifact_mutation_after_approval_fails_release_closed(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id, _ = _generate(
        qualified_candidate, content_inputs_path
    )
    approval_reason = "Untouched packet reviewed."
    decide_packet(
        paths=paths,
        packet_id=packet_id,
        actor="asserted-human-reviewer",
        approved=True,
        reason=approval_reason,
        signed_operation=signed_operation(
            packet_id, AuthorityOperation.APPROVE, approval_reason
        ),
    )
    signed_release = signed_operation(
        packet_id, AuthorityOperation.RELEASE, RELEASE_REASON
    )
    (paths.packets / packet_id / "05_repository_note.md").write_text(
        "changed after approval\n", encoding="utf-8", newline="\n"
    )

    with pytest.raises(PacketIntegrityError, match="integrity verification failed"):
        release_packet(paths, packet_id, "asserted-release-actor", signed_release)

    assert database.get_packet(paths.database, packet_id)["state"] == "APPROVED"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "APPROVED"  # type: ignore[index]
    event = _events(paths, "release")[-1]
    assert event["outcome"] == "rejected"
    assert event["resulting_state"] == "APPROVED"


def test_packet_receipt_mutation_after_approval_fails_release_closed(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id, _ = _generate(
        qualified_candidate, content_inputs_path
    )
    approval_reason = "Untouched packet reviewed."
    decide_packet(
        paths=paths,
        packet_id=packet_id,
        actor="asserted-human-reviewer",
        approved=True,
        reason=approval_reason,
        signed_operation=signed_operation(
            packet_id, AuthorityOperation.APPROVE, approval_reason
        ),
    )
    signed_release = signed_operation(
        packet_id, AuthorityOperation.RELEASE, RELEASE_REASON
    )
    packet_receipt_path = paths.packets / packet_id / "packet_receipt.json"
    packet_receipt = json.loads(packet_receipt_path.read_text(encoding="utf-8"))
    packet_receipt["warnings"].append("changed after approval")
    packet_receipt_path.write_text(
        json.dumps(packet_receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(ValueError, match="current packet identity"):
        release_packet(paths, packet_id, "asserted-release-actor", signed_release)

    assert database.get_packet(paths.database, packet_id)["state"] == "APPROVED"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "APPROVED"  # type: ignore[index]
    assert _events(paths, "release")[-1]["outcome"] == "rejected"


def test_approval_manifest_disagreement_fails_release_closed(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id, _ = _generate(
        qualified_candidate, content_inputs_path
    )
    approval_reason = "Untouched packet reviewed."
    decide_packet(
        paths=paths,
        packet_id=packet_id,
        actor="asserted-human-reviewer",
        approved=True,
        reason=approval_reason,
        signed_operation=signed_operation(
            packet_id, AuthorityOperation.APPROVE, approval_reason
        ),
    )
    signed_release = signed_operation(
        packet_id, AuthorityOperation.RELEASE, RELEASE_REASON
    )
    with database.connect(paths.database) as connection:
        connection.execute(
            "UPDATE approvals SET manifest_hash = ? WHERE packet_id = ?",
            ("0" * 64, packet_id),
        )

    with pytest.raises(PacketIntegrityError, match="binding mismatch"):
        release_packet(paths, packet_id, "asserted-release-actor", signed_release)

    assert database.get_packet(paths.database, packet_id)["state"] == "APPROVED"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "APPROVED"  # type: ignore[index]
    assert _events(paths, "release")[-1]["outcome"] == "rejected"


def test_failed_approval_persistence_rolls_back_state_and_event(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id, _ = _generate(
        qualified_candidate, content_inputs_path
    )

    def fail_approval(*args: object, **kwargs: object) -> None:
        raise OSError("simulated canonical approval persistence failure")

    approval_reason = "Must roll back."
    signed = signed_operation(packet_id, AuthorityOperation.APPROVE, approval_reason)
    monkeypatch.setattr(database, "insert_approval", fail_approval)
    with pytest.raises(OSError, match="canonical approval"):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted-human-reviewer",
            approved=True,
            reason=approval_reason,
            signed_operation=signed,
        )

    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_approved_approval(paths.database, packet_id) is None
    assert _events(paths, "approve") == []


def test_failed_transition_event_persistence_rolls_back_approval_and_state(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id, _ = _generate(
        qualified_candidate, content_inputs_path
    )
    original = database.insert_transition_event

    def fail_approval_event(
        connection: sqlite3.Connection, event: dict[str, object]
    ) -> None:
        if event["command"] == "approve":
            raise OSError("simulated canonical transition-event persistence failure")
        original(connection, event)

    approval_reason = "Must roll back."
    signed = signed_operation(packet_id, AuthorityOperation.APPROVE, approval_reason)
    monkeypatch.setattr(database, "insert_transition_event", fail_approval_event)
    with pytest.raises(OSError, match="transition-event"):
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted-human-reviewer",
            approved=True,
            reason=approval_reason,
            signed_operation=signed,
        )

    assert database.get_packet(paths.database, packet_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "AWAITING_APPROVAL"  # type: ignore[index]
    assert database.get_approved_approval(paths.database, packet_id) is None
    assert _events(paths, "approve") == []


def test_failed_packet_generation_event_keeps_paired_canonical_state(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths, candidate_id = qualified_candidate
    original = database.insert_transition_event

    def fail_packet_generated_event(
        connection: sqlite3.Connection, event: dict[str, object]
    ) -> None:
        if event["requested_state"] == "PACKET_GENERATED":
            raise OSError("simulated packet-generation event failure")
        original(connection, event)

    monkeypatch.setattr(database, "insert_transition_event", fail_packet_generated_event)
    with pytest.raises(OSError, match="packet-generation"):
        generate_packet(paths, candidate_id, content_inputs_path)

    assert database.get_candidate(paths.database, candidate_id)["state"] == "QUALIFIED"  # type: ignore[index]
    assert database.state_counts(paths.database, "packets") == {}
    assert _events(paths, "generate") == []


def test_failed_jsonl_projection_preserves_event_and_reconciles(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id, packet_id, _ = _generate(
        qualified_candidate, content_inputs_path
    )
    original_append = receipts.append_canonical_receipt

    def fail_append(*args: object, **kwargs: object) -> None:
        raise OSError("simulated JSONL projection failure")

    approval_reason = "Canonical commit survives projection failure."
    signed = signed_operation(packet_id, AuthorityOperation.APPROVE, approval_reason)
    prior_jsonl = paths.receipt_log.read_bytes()
    monkeypatch.setattr(receipts, "append_canonical_receipt", fail_append)
    with pytest.raises(ReceiptProjectionError) as caught:
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted-human-reviewer",
            approved=True,
            reason=approval_reason,
            signed_operation=signed,
        )
    event_id = caught.value.event_id

    assert paths.receipt_log.read_bytes() == prior_jsonl
    assert database.get_packet(paths.database, packet_id)["state"] == "APPROVED"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "APPROVED"  # type: ignore[index]
    event = database.get_transition_event(paths.database, event_id)
    assert event is not None
    assert event["receipt_projected_at_utc"] is None
    assert database.get_approved_approval(paths.database, packet_id) is not None

    monkeypatch.setattr(receipts, "append_canonical_receipt", original_append)
    assert receipts.reconcile_pending_receipts(paths.database, paths.receipt_log) == 1
    projected = database.get_transition_event(paths.database, event_id)
    assert projected is not None
    assert projected["receipt_projected_at_utc"] is not None
    assert receipts.find_receipt(paths.receipt_log, event_id) is not None
    assert receipts.reconcile_pending_receipts(paths.database, paths.receipt_log) == 0


def test_reconcile_after_append_before_mark_does_not_duplicate_run_id(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, _, packet_id, _ = _generate(qualified_candidate, content_inputs_path)
    original_mark = database.mark_transition_event_projected

    def fail_mark(*args: object, **kwargs: object) -> None:
        raise OSError("simulated projection-mark failure")

    approval_reason = "Append succeeds before projection mark fails."
    signed = signed_operation(packet_id, AuthorityOperation.APPROVE, approval_reason)
    monkeypatch.setattr(database, "mark_transition_event_projected", fail_mark)
    with pytest.raises(ReceiptProjectionError) as caught:
        decide_packet(
            paths=paths,
            packet_id=packet_id,
            actor="asserted-human-reviewer",
            approved=True,
            reason=approval_reason,
            signed_operation=signed,
        )
    event_id = caught.value.event_id
    lines_before = paths.receipt_log.read_text(encoding="utf-8").splitlines()
    assert sum(f'"run_id":"{event_id}"' in line for line in lines_before) == 1

    monkeypatch.setattr(database, "mark_transition_event_projected", original_mark)
    assert receipts.reconcile_pending_receipts(paths.database, paths.receipt_log) == 1
    lines_after = paths.receipt_log.read_text(encoding="utf-8").splitlines()
    assert sum(f'"run_id":"{event_id}"' in line for line in lines_after) == 1
    event = database.get_transition_event(paths.database, event_id)
    assert event is not None
    assert event["receipt_projected_at_utc"] is not None


def test_invalid_jump_is_rejected_inspectable_and_does_not_mutate(
    workspace: WorkspacePaths,
) -> None:
    candidate, _, _ = ingest_signal(
        paths=workspace,
        title="Invalid jump",
        source_url="https://example.com/invalid-jump",
        source_file=None,
    )

    with pytest.raises(InvalidTransition):
        transition_candidate(
            database_path=workspace.database,
            receipt_log=workspace.receipt_log,
            candidate_id=candidate.candidate_id,
            requested=WorkflowState.APPROVED,
            command="invalid-jump",
            actor="asserted-test-actor",
            reason="Must be rejected.",
        )

    assert database.get_candidate(workspace.database, candidate.candidate_id)["state"] == "EVIDENCE_PRESERVED"  # type: ignore[index]
    event = _events(workspace, "invalid-jump")[-1]
    assert event["outcome"] == "rejected"
    assert event["prior_state"] == event["resulting_state"] == "EVIDENCE_PRESERVED"
    assert receipts.find_receipt(workspace.receipt_log, str(event["event_id"])) is not None


def test_duplicate_transition_event_id_is_impossible(workspace: WorkspacePaths) -> None:
    candidate, _, event_id = ingest_signal(
        paths=workspace,
        title="Unique event",
        source_url="https://example.com/unique-event",
        source_file=None,
    )
    event = database.get_transition_event(workspace.database, event_id)
    assert event is not None
    event_count = len(_events(workspace))
    jsonl_bytes = workspace.receipt_log.read_bytes()

    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        database.record_transition_event(workspace.database, event)

    assert len(_events(workspace)) == event_count
    assert workspace.receipt_log.read_bytes() == jsonl_bytes
    assert database.get_candidate(workspace.database, candidate.candidate_id) is not None


def test_legacy_schema_migration_is_idempotent_and_preserves_approvals(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "legacy.sqlite"
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
            CREATE TABLE approvals (
                approval_id TEXT PRIMARY KEY, packet_id TEXT NOT NULL REFERENCES packets(packet_id),
                actor TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL,
                manifest_hash TEXT NOT NULL, prior_state TEXT NOT NULL, decided_at_utc TEXT NOT NULL
            );
            INSERT INTO candidates VALUES (
                'cand_legacy', 'Legacy', 'https://example.com/legacy', NULL, 'identity', '[]',
                'APPROVED', '2026-01-01T00:00:00Z', NULL, NULL
            );
            INSERT INTO packets VALUES (
                'pkt_legacy', 'cand_legacy', 'legacy/path', 'manifest', 'APPROVED',
                '2026-01-01T00:00:00Z'
            );
            INSERT INTO approvals VALUES (
                'appr_legacy', 'pkt_legacy', 'legacy-asserted-actor', 'APPROVED', 'legacy',
                'manifest', 'AWAITING_APPROVAL', '2026-01-01T00:00:00Z'
            );
            """
        )

    database.migrate_database(database_path)
    database.migrate_database(database_path)

    with database.connect(database_path) as connection:
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(approvals)").fetchall()
        }
        approval = connection.execute(
            "SELECT * FROM approvals WHERE approval_id = 'appr_legacy'"
        ).fetchone()
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    assert "transition_event_id" in columns
    assert approval is not None
    assert approval["transition_event_id"] is None
    assert version == database.DATABASE_SCHEMA_VERSION
