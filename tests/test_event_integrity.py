from __future__ import annotations

import base64
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Callable

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from governed_signal_to_content import cli, database, receipts
from governed_signal_to_content.authentication import (
    APPROVAL_REASON,
    RELEASE_REASON,
    AuthenticationError,
    OperationBindingError,
    ReplayDetected,
)
from governed_signal_to_content.config import WorkspacePaths, workspace_paths
from governed_signal_to_content.integrity import (
    CHAIN_ACTIVATION_DOMAIN,
    CHAIN_DOMAIN,
    CHAIN_ORIGIN,
    CHAIN_VERSION,
    CanonicalChainError,
    calculate_activation_hash,
    calculate_event_hash,
    verify_integrity,
)
from governed_signal_to_content.models import AuthorityOperation, RunReceipt, SignedOperation
from governed_signal_to_content.packets import PacketIntegrityError, generate_packet
from governed_signal_to_content.receipts import (
    new_receipt,
    project_transition_event,
    transition_event_from_receipt,
)
from governed_signal_to_content.transition_mediator import mediate_signed_transition


def _event(command: str, *, reason: str | None = None) -> dict[str, object]:
    receipt = new_receipt(
        command=command,
        actor="asserted-integrity-tester",
        input_identifiers={"candidate_id": f"cand_{command}"},
        prior_state="DISCOVERED",
        requested_transition="EVIDENCE_PRESERVED",
        resulting_state="EVIDENCE_PRESERVED",
        outcome="accepted",
        reason=reason or f"Integrity event {command}",
        file_hashes={"artifact": "a" * 64},
    )
    return transition_event_from_receipt(
        receipt,
        target_type="candidate",
        target_id=f"cand_{command}",
    )


def _chain_workspace(tmp_path: Path, count: int = 3) -> WorkspacePaths:
    paths = workspace_paths(tmp_path / "chain-workspace")
    database.initialize_workspace(paths)
    for index in range(1, count + 1):
        event = _event(f"event-{index}")
        database.record_transition_event(paths.database, event)
        project_transition_event(paths.database, paths.receipt_log, str(event["event_id"]))
    return paths


def _chain_rows(paths: WorkspacePaths) -> list[dict[str, object]]:
    with database.connect(paths.database) as connection:
        rows = connection.execute(
            """
            SELECT e.*, c.chain_version, c.chain_origin, c.event_sequence,
                   c.previous_event_hash, c.event_hash
            FROM transition_events AS e
            JOIN transition_event_chain_entries AS c ON c.event_id = e.event_id
            ORDER BY c.event_sequence
            """
        ).fetchall()
    return [dict(row) for row in rows]


def _clone_event(connection: sqlite3.Connection, source_id: str, clone_id: str) -> None:
    columns = [
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(transition_events)").fetchall()
    ]
    source = connection.execute(
        "SELECT * FROM transition_events WHERE event_id = ?", (source_id,)
    ).fetchone()
    assert source is not None
    values = dict(source)
    values["event_id"] = clone_id
    connection.execute(
        f"INSERT INTO transition_events ({', '.join(columns)}) "  # noqa: S608
        f"VALUES ({', '.join('?' for _ in columns)})",  # noqa: S608
        tuple(values[column] for column in columns),
    )


def test_hash_definition_is_deterministic_sensitive_and_domain_separated() -> None:
    event = _event("hash-test")
    receipt_payload = json.loads(str(event["receipt_json"]))
    receipt_payload.update(
        {
            "chain_version": CHAIN_VERSION,
            "chain_origin": CHAIN_ORIGIN,
            "event_sequence": 1,
            "previous_event_hash": "0" * 64,
        }
    )
    first = calculate_event_hash(
        event,
        event_sequence=1,
        previous_event_hash="0" * 64,
        receipt_without_event_hash=receipt_payload,
    )
    second = calculate_event_hash(
        dict(reversed(list(event.items()))),
        event_sequence=1,
        previous_event_hash="0" * 64,
        receipt_without_event_hash=dict(reversed(list(receipt_payload.items()))),
    )
    assert first == second

    changed = {**event, "reason": "changed semantic evidence"}
    assert calculate_event_hash(
        changed,
        event_sequence=1,
        previous_event_hash="0" * 64,
        receipt_without_event_hash=receipt_payload,
    ) != first
    projected = {**event, "receipt_projected_at_utc": "2099-01-01T00:00:00Z"}
    assert calculate_event_hash(
        projected,
        event_sequence=1,
        previous_event_hash="0" * 64,
        receipt_without_event_hash=receipt_payload,
    ) == first
    assert calculate_event_hash(
        event,
        event_sequence=1,
        previous_event_hash="0" * 64,
        receipt_without_event_hash=receipt_payload,
        domain=f"{CHAIN_DOMAIN}_OTHER",
    ) != first
    assert calculate_activation_hash([]) == calculate_activation_hash([])
    assert CHAIN_ACTIVATION_DOMAIN != CHAIN_DOMAIN


def test_native_genesis_three_event_chain_and_receipt_identity(tmp_path: Path) -> None:
    paths = _chain_workspace(tmp_path)
    rows = _chain_rows(paths)
    with database.connect(paths.database) as connection:
        state = dict(
            connection.execute(
                "SELECT * FROM transition_event_chain_state WHERE singleton_id = 1"
            ).fetchone()
        )

    assert [row["event_sequence"] for row in rows] == [1, 2, 3]
    assert rows[0]["previous_event_hash"] == state["activation_hash"]
    assert rows[1]["previous_event_hash"] == rows[0]["event_hash"]
    assert rows[2]["previous_event_hash"] == rows[1]["event_hash"]
    assert state["head_event_id"] == rows[2]["event_id"]
    assert state["head_event_hash"] == rows[2]["event_hash"]
    for row in rows:
        projected = receipts.find_receipt(paths.receipt_log, str(row["event_id"]))
        assert projected is not None
        assert projected["chain_version"] == CHAIN_VERSION
        assert projected["event_sequence"] == row["event_sequence"]
        assert projected["previous_event_hash"] == row["previous_event_hash"]
        assert projected["event_hash"] == row["event_hash"]
        assert RunReceipt.model_validate(projected).event_hash == row["event_hash"]
        receipt_schema = json.loads(
            (Path(__file__).parents[1] / "schemas" / "run_receipt.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator(receipt_schema).validate(projected)

    result = verify_integrity(paths.database, paths.receipt_log)
    assert result.canonical_chain_valid
    assert result.projection_valid
    assert result.projection_complete
    assert result.native_events_checked == 3
    assert not result.failures


def test_authority_replay_and_authentication_failure_events_share_one_chain(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, _ = qualified_candidate
    packet_id, _, _, _ = generate_packet(
        paths, qualified_candidate[1], content_inputs_path
    )
    approval = signed_operation(packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON)
    approved = mediate_signed_transition(
        paths=paths, signed_operation=approval, asserted_actor="display-only"
    )
    with pytest.raises(ReplayDetected):
        mediate_signed_transition(
            paths=paths, signed_operation=approval, asserted_actor="display-only"
        )
    release = signed_operation(packet_id, AuthorityOperation.RELEASE, RELEASE_REASON)
    released = mediate_signed_transition(
        paths=paths, signed_operation=release, asserted_actor="display-only"
    )
    invalid = release.model_copy(
        update={"signature_b64": base64.b64encode(b"invalid").decode("ascii")}
    )
    before_unidentified = len(_chain_rows(paths))
    with pytest.raises(AuthenticationError):
        mediate_signed_transition(
            paths=paths, signed_operation=invalid, asserted_actor="untrusted-display"
        )
    after_identifiable = len(_chain_rows(paths))
    with pytest.raises(AuthenticationError):
        mediate_signed_transition(
            paths=paths, signed_operation=None, asserted_actor="untrusted-display"
        )
    assert len(_chain_rows(paths)) == after_identifiable
    assert after_identifiable == before_unidentified + 1

    approval_event = database.get_transition_event(
        paths.database, approved.canonical_event_id
    )
    release_event = database.get_transition_event(paths.database, released.canonical_event_id)
    assert approval_event is not None and release_event is not None
    approval_identifiers = json.loads(str(approval_event["input_identifiers_json"]))
    release_identifiers = json.loads(str(release_event["input_identifiers_json"]))
    assert approval_identifiers["approval_id"] == approval.envelope.approval_id
    assert approval_identifiers["approval_decision"] == "APPROVED"
    assert release_identifiers["approval_transition_event_id"] == (
        release.envelope.approval_transition_event_id
    )
    result = verify_integrity(paths.database, paths.receipt_log)
    assert result.canonical_chain_valid and result.projection_valid
    assert [row["event_sequence"] for row in _chain_rows(paths)] == list(
        range(1, len(_chain_rows(paths)) + 1)
    )


def test_authenticated_state_and_artifact_rejections_are_chained_and_consumed(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id = qualified_candidate
    packet_id, _, _, _ = generate_packet(paths, candidate_id, content_inputs_path)
    accepted = signed_operation(packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON)
    stale = signed_operation(packet_id, AuthorityOperation.APPROVE, APPROVAL_REASON)
    mediate_signed_transition(
        paths=paths, signed_operation=accepted, asserted_actor="display-only"
    )
    with pytest.raises(OperationBindingError) as state_rejection:
        mediate_signed_transition(
            paths=paths, signed_operation=stale, asserted_actor="display-only"
        )
    state_event = database.get_transition_event(
        paths.database, state_rejection.value.transition_result.canonical_event_id
    )
    assert state_event is not None
    assert state_event["outcome"] == "rejected"
    assert state_event["authentication_status"] == "verified"
    assert database.find_consumed_authenticated_operation(
        paths.database, stale.envelope.operation_id, "unused"
    ) is not None

    artifact_signed = signed_operation(packet_id, AuthorityOperation.RELEASE, RELEASE_REASON)
    packet = database.get_packet(paths.database, packet_id)
    assert packet is not None
    governed_file = Path(str(packet["packet_path"])) / "01_linkedin_analysis.md"
    governed_file.write_text("tampered after signing", encoding="utf-8")
    with pytest.raises(PacketIntegrityError) as artifact_rejection:
        mediate_signed_transition(
            paths=paths,
            signed_operation=artifact_signed,
            asserted_actor="display-only",
        )
    artifact_event = database.get_transition_event(
        paths.database, artifact_rejection.value.transition_result.canonical_event_id
    )
    assert artifact_event is not None
    assert artifact_event["outcome"] == "rejected"
    assert artifact_event["authentication_status"] == "verified"
    assert database.find_consumed_authenticated_operation(
        paths.database, artifact_signed.envelope.operation_id, "unused"
    ) is not None
    assert verify_integrity(paths.database, paths.receipt_log).canonical_chain_valid


def test_accepted_rejection_decision_is_atomically_chained(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    signed_operation: Callable[[str, AuthorityOperation, str], SignedOperation],
) -> None:
    paths, candidate_id = qualified_candidate
    packet_id, _, _, _ = generate_packet(paths, candidate_id, content_inputs_path)
    signed = signed_operation(packet_id, AuthorityOperation.REJECT, "Reject this packet.")
    result = mediate_signed_transition(
        paths=paths, signed_operation=signed, asserted_actor="display-only"
    )
    event = database.get_transition_event(paths.database, result.canonical_event_id)
    with database.connect(paths.database) as connection:
        approval_row = connection.execute(
            "SELECT * FROM approvals WHERE approval_id = ?",
            (signed.envelope.approval_id,),
        ).fetchone()
    approval = None if approval_row is None else dict(approval_row)
    assert event is not None and approval is not None
    assert event["outcome"] == "accepted"
    assert event["event_sequence"] is not None
    assert event["event_hash"] is not None
    assert approval["decision"] == "REJECTED"
    assert approval["transition_event_id"] == event["event_id"]
    assert database.get_packet(paths.database, packet_id)["state"] == "REJECTED"  # type: ignore[index]
    assert database.get_candidate(paths.database, candidate_id)["state"] == "REJECTED"  # type: ignore[index]
    assert verify_integrity(paths.database, paths.receipt_log).canonical_chain_valid


@pytest.mark.parametrize(
    "tamper",
    [
        "event_payload",
        "previous_hash",
        "event_hash",
        "delete_middle",
        "delete_tail",
        "fabricated_insert",
        "reorder_sequence",
        "malformed_sequence",
        "head_mismatch",
    ],
)
def test_canonical_tampering_is_detected(tmp_path: Path, tamper: str) -> None:
    paths = _chain_workspace(tmp_path)
    rows = _chain_rows(paths)
    with sqlite3.connect(paths.database) as raw:
        raw.row_factory = sqlite3.Row
        if tamper == "event_payload":
            raw.execute(
                "UPDATE transition_events SET reason = 'mutated' WHERE event_id = ?",
                (rows[1]["event_id"],),
            )
        elif tamper == "previous_hash":
            raw.execute(
                "UPDATE transition_event_chain_entries SET previous_event_hash = ? "
                "WHERE event_sequence = 2",
                ("b" * 64,),
            )
        elif tamper == "event_hash":
            raw.execute(
                "UPDATE transition_event_chain_entries SET event_hash = ? "
                "WHERE event_sequence = 3",
                ("c" * 64,),
            )
        elif tamper in {"delete_middle", "delete_tail"}:
            victim = rows[1] if tamper == "delete_middle" else rows[2]
            raw.execute(
                "DELETE FROM transition_event_chain_entries WHERE event_id = ?",
                (victim["event_id"],),
            )
            raw.execute(
                "DELETE FROM transition_events WHERE event_id = ?", (victim["event_id"],)
            )
        elif tamper == "fabricated_insert":
            _clone_event(raw, str(rows[0]["event_id"]), "fabricated-event")
        elif tamper == "reorder_sequence":
            raw.execute(
                "UPDATE transition_event_chain_entries SET event_sequence = 100 "
                "WHERE event_sequence = 1"
            )
            raw.execute(
                "UPDATE transition_event_chain_entries SET event_sequence = 1 "
                "WHERE event_sequence = 2"
            )
            raw.execute(
                "UPDATE transition_event_chain_entries SET event_sequence = 2 "
                "WHERE event_sequence = 100"
            )
        elif tamper == "malformed_sequence":
            raw.execute("PRAGMA ignore_check_constraints = ON")
            raw.execute(
                "UPDATE transition_event_chain_entries SET event_sequence = 'invalid' "
                "WHERE event_sequence = 2"
            )
        elif tamper == "head_mismatch":
            raw.execute(
                "UPDATE transition_event_chain_state SET head_event_hash = ? "
                "WHERE singleton_id = 1",
                ("d" * 64,),
            )
        raw.commit()

    result = verify_integrity(paths.database, paths.receipt_log)
    assert not result.canonical_chain_valid
    assert result.failures


def test_database_constraints_reject_duplicate_sequence_and_branch(tmp_path: Path) -> None:
    paths = _chain_workspace(tmp_path, count=1)
    row = _chain_rows(paths)[0]
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        with database.connect(paths.database, immediate=True) as connection:
            _clone_event(connection, str(row["event_id"]), "duplicate-sequence-event")
            connection.execute(
                """
                INSERT INTO transition_event_chain_entries VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "duplicate-sequence-event",
                    CHAIN_VERSION,
                    CHAIN_ORIGIN,
                    1,
                    "e" * 64,
                    "f" * 64,
                ),
            )
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        with database.connect(paths.database, immediate=True) as connection:
            _clone_event(connection, str(row["event_id"]), "branch-event")
            connection.execute(
                """
                INSERT INTO transition_event_chain_entries VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "branch-event",
                    CHAIN_VERSION,
                    CHAIN_ORIGIN,
                    2,
                    row["previous_event_hash"],
                    "f" * 64,
                ),
            )
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        with database.connect(paths.database, immediate=True) as connection:
            _clone_event(connection, str(row["event_id"]), "duplicate-hash-event")
            connection.execute(
                """
                INSERT INTO transition_event_chain_entries VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    "duplicate-hash-event",
                    CHAIN_VERSION,
                    CHAIN_ORIGIN,
                    2,
                    "1" * 64,
                    row["event_hash"],
                ),
            )


def test_first_append_refuses_a_corrupt_activation_checkpoint(tmp_path: Path) -> None:
    paths = workspace_paths(tmp_path / "corrupt-activation")
    database.initialize_workspace(paths)
    with database.connect(paths.database) as connection:
        connection.execute(
            """
            UPDATE transition_event_chain_state
            SET activation_hash = ?, head_event_hash = ?
            WHERE singleton_id = 1
            """,
            ("f" * 64, "f" * 64),
        )
    with pytest.raises(CanonicalChainError, match="activation checkpoint"):
        database.record_transition_event(paths.database, _event("must-not-append"))
    with database.connect(paths.database) as connection:
        assert int(
            connection.execute("SELECT COUNT(*) FROM transition_events").fetchone()[0]
        ) == 0


def test_runtime_append_refuses_a_corrupt_chain_tail(tmp_path: Path) -> None:
    paths = _chain_workspace(tmp_path, count=1)
    with database.connect(paths.database) as connection:
        initial_head = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
        connection.execute("UPDATE transition_events SET reason = 'mutated tail'")
    with pytest.raises(CanonicalChainError, match="hash mismatch"):
        database.record_transition_event(paths.database, _event("must-not-extend"))
    with database.connect(paths.database) as connection:
        final_head = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
        event_count = int(
            connection.execute("SELECT COUNT(*) FROM transition_events").fetchone()[0]
        )
    assert final_head == initial_head
    assert event_count == 1


@pytest.mark.parametrize(
    "tamper",
    ["payload", "event_hash", "missing", "duplicate", "malformed", "encoding"],
)
def test_receipt_projection_tampering_is_separate_from_chain_validity(
    tmp_path: Path, tamper: str
) -> None:
    paths = _chain_workspace(tmp_path, count=1)
    line = paths.receipt_log.read_text(encoding="utf-8").strip()
    value = json.loads(line)
    if tamper == "payload":
        value["reason"] = "mutated projection"
        paths.receipt_log.write_text(json.dumps(value) + "\n", encoding="utf-8")
    elif tamper == "event_hash":
        value["event_hash"] = "0" * 64
        paths.receipt_log.write_text(json.dumps(value) + "\n", encoding="utf-8")
    elif tamper == "missing":
        paths.receipt_log.write_text("", encoding="utf-8")
    elif tamper == "duplicate":
        paths.receipt_log.write_text(line + "\n" + line + "\n", encoding="utf-8")
    elif tamper == "malformed":
        paths.receipt_log.write_text("{not-json\n", encoding="utf-8")
    else:
        paths.receipt_log.write_bytes(b"\xff\xfe\xfd")

    result = verify_integrity(paths.database, paths.receipt_log)
    assert result.canonical_chain_valid
    assert not result.projection_valid


def test_pending_projection_is_recoverable_and_append_before_mark_is_idempotent(
    tmp_path: Path,
) -> None:
    paths = _chain_workspace(tmp_path, count=1)
    row = _chain_rows(paths)[0]
    original_line = paths.receipt_log.read_text(encoding="utf-8")
    with database.connect(paths.database) as connection:
        connection.execute(
            "UPDATE transition_events SET receipt_projected_at_utc = NULL WHERE event_id = ?",
            (row["event_id"],),
        )
    paths.receipt_log.write_text("", encoding="utf-8")
    pending = verify_integrity(paths.database, paths.receipt_log)
    assert pending.canonical_chain_valid and pending.projection_valid
    assert not pending.projection_complete
    assert pending.pending_projection_count == 1

    assert receipts.reconcile_pending_receipts(paths.database, paths.receipt_log) == 1
    assert paths.receipt_log.read_text(encoding="utf-8") == original_line
    with database.connect(paths.database) as connection:
        connection.execute(
            "UPDATE transition_events SET receipt_projected_at_utc = NULL WHERE event_id = ?",
            (row["event_id"],),
        )
    assert receipts.reconcile_pending_receipts(paths.database, paths.receipt_log) == 1
    assert paths.receipt_log.read_text(encoding="utf-8") == original_line
    assert receipts.reconcile_pending_receipts(paths.database, paths.receipt_log) == 0
    complete = verify_integrity(paths.database, paths.receipt_log)
    assert complete.projection_valid and complete.projection_complete


def test_schema2_migration_creates_honest_idempotent_checkpoint(tmp_path: Path) -> None:
    paths = workspace_paths(tmp_path / "legacy-workspace")
    paths.state.mkdir(parents=True)
    paths.receipts.mkdir(parents=True)
    legacy_receipt = new_receipt(
        command="legacy",
        actor="legacy-asserted-actor",
        input_identifiers={"candidate_id": "cand_legacy"},
        prior_state="DISCOVERED",
        requested_transition="EVIDENCE_PRESERVED",
        resulting_state="EVIDENCE_PRESERVED",
        outcome="accepted",
        reason="Legacy event",
    )
    legacy_event = transition_event_from_receipt(
        legacy_receipt, target_type="candidate", target_id="cand_legacy"
    )
    paths.receipt_log.write_text(
        str(legacy_event["receipt_json"]) + "\n", encoding="utf-8", newline="\n"
    )
    original_jsonl = paths.receipt_log.read_bytes()
    with sqlite3.connect(paths.database) as connection:
        connection.executescript(
            """
            CREATE TABLE transition_events (
                event_id TEXT PRIMARY KEY, command TEXT NOT NULL,
                asserted_actor TEXT NOT NULL, target_type TEXT NOT NULL,
                target_id TEXT NOT NULL, candidate_id TEXT, packet_id TEXT,
                prior_state TEXT, requested_state TEXT, resulting_state TEXT,
                outcome TEXT NOT NULL, reason TEXT NOT NULL, governed_hash TEXT,
                input_identifiers_json TEXT NOT NULL, file_hashes_json TEXT NOT NULL,
                occurred_at_utc TEXT NOT NULL, application_version TEXT NOT NULL,
                receipt_json TEXT NOT NULL, receipt_projected_at_utc TEXT,
                authentication_status TEXT, authenticated_principal_id TEXT,
                authentication_scheme TEXT, authentication_key_id TEXT,
                authentication_verifier_fingerprint TEXT,
                authentication_operation_id TEXT, authentication_envelope_hash TEXT,
                authentication_proof_hash TEXT, authenticated_at_utc TEXT
            );
            PRAGMA user_version = 2;
            """
        )
        columns = [
            str(row[1])
            for row in connection.execute("PRAGMA table_info(transition_events)")
        ]
        connection.execute(
            f"INSERT INTO transition_events ({', '.join(columns)}) "  # noqa: S608
            f"VALUES ({', '.join('?' for _ in columns)})",  # noqa: S608
            tuple(
                (
                    "2026-01-01T00:00:01Z"
                    if column == "receipt_projected_at_utc"
                    else legacy_event.get(column)
                )
                for column in columns
            ),
        )

    database.migrate_database(paths.database)
    with database.connect(paths.database) as connection:
        first_state = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
    database.migrate_database(paths.database)
    with database.connect(paths.database) as connection:
        second_state = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    migrated = database.get_transition_event(paths.database, str(legacy_event["event_id"]))
    assert migrated is not None and migrated["event_sequence"] is None
    assert migrated["authenticated_principal_id"] is None
    assert first_state == second_state
    assert first_state["legacy_event_count"] == 1
    assert first_state["head_sequence"] == 0
    assert version == database.DATABASE_SCHEMA_VERSION == 6
    assert paths.receipt_log.read_bytes() == original_jsonl

    native = _event("post-activation")
    database.record_transition_event(paths.database, native)
    project_transition_event(paths.database, paths.receipt_log, str(native["event_id"]))
    stored_native = database.get_transition_event(paths.database, str(native["event_id"]))
    assert stored_native is not None
    assert stored_native["event_sequence"] == 1
    assert stored_native["previous_event_hash"] == first_state["activation_hash"]
    result = verify_integrity(paths.database, paths.receipt_log)
    assert result.canonical_chain_valid and result.projection_valid
    assert result.legacy_events_checked == 1


def test_chain_fault_rolls_back_state_event_and_head(
    workspace: WorkspacePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    from governed_signal_to_content.evidence import ingest_signal

    with database.connect(workspace.database) as connection:
        initial_head = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
    original = database.insert_transition_event

    def fail_after_chain(
        connection: sqlite3.Connection, event: dict[str, object]
    ) -> dict[str, object]:
        original(connection, event)
        raise sqlite3.OperationalError("injected head persistence failure")

    monkeypatch.setattr(database, "insert_transition_event", fail_after_chain)
    with pytest.raises(sqlite3.OperationalError, match="injected"):
        ingest_signal(
            paths=workspace,
            title="Atomic chain failure",
            source_url="https://example.com/atomic-chain-failure",
            source_file=None,
        )
    with database.connect(workspace.database) as connection:
        final_head = dict(
            connection.execute("SELECT * FROM transition_event_chain_state").fetchone()
        )
        event_count = int(
            connection.execute("SELECT COUNT(*) FROM transition_events").fetchone()[0]
        )
    assert initial_head == final_head
    assert event_count == 0


def test_two_concurrent_writers_cannot_fork_the_chain(tmp_path: Path) -> None:
    paths = workspace_paths(tmp_path / "concurrent-workspace")
    database.initialize_workspace(paths)
    events = [_event("concurrent-a"), _event("concurrent-b")]
    barrier = Barrier(2)

    def append(event: dict[str, object]) -> None:
        barrier.wait()
        database.record_transition_event(paths.database, event)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(append, event) for event in events]
        for future in futures:
            future.result(timeout=15)

    rows = _chain_rows(paths)
    assert [row["event_sequence"] for row in rows] == [1, 2]
    assert rows[1]["previous_event_hash"] == rows[0]["event_hash"]
    assert verify_integrity(paths.database, paths.receipt_log).canonical_chain_valid


def test_verify_integrity_cli_is_read_only_and_uses_failure_exit_code(
    tmp_path: Path,
) -> None:
    paths = _chain_workspace(tmp_path, count=1)
    runner = CliRunner()
    clean = runner.invoke(
        cli.app, ["verify-integrity", "--workspace", str(paths.root)]
    )
    assert clean.exit_code == 0
    assert json.loads(clean.stdout)["canonical_chain_valid"] is True

    with sqlite3.connect(paths.database) as connection:
        connection.execute("UPDATE transition_events SET reason = 'tampered'")
    before_verification = paths.database.read_bytes()
    corrupt = runner.invoke(
        cli.app, ["verify-integrity", "--workspace", str(paths.root)]
    )
    assert corrupt.exit_code == 1
    assert json.loads(corrupt.stdout)["canonical_chain_valid"] is False
    assert paths.database.read_bytes() == before_verification


def test_verify_integrity_does_not_activate_schema2_database(tmp_path: Path) -> None:
    database_path = tmp_path / "schema2.sqlite"
    receipt_log = tmp_path / "receipts.jsonl"
    receipt_log.write_text("", encoding="utf-8")
    with sqlite3.connect(database_path) as connection:
        connection.execute("CREATE TABLE transition_events (event_id TEXT PRIMARY KEY)")
        connection.execute("PRAGMA user_version = 2")
    before = database_path.read_bytes()
    result = verify_integrity(database_path, receipt_log)
    assert not result.canonical_chain_valid
    assert result.failures[0].code == "chain_not_activated"
    assert database_path.read_bytes() == before
