"""SQLite persistence for authoritative workflow state."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import WorkspacePaths


SCHEMA = """
CREATE TABLE IF NOT EXISTS candidates (
    candidate_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    source_url TEXT NOT NULL,
    normalized_url TEXT,
    source_identity TEXT NOT NULL,
    development_identifiers_json TEXT NOT NULL DEFAULT '[]',
    state TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    normalized_json TEXT,
    classification_json TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES candidates(candidate_id),
    record_json TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    content_preserved INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS packets (
    packet_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES candidates(candidate_id),
    packet_path TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    packet_id TEXT NOT NULL REFERENCES packets(packet_id),
    actor TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    prior_state TEXT NOT NULL,
    decided_at_utc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_candidates_source_identity
ON candidates(source_identity);
CREATE INDEX IF NOT EXISTS idx_candidates_normalized_url
ON candidates(normalized_url);
CREATE INDEX IF NOT EXISTS idx_packets_candidate
ON packets(candidate_id);
"""


@contextmanager
def connect(database: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_workspace(paths: WorkspacePaths) -> None:
    for directory in (
        paths.root,
        paths.evidence,
        paths.candidates,
        paths.packets,
        paths.approvals,
        paths.receipts,
        paths.state,
    ):
        directory.mkdir(parents=True, exist_ok=True)
    paths.receipt_log.touch(exist_ok=True)
    with connect(paths.database) as connection:
        connection.executescript(SCHEMA)


def insert_candidate(database: Path, candidate: dict[str, object]) -> None:
    with connect(database) as connection:
        connection.execute(
            """
            INSERT INTO candidates (
                candidate_id, title, source_url, normalized_url,
                source_identity, development_identifiers_json, state, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                candidate["candidate_id"],
                candidate["title"],
                candidate["source_url"],
                candidate.get("normalized_url"),
                candidate["source_identity"],
                json.dumps(candidate.get("development_identifiers", [])),
                candidate["state"],
                candidate["created_at_utc"],
            ),
        )


def insert_evidence(database: Path, record: dict[str, object]) -> None:
    with connect(database) as connection:
        connection.execute(
            """
            INSERT INTO evidence (evidence_id, candidate_id, record_json, sha256, content_preserved)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                record["evidence_id"],
                record["candidate_id"],
                json.dumps(record, ensure_ascii=False, sort_keys=True),
                record["sha256"],
                int(bool(record["content_preserved"])),
            ),
        )


def get_candidate(database: Path, candidate_id: str) -> dict[str, object] | None:
    with connect(database) as connection:
        row = connection.execute(
            "SELECT * FROM candidates WHERE candidate_id = ?", (candidate_id,)
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["development_identifiers"] = json.loads(
        str(result.pop("development_identifiers_json"))
    )
    return result


def update_candidate_fields(database: Path, candidate_id: str, **fields: object) -> None:
    allowed = {
        "normalized_url",
        "source_identity",
        "development_identifiers_json",
        "state",
        "normalized_json",
        "classification_json",
    }
    if not fields or not set(fields).issubset(allowed):
        raise ValueError("Unsupported or empty candidate update")
    assignments = ", ".join(f"{name} = ?" for name in fields)
    with connect(database) as connection:
        cursor = connection.execute(
            f"UPDATE candidates SET {assignments} WHERE candidate_id = ?",  # noqa: S608
            (*fields.values(), candidate_id),
        )
        if cursor.rowcount != 1:
            raise KeyError(f"Unknown candidate: {candidate_id}")


def other_candidates(database: Path, candidate_id: str) -> list[dict[str, object]]:
    with connect(database) as connection:
        rows = connection.execute(
            "SELECT * FROM candidates WHERE candidate_id <> ?", (candidate_id,)
        ).fetchall()
    results: list[dict[str, object]] = []
    for row in rows:
        item = dict(row)
        item["development_identifiers"] = json.loads(
            str(item.pop("development_identifiers_json"))
        )
        results.append(item)
    return results


def insert_packet(database: Path, packet: dict[str, object]) -> None:
    with connect(database) as connection:
        connection.execute(
            """
            INSERT INTO packets (
                packet_id, candidate_id, packet_path, manifest_hash, state, created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                packet["packet_id"],
                packet["candidate_id"],
                packet["packet_path"],
                packet["manifest_hash"],
                packet["state"],
                packet["created_at_utc"],
            ),
        )


def get_packet(database: Path, packet_id: str) -> dict[str, object] | None:
    with connect(database) as connection:
        row = connection.execute(
            "SELECT * FROM packets WHERE packet_id = ?", (packet_id,)
        ).fetchone()
    return dict(row) if row is not None else None


def update_packet_and_candidate_state(
    database: Path, packet_id: str, candidate_id: str, state: str
) -> None:
    with connect(database) as connection:
        packet_cursor = connection.execute(
            "UPDATE packets SET state = ? WHERE packet_id = ?", (state, packet_id)
        )
        candidate_cursor = connection.execute(
            "UPDATE candidates SET state = ? WHERE candidate_id = ?", (state, candidate_id)
        )
        if packet_cursor.rowcount != 1 or candidate_cursor.rowcount != 1:
            raise KeyError("Packet or candidate disappeared during transition")


def insert_approval(database: Path, approval: dict[str, object]) -> None:
    with connect(database) as connection:
        connection.execute(
            """
            INSERT INTO approvals (
                approval_id, packet_id, actor, decision, reason,
                manifest_hash, prior_state, decided_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                approval["approval_id"],
                approval["packet_id"],
                approval["actor"],
                approval["decision"],
                approval["reason"],
                approval["manifest_hash"],
                approval["prior_state"],
                approval["decided_at_utc"],
            ),
        )


def state_counts(database: Path, table: str) -> dict[str, int]:
    if table not in {"candidates", "packets"}:
        raise ValueError("Unsupported table")
    with connect(database) as connection:
        rows = connection.execute(
            f"SELECT state, COUNT(*) AS count FROM {table} GROUP BY state"  # noqa: S608
        ).fetchall()
    return {str(row["state"]): int(row["count"]) for row in rows}
