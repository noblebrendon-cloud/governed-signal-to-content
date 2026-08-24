"""SQLite persistence for authoritative workflow state."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

from .config import WorkspacePaths
from .integrity import (
    CHAIN_ACTIVATION_DOMAIN,
    CHAIN_DOMAIN,
    CHAIN_HASH_ALGORITHM,
    CHAIN_ORIGIN,
    CHAIN_VERSION,
    LEGACY_ORDERING,
    CanonicalChainError,
    calculate_activation_hash,
    canonical_receipt_from_event,
    prepare_chained_event,
)


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
    scope_version TEXT CHECK (scope_version IS NULL OR scope_version = '1.0'),
    brand_id TEXT,
    channel_id TEXT,
    destination_id TEXT,
    state TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    CHECK (
        (scope_version IS NULL AND brand_id IS NULL
         AND channel_id IS NULL AND destination_id IS NULL)
        OR (scope_version = '1.0' AND brand_id IS NOT NULL
            AND channel_id IS NOT NULL AND destination_id IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS trusted_principals (
    principal_id TEXT PRIMARY KEY,
    authentication_scheme TEXT NOT NULL,
    key_id TEXT NOT NULL UNIQUE,
    public_key_b64 TEXT NOT NULL,
    verifier_fingerprint TEXT NOT NULL UNIQUE,
    bootstrapped_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transition_events (
    event_id TEXT PRIMARY KEY,
    command TEXT NOT NULL,
    asserted_actor TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    candidate_id TEXT,
    packet_id TEXT,
    prior_state TEXT,
    requested_state TEXT,
    resulting_state TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('accepted', 'rejected')),
    reason TEXT NOT NULL,
    governed_hash TEXT,
    input_identifiers_json TEXT NOT NULL,
    file_hashes_json TEXT NOT NULL,
    occurred_at_utc TEXT NOT NULL,
    application_version TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    receipt_projected_at_utc TEXT,
    authentication_status TEXT,
    authenticated_principal_id TEXT,
    authentication_scheme TEXT,
    authentication_key_id TEXT,
    authentication_verifier_fingerprint TEXT,
    authentication_operation_id TEXT,
    authentication_envelope_hash TEXT,
    authentication_proof_hash TEXT,
    authenticated_at_utc TEXT,
    authorization_status TEXT CHECK (
        authorization_status IN ('allowed', 'denied', 'not_evaluated')
    ),
    authorization_principal_id TEXT,
    authorization_required_capability TEXT,
    authorization_prior_state TEXT,
    authorization_requested_state TEXT,
    authorization_scope_version TEXT CHECK (
        authorization_scope_version IS NULL OR authorization_scope_version = '1.0'
    ),
    authorization_brand_id TEXT,
    authorization_channel_id TEXT,
    authorization_destination_id TEXT,
    authorization_matching_grant_id TEXT,
    authorization_reason_code TEXT
);

CREATE TABLE IF NOT EXISTS transition_event_chain_entries (
    event_id TEXT PRIMARY KEY REFERENCES transition_events(event_id) ON DELETE RESTRICT,
    chain_version TEXT NOT NULL CHECK (chain_version = '1.0'),
    chain_origin TEXT NOT NULL CHECK (chain_origin = 'native'),
    event_sequence INTEGER NOT NULL UNIQUE CHECK (event_sequence >= 1),
    previous_event_hash TEXT NOT NULL UNIQUE CHECK (
        length(previous_event_hash) = 64
        AND lower(previous_event_hash) = previous_event_hash
        AND previous_event_hash NOT GLOB '*[^0-9a-f]*'
    ),
    event_hash TEXT NOT NULL UNIQUE CHECK (
        length(event_hash) = 64
        AND lower(event_hash) = event_hash
        AND event_hash NOT GLOB '*[^0-9a-f]*'
    )
);

CREATE TABLE IF NOT EXISTS transition_event_chain_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    chain_version TEXT NOT NULL CHECK (chain_version = '1.0'),
    chain_origin TEXT NOT NULL CHECK (chain_origin = 'native'),
    hash_algorithm TEXT NOT NULL CHECK (hash_algorithm = 'sha256'),
    event_domain TEXT NOT NULL,
    activation_domain TEXT NOT NULL,
    legacy_ordering TEXT NOT NULL,
    legacy_event_count INTEGER NOT NULL CHECK (legacy_event_count >= 0),
    activation_hash TEXT NOT NULL CHECK (
        length(activation_hash) = 64
        AND lower(activation_hash) = activation_hash
        AND activation_hash NOT GLOB '*[^0-9a-f]*'
    ),
    head_sequence INTEGER NOT NULL CHECK (head_sequence >= 0),
    head_event_id TEXT REFERENCES transition_events(event_id) ON DELETE RESTRICT,
    head_event_hash TEXT NOT NULL CHECK (
        length(head_event_hash) = 64
        AND lower(head_event_hash) = head_event_hash
        AND head_event_hash NOT GLOB '*[^0-9a-f]*'
    ),
    CHECK (
        (head_sequence = 0 AND head_event_id IS NULL AND head_event_hash = activation_hash)
        OR (head_sequence > 0 AND head_event_id IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    packet_id TEXT NOT NULL REFERENCES packets(packet_id),
    actor TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    prior_state TEXT NOT NULL,
    decided_at_utc TEXT NOT NULL,
    transition_event_id TEXT NOT NULL UNIQUE REFERENCES transition_events(event_id),
    authenticated_principal_id TEXT,
    authenticated_operation_id TEXT,
    scope_version TEXT CHECK (scope_version IS NULL OR scope_version = '1.0'),
    brand_id TEXT,
    channel_id TEXT,
    destination_id TEXT,
    CHECK (
        (scope_version IS NULL AND brand_id IS NULL
         AND channel_id IS NULL AND destination_id IS NULL)
        OR (scope_version = '1.0' AND brand_id IS NOT NULL
            AND channel_id IS NOT NULL AND destination_id IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS authenticated_operations (
    operation_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES trusted_principals(principal_id),
    authentication_scheme TEXT NOT NULL,
    key_id TEXT NOT NULL,
    verifier_fingerprint TEXT NOT NULL,
    envelope_hash TEXT NOT NULL,
    proof_hash TEXT NOT NULL UNIQUE,
    envelope_json TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    verified_at_utc TEXT NOT NULL,
    consumed_at_utc TEXT NOT NULL,
    adjudication_event_id TEXT NOT NULL UNIQUE REFERENCES transition_events(event_id),
    adjudication_outcome TEXT NOT NULL CHECK (adjudication_outcome IN ('accepted', 'rejected'))
);

CREATE TABLE IF NOT EXISTS capability_grants (
    grant_id TEXT PRIMARY KEY CHECK (
        grant_id GLOB 'grant_*' AND length(grant_id) = 38
        AND substr(grant_id, 7) NOT GLOB '*[^0-9a-f]*'
    ),
    subject_principal_id TEXT NOT NULL REFERENCES trusted_principals(principal_id),
    capability TEXT NOT NULL CHECK (
        capability IN (
            'packet.approve', 'packet.reject', 'packet.release',
            'policy.manage_capabilities', 'effect.manage_bindings'
        )
    ),
    expected_prior_state TEXT,
    requested_state TEXT,
    scope_version TEXT CHECK (scope_version IS NULL OR scope_version = '1.0'),
    brand_id TEXT,
    channel_id TEXT,
    destination_id TEXT,
    granted_by_principal_id TEXT NOT NULL REFERENCES trusted_principals(principal_id),
    authenticated_operation_id TEXT NOT NULL UNIQUE
        REFERENCES authenticated_operations(operation_id),
    policy_event_id TEXT NOT NULL UNIQUE
        REFERENCES transition_events(event_id) ON DELETE RESTRICT,
    created_at_utc TEXT NOT NULL,
    application_version TEXT NOT NULL,
    CHECK (
        (capability = 'packet.approve'
         AND expected_prior_state = 'AWAITING_APPROVAL'
         AND requested_state = 'APPROVED')
        OR (capability = 'packet.reject'
            AND expected_prior_state = 'AWAITING_APPROVAL'
            AND requested_state = 'REJECTED')
        OR (capability = 'packet.release'
            AND expected_prior_state = 'APPROVED'
            AND requested_state = 'RELEASED')
        OR (capability = 'policy.manage_capabilities'
            AND expected_prior_state IS NULL AND requested_state IS NULL)
        OR (capability = 'effect.manage_bindings'
            AND expected_prior_state IS NULL AND requested_state IS NULL)
    ),
    CHECK (
        (scope_version IS NULL AND brand_id IS NULL
         AND channel_id IS NULL AND destination_id IS NULL)
        OR (scope_version = '1.0'
            AND capability IN ('policy.manage_capabilities', 'effect.manage_bindings')
            AND brand_id IS NULL AND channel_id IS NULL AND destination_id IS NULL)
        OR (scope_version = '1.0'
            AND capability NOT IN ('policy.manage_capabilities', 'effect.manage_bindings')
            AND brand_id IS NOT NULL AND channel_id IS NOT NULL
            AND destination_id IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS capability_revocations (
    revocation_id TEXT PRIMARY KEY CHECK (
        revocation_id GLOB 'revoke_*' AND length(revocation_id) = 39
        AND substr(revocation_id, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    grant_id TEXT NOT NULL UNIQUE REFERENCES capability_grants(grant_id),
    revoked_by_principal_id TEXT NOT NULL REFERENCES trusted_principals(principal_id),
    authenticated_operation_id TEXT NOT NULL UNIQUE
        REFERENCES authenticated_operations(operation_id),
    policy_event_id TEXT NOT NULL UNIQUE
        REFERENCES transition_events(event_id) ON DELETE RESTRICT,
    revoked_at_utc TEXT NOT NULL,
    application_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS capability_policy_state (
    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
    bootstrap_principal_id TEXT NOT NULL REFERENCES trusted_principals(principal_id),
    bootstrap_grant_id TEXT NOT NULL UNIQUE REFERENCES capability_grants(grant_id),
    bootstrap_operation_id TEXT NOT NULL UNIQUE
        REFERENCES authenticated_operations(operation_id),
    bootstrap_event_id TEXT NOT NULL UNIQUE
        REFERENCES transition_events(event_id) ON DELETE RESTRICT,
    bootstrapped_at_utc TEXT NOT NULL,
    application_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS external_destination_bindings (
    binding_id TEXT PRIMARY KEY CHECK (
        binding_id GLOB 'bind_*' AND length(binding_id) = 37
        AND substr(binding_id, 6) NOT GLOB '*[^0-9a-f]*'
    ),
    scope_version TEXT NOT NULL CHECK (scope_version = '1.0'),
    brand_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    destination_id TEXT NOT NULL,
    adapter_id TEXT NOT NULL CHECK (adapter_id = 'test.capture'),
    external_target_ref TEXT NOT NULL,
    credential_ref TEXT NOT NULL CHECK (
        credential_ref GLOB 'cred_*' AND length(credential_ref) BETWEEN 6 AND 64
    ),
    registered_by_principal_id TEXT NOT NULL
        REFERENCES trusted_principals(principal_id),
    authenticated_operation_id TEXT NOT NULL UNIQUE
        REFERENCES authenticated_operations(operation_id),
    registration_event_id TEXT NOT NULL UNIQUE
        REFERENCES transition_events(event_id) ON DELETE RESTRICT,
    created_at_utc TEXT NOT NULL,
    application_version TEXT NOT NULL,
    UNIQUE (scope_version, brand_id, channel_id, destination_id),
    UNIQUE (adapter_id, external_target_ref)
);

CREATE TABLE IF NOT EXISTS trusted_effect_executors (
    executor_id TEXT PRIMARY KEY CHECK (executor_id GLOB 'executor_*'),
    authentication_scheme TEXT NOT NULL CHECK (authentication_scheme = 'ed25519'),
    key_id TEXT NOT NULL UNIQUE,
    public_key_b64 TEXT NOT NULL,
    verifier_fingerprint TEXT NOT NULL UNIQUE CHECK (
        length(verifier_fingerprint) = 64
        AND lower(verifier_fingerprint) = verifier_fingerprint
        AND verifier_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    allowed_adapter_ids_json TEXT NOT NULL,
    registered_by_principal_id TEXT NOT NULL
        REFERENCES trusted_principals(principal_id),
    authenticated_operation_id TEXT NOT NULL UNIQUE
        REFERENCES authenticated_operations(operation_id),
    registration_event_id TEXT NOT NULL UNIQUE
        REFERENCES transition_events(event_id) ON DELETE RESTRICT,
    created_at_utc TEXT NOT NULL,
    application_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS external_effect_requests (
    effect_id TEXT PRIMARY KEY CHECK (
        effect_id GLOB 'effect_*' AND length(effect_id) = 39
        AND substr(effect_id, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    release_event_id TEXT NOT NULL UNIQUE
        REFERENCES transition_events(event_id) ON DELETE RESTRICT,
    packet_id TEXT NOT NULL REFERENCES packets(packet_id),
    candidate_id TEXT NOT NULL REFERENCES candidates(candidate_id),
    approval_id TEXT NOT NULL REFERENCES approvals(approval_id),
    approval_event_id TEXT NOT NULL REFERENCES transition_events(event_id),
    authenticated_principal_id TEXT NOT NULL
        REFERENCES trusted_principals(principal_id),
    authorizing_grant_id TEXT NOT NULL REFERENCES capability_grants(grant_id),
    capability TEXT NOT NULL CHECK (capability = 'packet.release'),
    scope_version TEXT NOT NULL CHECK (scope_version = '1.0'),
    brand_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    destination_id TEXT NOT NULL,
    destination_binding_id TEXT NOT NULL
        REFERENCES external_destination_bindings(binding_id),
    adapter_id TEXT NOT NULL CHECK (adapter_id = 'test.capture'),
    external_target_ref TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    packet_manifest_hash TEXT NOT NULL,
    packet_receipt_hash TEXT NOT NULL,
    release_event_hash TEXT NOT NULL,
    release_event_sequence INTEGER NOT NULL CHECK (release_event_sequence >= 1),
    idempotency_key TEXT NOT NULL UNIQUE CHECK (
        idempotency_key GLOB 'idem_*' AND length(idempotency_key) = 69
    ),
    request_hash TEXT NOT NULL UNIQUE CHECK (length(request_hash) = 64),
    created_at_utc TEXT NOT NULL,
    application_version TEXT NOT NULL,
    request_event_id TEXT NOT NULL UNIQUE
        REFERENCES transition_events(event_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS external_effect_dispatches (
    dispatch_id TEXT PRIMARY KEY CHECK (
        dispatch_id GLOB 'dispatch_*' AND length(dispatch_id) = 41
        AND substr(dispatch_id, 10) NOT GLOB '*[^0-9a-f]*'
    ),
    effect_id TEXT NOT NULL REFERENCES external_effect_requests(effect_id),
    effect_request_hash TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
    claimed_at_utc TEXT NOT NULL,
    application_version TEXT NOT NULL,
    dispatch_event_id TEXT NOT NULL UNIQUE
        REFERENCES transition_events(event_id) ON DELETE RESTRICT,
    UNIQUE (effect_id, attempt_number)
);

CREATE TABLE IF NOT EXISTS external_effect_results (
    result_id TEXT PRIMARY KEY CHECK (
        result_id GLOB 'result_*' AND length(result_id) = 39
        AND substr(result_id, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    effect_id TEXT NOT NULL REFERENCES external_effect_requests(effect_id),
    dispatch_id TEXT NOT NULL UNIQUE REFERENCES external_effect_dispatches(dispatch_id),
    executor_id TEXT NOT NULL REFERENCES trusted_effect_executors(executor_id),
    executor_key_id TEXT NOT NULL,
    effect_request_hash TEXT NOT NULL,
    adapter_id TEXT NOT NULL CHECK (adapter_id = 'test.capture'),
    scope_version TEXT NOT NULL CHECK (scope_version = '1.0'),
    brand_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    destination_id TEXT NOT NULL,
    destination_binding_id TEXT NOT NULL
        REFERENCES external_destination_bindings(binding_id),
    artifact_hash TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('SUCCEEDED', 'FAILED', 'UNKNOWN')),
    effect_may_have_occurred INTEGER NOT NULL CHECK (
        effect_may_have_occurred IN (0, 1)
    ),
    retry_permitted INTEGER NOT NULL CHECK (retry_permitted IN (0, 1)),
    remote_reference TEXT,
    response_hash TEXT,
    error_code TEXT,
    started_at_utc TEXT NOT NULL,
    completed_at_utc TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    envelope_hash TEXT NOT NULL,
    proof_hash TEXT NOT NULL UNIQUE,
    result_event_id TEXT NOT NULL UNIQUE
        REFERENCES transition_events(event_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_candidates_source_identity
ON candidates(source_identity);
CREATE INDEX IF NOT EXISTS idx_candidates_normalized_url
ON candidates(normalized_url);
CREATE INDEX IF NOT EXISTS idx_packets_candidate
ON packets(candidate_id);
CREATE INDEX IF NOT EXISTS idx_transition_events_target
ON transition_events(target_type, target_id, occurred_at_utc);
CREATE INDEX IF NOT EXISTS idx_transition_events_pending_projection
ON transition_events(receipt_projected_at_utc, occurred_at_utc);
CREATE INDEX IF NOT EXISTS idx_authenticated_operations_principal
ON authenticated_operations(principal_id, consumed_at_utc);
CREATE INDEX IF NOT EXISTS idx_capability_grants_effective
ON capability_grants(
    subject_principal_id, capability, expected_prior_state, requested_state,
    scope_version, brand_id, channel_id, destination_id, created_at_utc, grant_id
);
CREATE INDEX IF NOT EXISTS idx_capability_revocations_grant
ON capability_revocations(grant_id, revoked_at_utc);
CREATE INDEX IF NOT EXISTS idx_external_effect_requests_packet
ON external_effect_requests(packet_id, created_at_utc);
CREATE INDEX IF NOT EXISTS idx_external_effect_dispatches_effect
ON external_effect_dispatches(effect_id, attempt_number);
CREATE INDEX IF NOT EXISTS idx_external_effect_results_effect
ON external_effect_results(effect_id, completed_at_utc);
"""

DATABASE_SCHEMA_VERSION = 6


@contextmanager
def connect(database: Path, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(database, timeout=30.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        if immediate:
            connection.execute("BEGIN IMMEDIATE")
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
        _migrate_schema(connection)


def _upgrade_capability_grant_vocabulary(connection: sqlite3.Connection) -> None:
    """Rebuild the constrained grant table without changing any canonical row value."""
    table = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' "
        "AND name = 'capability_grants'"
    ).fetchone()
    if table is None or "effect.manage_bindings" in str(table["sql"]):
        return
    connection.commit()
    connection.execute("PRAGMA foreign_keys = OFF")
    try:
        connection.executescript(
            """
            BEGIN IMMEDIATE;
            CREATE TABLE capability_grants_v6 (
                grant_id TEXT PRIMARY KEY CHECK (
                    grant_id GLOB 'grant_*' AND length(grant_id) = 38
                    AND substr(grant_id, 7) NOT GLOB '*[^0-9a-f]*'
                ),
                subject_principal_id TEXT NOT NULL
                    REFERENCES trusted_principals(principal_id),
                capability TEXT NOT NULL CHECK (
                    capability IN (
                        'packet.approve', 'packet.reject', 'packet.release',
                        'policy.manage_capabilities', 'effect.manage_bindings'
                    )
                ),
                expected_prior_state TEXT,
                requested_state TEXT,
                scope_version TEXT CHECK (
                    scope_version IS NULL OR scope_version = '1.0'
                ),
                brand_id TEXT,
                channel_id TEXT,
                destination_id TEXT,
                granted_by_principal_id TEXT NOT NULL
                    REFERENCES trusted_principals(principal_id),
                authenticated_operation_id TEXT NOT NULL UNIQUE
                    REFERENCES authenticated_operations(operation_id),
                policy_event_id TEXT NOT NULL UNIQUE
                    REFERENCES transition_events(event_id) ON DELETE RESTRICT,
                created_at_utc TEXT NOT NULL,
                application_version TEXT NOT NULL,
                CHECK (
                    (capability = 'packet.approve'
                     AND expected_prior_state = 'AWAITING_APPROVAL'
                     AND requested_state = 'APPROVED')
                    OR (capability = 'packet.reject'
                        AND expected_prior_state = 'AWAITING_APPROVAL'
                        AND requested_state = 'REJECTED')
                    OR (capability = 'packet.release'
                        AND expected_prior_state = 'APPROVED'
                        AND requested_state = 'RELEASED')
                    OR (capability IN (
                            'policy.manage_capabilities', 'effect.manage_bindings'
                        )
                        AND expected_prior_state IS NULL
                        AND requested_state IS NULL)
                ),
                CHECK (
                    (scope_version IS NULL AND brand_id IS NULL
                     AND channel_id IS NULL AND destination_id IS NULL)
                    OR (scope_version = '1.0'
                        AND capability IN (
                            'policy.manage_capabilities', 'effect.manage_bindings'
                        )
                        AND brand_id IS NULL AND channel_id IS NULL
                        AND destination_id IS NULL)
                    OR (scope_version = '1.0'
                        AND capability NOT IN (
                            'policy.manage_capabilities', 'effect.manage_bindings'
                        )
                        AND brand_id IS NOT NULL AND channel_id IS NOT NULL
                        AND destination_id IS NOT NULL)
                )
            );
            INSERT INTO capability_grants_v6 (
                grant_id, subject_principal_id, capability,
                expected_prior_state, requested_state, scope_version,
                brand_id, channel_id, destination_id, granted_by_principal_id,
                authenticated_operation_id, policy_event_id, created_at_utc,
                application_version
            )
            SELECT grant_id, subject_principal_id, capability,
                   expected_prior_state, requested_state, scope_version,
                   brand_id, channel_id, destination_id, granted_by_principal_id,
                   authenticated_operation_id, policy_event_id, created_at_utc,
                   application_version
            FROM capability_grants;
            DROP TABLE capability_grants;
            ALTER TABLE capability_grants_v6 RENAME TO capability_grants;
            COMMIT;
            """
        )
    finally:
        connection.execute("PRAGMA foreign_keys = ON")
    violations = connection.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise RuntimeError("Capability grant migration produced foreign-key violations")


def _migrate_schema(connection: sqlite3.Connection) -> None:
    """Apply the small, deterministic, idempotent local schema migration."""
    starting_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    connection.executescript(SCHEMA)
    packet_columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(packets)").fetchall()
    }
    scope_column_definitions = {
        "scope_version": "TEXT CHECK (scope_version IS NULL OR scope_version = '1.0')",
        "brand_id": "TEXT",
        "channel_id": "TEXT",
        "destination_id": "TEXT",
    }
    for name, definition in scope_column_definitions.items():
        if name not in packet_columns:
            connection.execute(f"ALTER TABLE packets ADD COLUMN {name} {definition}")
    approval_columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(approvals)").fetchall()
    }
    if "transition_event_id" not in approval_columns:
        # Historical approvals predate canonical transition events. They remain
        # valid legacy evidence, so this migration intentionally leaves them NULL.
        connection.execute("ALTER TABLE approvals ADD COLUMN transition_event_id TEXT")
    for name in ("authenticated_principal_id", "authenticated_operation_id"):
        if name not in approval_columns:
            connection.execute(f"ALTER TABLE approvals ADD COLUMN {name} TEXT")
    for name, definition in scope_column_definitions.items():
        if name not in approval_columns:
            connection.execute(f"ALTER TABLE approvals ADD COLUMN {name} {definition}")
    transition_columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(transition_events)").fetchall()
    }
    for name in (
        "authentication_status",
        "authenticated_principal_id",
        "authentication_scheme",
        "authentication_key_id",
        "authentication_verifier_fingerprint",
        "authentication_operation_id",
        "authentication_envelope_hash",
        "authentication_proof_hash",
        "authenticated_at_utc",
    ):
        if name not in transition_columns:
            connection.execute(f"ALTER TABLE transition_events ADD COLUMN {name} TEXT")
    authorization_column_definitions = {
        "authorization_status": "TEXT CHECK (authorization_status IN ('allowed', 'denied', 'not_evaluated'))",
        "authorization_principal_id": "TEXT",
        "authorization_required_capability": "TEXT",
        "authorization_prior_state": "TEXT",
        "authorization_requested_state": "TEXT",
        "authorization_scope_version": "TEXT CHECK (authorization_scope_version IS NULL OR authorization_scope_version = '1.0')",
        "authorization_brand_id": "TEXT",
        "authorization_channel_id": "TEXT",
        "authorization_destination_id": "TEXT",
        "authorization_matching_grant_id": "TEXT",
        "authorization_reason_code": "TEXT",
    }
    for name, definition in authorization_column_definitions.items():
        if name not in transition_columns:
            connection.execute(
                f"ALTER TABLE transition_events ADD COLUMN {name} {definition}"
            )
    grant_columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(capability_grants)").fetchall()
    }
    for name, definition in scope_column_definitions.items():
        if name not in grant_columns:
            connection.execute(
                f"ALTER TABLE capability_grants ADD COLUMN {name} {definition}"
            )
    _upgrade_capability_grant_vocabulary(connection)
    connection.execute("DROP INDEX IF EXISTS idx_capability_grants_effective")
    connection.execute(
        """
        CREATE INDEX idx_capability_grants_effective
        ON capability_grants(
            subject_principal_id, capability, expected_prior_state,
            requested_state, scope_version, brand_id, channel_id,
            destination_id, created_at_utc, grant_id
        )
        """
    )
    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_approvals_transition_event
        ON approvals(transition_event_id)
        WHERE transition_event_id IS NOT NULL
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_transition_events_authenticated_principal
        ON transition_events(authenticated_principal_id, occurred_at_utc)
        """
    )
    chain_state = connection.execute(
        "SELECT * FROM transition_event_chain_state WHERE singleton_id = 1"
    ).fetchone()
    if chain_state is None:
        existing_entries = int(
            connection.execute(
                "SELECT COUNT(*) FROM transition_event_chain_entries"
            ).fetchone()[0]
        )
        if existing_entries:
            raise CanonicalChainError(
                "Cannot activate an event chain with entries but no chain state"
            )
        legacy_events = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM transition_events ORDER BY occurred_at_utc, event_id"
            ).fetchall()
        ]
        activation_hash = calculate_activation_hash(legacy_events)
        connection.execute(
            """
            INSERT INTO transition_event_chain_state (
                singleton_id, chain_version, chain_origin, hash_algorithm,
                event_domain, activation_domain, legacy_ordering,
                legacy_event_count, activation_hash, head_sequence,
                head_event_id, head_event_hash
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)
            """,
            (
                CHAIN_VERSION,
                CHAIN_ORIGIN,
                CHAIN_HASH_ALGORITHM,
                CHAIN_DOMAIN,
                CHAIN_ACTIVATION_DOMAIN,
                LEGACY_ORDERING,
                len(legacy_events),
                activation_hash,
                activation_hash,
            ),
        )
    else:
        expected = {
            "chain_version": CHAIN_VERSION,
            "chain_origin": CHAIN_ORIGIN,
            "hash_algorithm": CHAIN_HASH_ALGORITHM,
            "event_domain": CHAIN_DOMAIN,
            "activation_domain": CHAIN_ACTIVATION_DOMAIN,
            "legacy_ordering": LEGACY_ORDERING,
        }
        mismatches = [
            field for field, value in expected.items() if chain_state[field] != value
        ]
        if mismatches:
            raise CanonicalChainError(
                "Existing chain-state metadata is incompatible: "
                + ", ".join(sorted(mismatches))
            )
        if starting_version < DATABASE_SCHEMA_VERSION:
            legacy_events = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT e.* FROM transition_events AS e
                    LEFT JOIN transition_event_chain_entries AS c
                      ON c.event_id = e.event_id
                    WHERE c.event_id IS NULL
                    ORDER BY e.occurred_at_utc, e.event_id
                    """
                ).fetchall()
            ]
            if (
                int(chain_state["legacy_event_count"]) != len(legacy_events)
                or str(chain_state["activation_hash"])
                != calculate_activation_hash(legacy_events)
            ):
                raise CanonicalChainError(
                    "Existing legacy activation checkpoint does not match canonical history"
                )
    connection.execute(f"PRAGMA user_version = {DATABASE_SCHEMA_VERSION}")


def migrate_database(database: Path) -> None:
    """Make an existing workspace ready for canonical transition events."""
    with connect(database) as connection:
        _migrate_schema(connection)


def insert_candidate(database: Path, candidate: dict[str, object]) -> None:
    if candidate.get("state") != "DISCOVERED":
        raise ValueError("New candidates must begin in DISCOVERED")
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


def get_packet(database: Path, packet_id: str) -> dict[str, object] | None:
    with connect(database) as connection:
        row = connection.execute(
            "SELECT * FROM packets WHERE packet_id = ?", (packet_id,)
        ).fetchone()
    return dict(row) if row is not None else None


def insert_approval(
    connection: sqlite3.Connection, approval: dict[str, object]
) -> None:
    """Insert canonical approval evidence inside an existing transaction."""
    connection.execute(
        """
        INSERT INTO approvals (
            approval_id, packet_id, actor, decision, reason,
            manifest_hash, prior_state, decided_at_utc, transition_event_id,
            authenticated_principal_id, authenticated_operation_id,
            scope_version, brand_id, channel_id, destination_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            approval["transition_event_id"],
            approval.get("authenticated_principal_id"),
            approval.get("authenticated_operation_id"),
            approval.get("scope_version"),
            approval.get("brand_id"),
            approval.get("channel_id"),
            approval.get("destination_id"),
        ),
    )


def get_approved_approval(database: Path, packet_id: str) -> dict[str, object] | None:
    with connect(database) as connection:
        row = connection.execute(
            """
            SELECT * FROM approvals
            WHERE packet_id = ? AND decision = 'APPROVED'
            ORDER BY decided_at_utc DESC, approval_id DESC
            LIMIT 1
            """,
            (packet_id,),
        ).fetchone()
    return dict(row) if row is not None else None


def bootstrap_trusted_principal(database: Path, principal: dict[str, object]) -> None:
    """Register the only allowed empty-registry trust bootstrap."""
    migrate_database(database)
    with connect(database) as connection:
        # Serialize the empty-registry check with insertion. Without an immediate
        # write transaction, two local processes could both observe an empty table.
        connection.execute("BEGIN IMMEDIATE")
        existing = int(
            connection.execute("SELECT COUNT(*) FROM trusted_principals").fetchone()[0]
        )
        if existing != 0:
            raise PermissionError(
                "Trusted-principal bootstrap is closed because the registry is not empty"
            )
        connection.execute(
            """
            INSERT INTO trusted_principals (
                principal_id, authentication_scheme, key_id, public_key_b64,
                verifier_fingerprint, bootstrapped_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                principal["principal_id"],
                principal["authentication_scheme"],
                principal["key_id"],
                principal["public_key_b64"],
                principal["verifier_fingerprint"],
                principal["bootstrapped_at_utc"],
            ),
        )


def get_trusted_principal(database: Path, principal_id: str) -> dict[str, object] | None:
    with connect(database) as connection:
        row = connection.execute(
            "SELECT * FROM trusted_principals WHERE principal_id = ?", (principal_id,)
        ).fetchone()
    return dict(row) if row is not None else None


def get_capability_policy_state(database: Path) -> dict[str, object] | None:
    with connect(database) as connection:
        row = connection.execute(
            "SELECT * FROM capability_policy_state WHERE singleton_id = 1"
        ).fetchone()
    return dict(row) if row is not None else None


def get_capability_grant(database: Path, grant_id: str) -> dict[str, object] | None:
    with connect(database) as connection:
        row = connection.execute(
            """
            SELECT g.*, r.revocation_id, r.revoked_at_utc,
                   c.event_sequence AS grant_event_sequence
            FROM capability_grants AS g
            JOIN transition_event_chain_entries AS c
              ON c.event_id = g.policy_event_id
            LEFT JOIN capability_revocations AS r ON r.grant_id = g.grant_id
            WHERE g.grant_id = ?
            """,
            (grant_id,),
        ).fetchone()
    return dict(row) if row is not None else None


def list_capability_grants(
    database: Path, principal_id: str | None = None
) -> list[dict[str, object]]:
    query = """
        SELECT g.*, r.revocation_id, r.revoked_by_principal_id,
               r.revoked_at_utc, c.event_sequence AS grant_event_sequence,
               CASE WHEN r.revocation_id IS NULL THEN 1 ELSE 0 END AS active
        FROM capability_grants AS g
        JOIN transition_event_chain_entries AS c ON c.event_id = g.policy_event_id
        LEFT JOIN capability_revocations AS r ON r.grant_id = g.grant_id
    """
    parameters: tuple[object, ...] = ()
    if principal_id is not None:
        query += " WHERE g.subject_principal_id = ?"
        parameters = (principal_id,)
    query += " ORDER BY c.event_sequence, g.grant_id"
    with connect(database) as connection:
        return [dict(row) for row in connection.execute(query, parameters).fetchall()]


def _insert_capability_grant(
    connection: sqlite3.Connection, grant: dict[str, object]
) -> None:
    connection.execute(
        """
        INSERT INTO capability_grants (
            grant_id, subject_principal_id, capability, expected_prior_state,
            requested_state, scope_version, brand_id, channel_id,
            destination_id, granted_by_principal_id,
            authenticated_operation_id, policy_event_id, created_at_utc,
            application_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            grant["grant_id"],
            grant["subject_principal_id"],
            grant["capability"],
            grant.get("expected_prior_state"),
            grant.get("requested_state"),
            grant.get("scope_version"),
            grant.get("brand_id"),
            grant.get("channel_id"),
            grant.get("destination_id"),
            grant["granted_by_principal_id"],
            grant["authenticated_operation_id"],
            grant["policy_event_id"],
            grant["created_at_utc"],
            grant["application_version"],
        ),
    )


def _insert_capability_revocation(
    connection: sqlite3.Connection, revocation: dict[str, object]
) -> None:
    connection.execute(
        """
        INSERT INTO capability_revocations (
            revocation_id, grant_id, revoked_by_principal_id,
            authenticated_operation_id, policy_event_id, revoked_at_utc,
            application_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            revocation["revocation_id"],
            revocation["grant_id"],
            revocation["revoked_by_principal_id"],
            revocation["authenticated_operation_id"],
            revocation["policy_event_id"],
            revocation["revoked_at_utc"],
            revocation["application_version"],
        ),
    )


def find_consumed_authenticated_operation(
    database: Path, operation_id: str, proof_hash: str
) -> dict[str, object] | None:
    with connect(database) as connection:
        row = connection.execute(
            """
            SELECT * FROM authenticated_operations
            WHERE operation_id = ? OR proof_hash = ?
            LIMIT 1
            """,
            (operation_id, proof_hash),
        ).fetchone()
    return dict(row) if row is not None else None


def insert_authenticated_operation(
    connection: sqlite3.Connection,
    operation: dict[str, object],
    *,
    adjudication_event_id: str,
    adjudication_outcome: str,
) -> None:
    connection.execute(
        """
        INSERT INTO authenticated_operations (
            operation_id, principal_id, authentication_scheme, key_id,
            verifier_fingerprint, envelope_hash, proof_hash, envelope_json,
            signature_b64, verified_at_utc, consumed_at_utc,
            adjudication_event_id, adjudication_outcome
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            operation["operation_id"],
            operation["principal_id"],
            operation["authentication_scheme"],
            operation["key_id"],
            operation["verifier_fingerprint"],
            operation["envelope_hash"],
            operation["proof_hash"],
            operation["envelope_json"],
            operation["signature_b64"],
            operation["verified_at_utc"],
            operation["consumed_at_utc"],
            adjudication_event_id,
            adjudication_outcome,
        ),
    )


def insert_transition_event(
    connection: sqlite3.Connection, event: dict[str, object]
) -> dict[str, object]:
    chain_state_row = connection.execute(
        "SELECT * FROM transition_event_chain_state WHERE singleton_id = 1"
    ).fetchone()
    if chain_state_row is None:
        raise CanonicalChainError("Canonical event chain is not activated")
    chain_state = dict(chain_state_row)
    expected_metadata = {
        "chain_version": CHAIN_VERSION,
        "chain_origin": CHAIN_ORIGIN,
        "hash_algorithm": CHAIN_HASH_ALGORITHM,
        "event_domain": CHAIN_DOMAIN,
        "activation_domain": CHAIN_ACTIVATION_DOMAIN,
        "legacy_ordering": LEGACY_ORDERING,
    }
    mismatches = [
        field
        for field, expected in expected_metadata.items()
        if chain_state.get(field) != expected
    ]
    if mismatches:
        raise CanonicalChainError(
            "Canonical chain-state metadata mismatch: "
            + ", ".join(sorted(mismatches))
        )

    try:
        head_sequence = int(chain_state["head_sequence"])
    except (TypeError, ValueError) as error:
        raise CanonicalChainError(
            "Canonical chain head sequence is not an integer"
        ) from error
    if head_sequence < 0:
        raise CanonicalChainError("Canonical chain head sequence is negative")
    head_event_id = chain_state.get("head_event_id")
    head_event_hash = str(chain_state["head_event_hash"])
    activation_hash = str(chain_state["activation_hash"])
    if head_sequence == 0:
        if head_event_id is not None or head_event_hash != activation_hash:
            raise CanonicalChainError("Canonical genesis head is inconsistent")
        legacy_events = [
            dict(row)
            for row in connection.execute(
                """
                SELECT e.* FROM transition_events AS e
                LEFT JOIN transition_event_chain_entries AS c
                  ON c.event_id = e.event_id
                WHERE c.event_id IS NULL
                ORDER BY e.occurred_at_utc, e.event_id
                """
            ).fetchall()
        ]
        if (
            int(chain_state["legacy_event_count"]) != len(legacy_events)
            or calculate_activation_hash(legacy_events) != activation_hash
        ):
            raise CanonicalChainError(
                "Canonical legacy activation checkpoint is inconsistent"
            )
    else:
        tail_row = connection.execute(
            """
            SELECT e.*, c.chain_version, c.chain_origin, c.event_sequence,
                   c.previous_event_hash, c.event_hash
            FROM transition_event_chain_entries AS c
            JOIN transition_events AS e ON e.event_id = c.event_id
            WHERE c.event_sequence = ?
            """,
            (head_sequence,),
        ).fetchone()
        if (
            tail_row is None
            or tail_row["event_id"] != head_event_id
            or tail_row["event_hash"] != head_event_hash
        ):
            raise CanonicalChainError("Canonical chain head does not match its tail event")
        tail = dict(tail_row)
        canonical_receipt_from_event(tail)
        if head_sequence == 1:
            expected_previous_hash = activation_hash
        else:
            predecessor = connection.execute(
                """
                SELECT event_hash FROM transition_event_chain_entries
                WHERE event_sequence = ?
                """,
                (head_sequence - 1,),
            ).fetchone()
            if predecessor is None:
                raise CanonicalChainError("Canonical chain tail predecessor is missing")
            expected_previous_hash = str(predecessor["event_hash"])
        if tail["previous_event_hash"] != expected_previous_hash:
            raise CanonicalChainError("Canonical chain tail predecessor is inconsistent")

    event_sequence = head_sequence + 1
    prepared = prepare_chained_event(
        event,
        event_sequence=event_sequence,
        previous_event_hash=head_event_hash,
    )
    connection.execute(
        """
        INSERT INTO transition_events (
            event_id, command, asserted_actor, target_type, target_id,
            candidate_id, packet_id, prior_state, requested_state,
            resulting_state, outcome, reason, governed_hash,
            input_identifiers_json, file_hashes_json, occurred_at_utc,
            application_version, receipt_json, receipt_projected_at_utc,
            authentication_status, authenticated_principal_id,
            authentication_scheme, authentication_key_id,
            authentication_verifier_fingerprint, authentication_operation_id,
            authentication_envelope_hash, authentication_proof_hash,
            authenticated_at_utc, authorization_status,
            authorization_principal_id, authorization_required_capability,
            authorization_prior_state, authorization_requested_state,
            authorization_scope_version, authorization_brand_id,
            authorization_channel_id, authorization_destination_id,
            authorization_matching_grant_id, authorization_reason_code
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            event["event_id"],
            event["command"],
            event["asserted_actor"],
            event["target_type"],
            event["target_id"],
            event.get("candidate_id"),
            event.get("packet_id"),
            event.get("prior_state"),
            event.get("requested_state"),
            event.get("resulting_state"),
            event["outcome"],
            event["reason"],
            event.get("governed_hash"),
            event["input_identifiers_json"],
            event["file_hashes_json"],
            event["occurred_at_utc"],
            event["application_version"],
            prepared.receipt_json,
            event.get("authentication_status"),
            event.get("authenticated_principal_id"),
            event.get("authentication_scheme"),
            event.get("authentication_key_id"),
            event.get("authentication_verifier_fingerprint"),
            event.get("authentication_operation_id"),
            event.get("authentication_envelope_hash"),
            event.get("authentication_proof_hash"),
            event.get("authenticated_at_utc"),
            event.get("authorization_status"),
            event.get("authorization_principal_id"),
            event.get("authorization_required_capability"),
            event.get("authorization_prior_state"),
            event.get("authorization_requested_state"),
            event.get("authorization_scope_version"),
            event.get("authorization_brand_id"),
            event.get("authorization_channel_id"),
            event.get("authorization_destination_id"),
            event.get("authorization_matching_grant_id"),
            event.get("authorization_reason_code"),
        ),
    )
    connection.execute(
        """
        INSERT INTO transition_event_chain_entries (
            event_id, chain_version, chain_origin, event_sequence,
            previous_event_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            event["event_id"],
            prepared.chain_version,
            prepared.chain_origin,
            prepared.event_sequence,
            prepared.previous_event_hash,
            prepared.event_hash,
        ),
    )
    cursor = connection.execute(
        """
        UPDATE transition_event_chain_state
        SET head_sequence = ?, head_event_id = ?, head_event_hash = ?
        WHERE singleton_id = 1 AND head_sequence = ?
          AND head_event_hash = ? AND head_event_id IS ?
        """,
        (
            prepared.event_sequence,
            event["event_id"],
            prepared.event_hash,
            head_sequence,
            head_event_hash,
            head_event_id,
        ),
    )
    if cursor.rowcount != 1:
        raise CanonicalChainError("Canonical chain head changed during event append")
    return {
        **event,
        "receipt_json": prepared.receipt_json,
        "chain_version": prepared.chain_version,
        "chain_origin": prepared.chain_origin,
        "event_sequence": prepared.event_sequence,
        "previous_event_hash": prepared.previous_event_hash,
        "event_hash": prepared.event_hash,
    }


def _validate_authorization_event(
    event: dict[str, object],
    decision: object,
    authenticated_operation: dict[str, object],
    *,
    accepted: bool,
) -> None:
    expected = {
        "authentication_status": "verified",
        "authenticated_principal_id": authenticated_operation.get("principal_id"),
        "authentication_operation_id": authenticated_operation.get("operation_id"),
        "authorization_status": getattr(decision, "status").value,
        "authorization_principal_id": getattr(decision, "principal_id"),
        "authorization_required_capability": getattr(
            decision, "required_capability"
        ),
        "authorization_prior_state": (
            None
            if getattr(decision, "actual_prior_state") is None
            else getattr(decision, "actual_prior_state").value
        ),
        "authorization_requested_state": (
            None
            if getattr(decision, "requested_state") is None
            else getattr(decision, "requested_state").value
        ),
        "authorization_scope_version": getattr(decision, "scope_version"),
        "authorization_brand_id": getattr(decision, "brand_id"),
        "authorization_channel_id": getattr(decision, "channel_id"),
        "authorization_destination_id": getattr(decision, "destination_id"),
        "authorization_matching_grant_id": getattr(
            decision, "matching_grant_id"
        ),
        "authorization_reason_code": getattr(decision, "reason").value,
        "outcome": "accepted" if accepted else "rejected",
    }
    mismatches = [field for field, value in expected.items() if event.get(field) != value]
    if mismatches:
        raise ValueError(
            "Canonical event authorization evidence mismatch: "
            + ", ".join(sorted(mismatches))
        )


def record_transition_event(
    database: Path,
    event: dict[str, object],
    authenticated_operation: dict[str, object] | None = None,
) -> None:
    """Commit a non-mutating (normally rejected) attempt as its own event."""
    with connect(database, immediate=True) as connection:
        insert_transition_event(connection, event)
        if authenticated_operation is not None:
            insert_authenticated_operation(
                connection,
                authenticated_operation,
                adjudication_event_id=str(event["event_id"]),
                adjudication_outcome=str(event["outcome"]),
            )


def apply_candidate_transition(
    database: Path,
    *,
    candidate_id: str,
    prior_state: str,
    resulting_state: str,
    event: dict[str, object],
    packet: dict[str, object] | None = None,
) -> None:
    """Atomically update candidate state, event, and optional generated packet."""
    if (prior_state, resulting_state) in AUTHORITY_SENSITIVE_STATE_PAIRS:
        raise PermissionError(
            "Authority-sensitive candidate transitions require the TransitionMediator"
        )
    with connect(database, immediate=True) as connection:
        if packet is not None:
            connection.execute(
                """
                INSERT INTO packets (
                    packet_id, candidate_id, packet_path, manifest_hash,
                    scope_version, brand_id, channel_id, destination_id,
                    state, created_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    packet["packet_id"],
                    packet["candidate_id"],
                    packet["packet_path"],
                    packet["manifest_hash"],
                    packet.get("scope_version"),
                    packet.get("brand_id"),
                    packet.get("channel_id"),
                    packet.get("destination_id"),
                    packet["state"],
                    packet["created_at_utc"],
                ),
            )
        cursor = connection.execute(
            """
            UPDATE candidates SET state = ?
            WHERE candidate_id = ? AND state = ?
            """,
            (resulting_state, candidate_id, prior_state),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("Candidate state changed before transition commit")
        insert_transition_event(connection, event)


AUTHORITY_SENSITIVE_STATE_PAIRS = frozenset(
    {
        ("AWAITING_APPROVAL", "APPROVED"),
        ("AWAITING_APPROVAL", "REJECTED"),
        ("APPROVED", "RELEASED"),
    }
)


def _commit_packet_transition(
    database: Path,
    *,
    packet_id: str,
    candidate_id: str,
    prior_state: str,
    resulting_state: str,
    event: dict[str, object],
    approval: dict[str, object] | None = None,
    authenticated_operation: dict[str, object] | None = None,
    required_packet_manifest: str | None = None,
    required_approval_manifest: str | None = None,
    required_approval_id: str | None = None,
    required_approval_event_id: str | None = None,
) -> None:
    """Atomically update paired state, evidence the transition, and decide if supplied."""
    with connect(database, immediate=True) as connection:
        packet = connection.execute(
            "SELECT candidate_id, state, manifest_hash FROM packets WHERE packet_id = ?",
            (packet_id,),
        ).fetchone()
        candidate = connection.execute(
            "SELECT state FROM candidates WHERE candidate_id = ?",
            (candidate_id,),
        ).fetchone()
        if packet is None or candidate is None:
            raise KeyError("Packet or candidate disappeared during transition")
        if str(packet["candidate_id"]) != candidate_id:
            raise RuntimeError("Packet/candidate identity changed before transition commit")
        if str(packet["state"]) != prior_state or str(candidate["state"]) != prior_state:
            raise RuntimeError("Packet/candidate paired state changed before transition commit")
        if (
            required_packet_manifest is not None
            and str(packet["manifest_hash"]) != required_packet_manifest
        ):
            raise RuntimeError("Packet manifest binding changed before transition commit")
        if required_approval_manifest is not None:
            approved = connection.execute(
                """
                SELECT approval_id, transition_event_id, manifest_hash FROM approvals
                WHERE packet_id = ? AND approval_id = ? AND decision = 'APPROVED'
                """,
                (packet_id, required_approval_id),
            ).fetchone()
            if approved is None:
                raise RuntimeError("Release requires a canonical approved decision")
            if (
                str(packet["manifest_hash"]) != required_approval_manifest
                or str(approved["manifest_hash"]) != required_approval_manifest
                or str(approved["approval_id"]) != required_approval_id
                or approved["transition_event_id"] != required_approval_event_id
            ):
                raise RuntimeError("Release approval binding changed before transition commit")
        packet_cursor = connection.execute(
            "UPDATE packets SET state = ? WHERE packet_id = ? AND state = ?",
            (resulting_state, packet_id, prior_state),
        )
        candidate_cursor = connection.execute(
            "UPDATE candidates SET state = ? WHERE candidate_id = ? AND state = ?",
            (resulting_state, candidate_id, prior_state),
        )
        if packet_cursor.rowcount != 1 or candidate_cursor.rowcount != 1:
            raise RuntimeError("Packet/candidate paired state changed before transition commit")
        insert_transition_event(connection, event)
        if approval is not None:
            insert_approval(connection, approval)
        if authenticated_operation is not None:
            insert_authenticated_operation(
                connection,
                authenticated_operation,
                adjudication_event_id=str(event["event_id"]),
                adjudication_outcome=str(event["outcome"]),
            )


def apply_packet_transition(
    database: Path,
    *,
    packet_id: str,
    candidate_id: str,
    prior_state: str,
    resulting_state: str,
    event: dict[str, object],
) -> None:
    """Commit only non-authority packet progression through the state machine."""
    if (prior_state, resulting_state) in AUTHORITY_SENSITIVE_STATE_PAIRS:
        raise PermissionError(
            "Authority-sensitive packet transitions require the TransitionMediator"
        )
    _commit_packet_transition(
        database,
        packet_id=packet_id,
        candidate_id=candidate_id,
        prior_state=prior_state,
        resulting_state=resulting_state,
        event=event,
    )


def _evaluate_transaction_authorization(
    connection: sqlite3.Connection,
    *,
    principal_id: str,
    required_capability: object,
    actual_prior_state: object,
    requested_state: object,
    packet: sqlite3.Row,
    request_scope_version: str | None,
    request_brand_id: str | None,
    request_channel_id: str | None,
    request_destination_id: str | None,
) -> object:
    from .authorization import CapabilityPolicyEvaluator, denied_decision
    from .models import AuthorizationReason

    packet_scope = (
        packet["scope_version"],
        packet["brand_id"],
        packet["channel_id"],
        packet["destination_id"],
    )
    if packet_scope[0] != "1.0" or None in packet_scope[1:]:
        return denied_decision(
            principal_id=principal_id,
            required_capability=required_capability,  # type: ignore[arg-type]
            reason=AuthorizationReason.SCOPE_REQUIRED,
            actual_prior_state=actual_prior_state,  # type: ignore[arg-type]
            requested_state=requested_state,  # type: ignore[arg-type]
        )
    actual_brand, actual_channel, actual_destination = (
        str(packet_scope[1]),
        str(packet_scope[2]),
        str(packet_scope[3]),
    )
    if request_scope_version != "1.0" or None in (
        request_brand_id,
        request_channel_id,
        request_destination_id,
    ):
        return denied_decision(
            principal_id=principal_id,
            required_capability=required_capability,  # type: ignore[arg-type]
            reason=AuthorizationReason.SCOPE_REQUIRED,
            actual_prior_state=actual_prior_state,  # type: ignore[arg-type]
            requested_state=requested_state,  # type: ignore[arg-type]
            brand_id=actual_brand,
            channel_id=actual_channel,
            destination_id=actual_destination,
        )
    if (
        request_brand_id,
        request_channel_id,
        request_destination_id,
    ) != (actual_brand, actual_channel, actual_destination):
        return denied_decision(
            principal_id=principal_id,
            required_capability=required_capability,  # type: ignore[arg-type]
            reason=AuthorizationReason.REQUEST_SCOPE_MISMATCH,
            actual_prior_state=actual_prior_state,  # type: ignore[arg-type]
            requested_state=requested_state,  # type: ignore[arg-type]
            brand_id=actual_brand,
            channel_id=actual_channel,
            destination_id=actual_destination,
        )
    return CapabilityPolicyEvaluator.evaluate(
        connection,
        principal_id=principal_id,
        required_capability=required_capability,  # type: ignore[arg-type]
        actual_prior_state=actual_prior_state,  # type: ignore[arg-type]
        requested_state=requested_state,  # type: ignore[arg-type]
        brand_id=actual_brand,
        channel_id=actual_channel,
        destination_id=actual_destination,
    )


def _commit_authority_transition(
    database: Path,
    *,
    operation: str,
    packet_id: str,
    candidate_id: str,
    prior_state: str,
    resulting_state: str,
    event_factory: Callable[[object, bool, str], dict[str, object]],
    authenticated_operation: dict[str, object],
    approval_factory: Callable[[str, str], dict[str, object]] | None,
    required_packet_manifest: str,
    required_approval_manifest: str | None = None,
    required_approval_id: str | None = None,
    required_approval_event_id: str | None = None,
    request_scope_version: str | None,
    request_brand_id: str | None,
    request_channel_id: str | None,
    request_destination_id: str | None,
) -> tuple[dict[str, object], object, bool]:
    """Atomically authorize and adjudicate one packet authority request."""
    from .authorization import REQUIRED_CAPABILITIES
    from .models import AuthorityOperation, WorkflowState

    if (prior_state, resulting_state) not in AUTHORITY_SENSITIVE_STATE_PAIRS:
        raise ValueError("Canonical authority commit received a non-authority state pair")
    authority_operation = AuthorityOperation(operation)
    required_capability = REQUIRED_CAPABILITIES[authority_operation][0]
    with connect(database, immediate=True) as connection:
        packet = connection.execute(
            """
            SELECT candidate_id, state, manifest_hash, scope_version,
                   brand_id, channel_id, destination_id
            FROM packets WHERE packet_id = ?
            """,
            (packet_id,),
        ).fetchone()
        candidate = connection.execute(
            "SELECT state FROM candidates WHERE candidate_id = ?", (candidate_id,)
        ).fetchone()
        if packet is None or candidate is None:
            raise KeyError("Packet or candidate disappeared during transition")
        if str(packet["candidate_id"]) != candidate_id:
            raise RuntimeError("Packet/candidate identity changed before transition commit")
        actual_prior = WorkflowState(str(packet["state"]))
        requested = WorkflowState(resulting_state)
        if str(candidate["state"]) != actual_prior.value:
            raise RuntimeError("Packet/candidate paired state changed before transition commit")
        decision = _evaluate_transaction_authorization(
            connection,
            principal_id=str(authenticated_operation["principal_id"]),
            required_capability=required_capability,
            actual_prior_state=actual_prior,
            requested_state=requested,
            packet=packet,
            request_scope_version=request_scope_version,
            request_brand_id=request_brand_id,
            request_channel_id=request_channel_id,
            request_destination_id=request_destination_id,
        )
        if not decision.allowed:
            reason = f"Authorization denied: {decision.reason.value}"
            rejected_event = event_factory(decision, False, reason)
            _validate_authorization_event(
                rejected_event, decision, authenticated_operation, accepted=False
            )
            stored = insert_transition_event(connection, rejected_event)
            insert_authenticated_operation(
                connection,
                authenticated_operation,
                adjudication_event_id=str(rejected_event["event_id"]),
                adjudication_outcome="rejected",
            )
            return stored, decision, False

        if actual_prior.value != prior_state:
            raise RuntimeError("Packet/candidate paired state changed before transition commit")
        if str(packet["manifest_hash"]) != required_packet_manifest:
            raise RuntimeError("Packet manifest binding changed before transition commit")
        if required_approval_manifest is not None:
            approved = connection.execute(
                """
                SELECT approval_id, transition_event_id, manifest_hash,
                       scope_version, brand_id, channel_id, destination_id
                FROM approvals
                WHERE packet_id = ? AND approval_id = ? AND decision = 'APPROVED'
                """,
                (packet_id, required_approval_id),
            ).fetchone()
            if approved is None:
                raise RuntimeError("Release requires a canonical approved decision")
            if (
                str(packet["manifest_hash"]) != required_approval_manifest
                or str(approved["manifest_hash"]) != required_approval_manifest
                or str(approved["approval_id"]) != required_approval_id
                or approved["transition_event_id"] != required_approval_event_id
                or approved["scope_version"] != packet["scope_version"]
                or approved["brand_id"] != packet["brand_id"]
                or approved["channel_id"] != packet["channel_id"]
                or approved["destination_id"] != packet["destination_id"]
            ):
                raise RuntimeError("Release approval binding changed before transition commit")

        accepted_event = event_factory(decision, True, "")
        _validate_authorization_event(
            accepted_event, decision, authenticated_operation, accepted=True
        )
        packet_cursor = connection.execute(
            "UPDATE packets SET state = ? WHERE packet_id = ? AND state = ?",
            (resulting_state, packet_id, prior_state),
        )
        candidate_cursor = connection.execute(
            "UPDATE candidates SET state = ? WHERE candidate_id = ? AND state = ?",
            (resulting_state, candidate_id, prior_state),
        )
        if packet_cursor.rowcount != 1 or candidate_cursor.rowcount != 1:
            raise RuntimeError("Packet/candidate paired state changed before transition commit")
        stored = insert_transition_event(connection, accepted_event)
        if approval_factory is not None:
            insert_approval(
                connection,
                approval_factory(
                    str(accepted_event["event_id"]),
                    str(accepted_event["occurred_at_utc"]),
                ),
            )
        insert_authenticated_operation(
            connection,
            authenticated_operation,
            adjudication_event_id=str(accepted_event["event_id"]),
            adjudication_outcome="accepted",
        )
        return stored, decision, True


def record_authenticated_authorization_rejection(
    database: Path,
    *,
    operation: str,
    principal_id: str,
    actual_prior_state: str,
    requested_state: str,
    packet_id: str,
    request_scope_version: str | None,
    request_brand_id: str | None,
    request_channel_id: str | None,
    request_destination_id: str | None,
    authenticated_operation: dict[str, object],
    event_factory: Callable[[object], dict[str, object]],
) -> tuple[dict[str, object], object]:
    """Persist an already-rejected authenticated request with current policy evidence."""
    from .authorization import REQUIRED_CAPABILITIES
    from .models import AuthorityOperation, WorkflowState

    authority_operation = AuthorityOperation(operation)
    required_capability = REQUIRED_CAPABILITIES[authority_operation][0]
    with connect(database, immediate=True) as connection:
        packet = connection.execute(
            """
            SELECT scope_version, brand_id, channel_id, destination_id
            FROM packets WHERE packet_id = ?
            """,
            (packet_id,),
        ).fetchone()
        if packet is None:
            from .authorization import denied_decision
            from .models import AuthorizationReason

            decision = denied_decision(
                principal_id=principal_id,
                required_capability=required_capability,
                reason=AuthorizationReason.SCOPE_REQUIRED,
                actual_prior_state=WorkflowState(actual_prior_state),
                requested_state=WorkflowState(requested_state),
            )
        else:
            decision = _evaluate_transaction_authorization(
                connection,
                principal_id=principal_id,
                required_capability=required_capability,
                actual_prior_state=WorkflowState(actual_prior_state),
                requested_state=WorkflowState(requested_state),
                packet=packet,
                request_scope_version=request_scope_version,
                request_brand_id=request_brand_id,
                request_channel_id=request_channel_id,
                request_destination_id=request_destination_id,
            )
        event = event_factory(decision)
        _validate_authorization_event(
            event, decision, authenticated_operation, accepted=False
        )
        stored = insert_transition_event(connection, event)
        insert_authenticated_operation(
            connection,
            authenticated_operation,
            adjudication_event_id=str(event["event_id"]),
            adjudication_outcome="rejected",
        )
        return stored, decision


def _commit_capability_policy_operation(
    database: Path,
    *,
    request: dict[str, object],
    authenticated_operation: dict[str, object],
    event_factory: Callable[[object, bool, str], dict[str, object]],
) -> tuple[dict[str, object], object, bool]:
    """Atomically authorize and commit one canonical capability-policy operation."""
    from .authorization import (
        CapabilityPolicyEvaluator,
        bootstrap_decision,
        denied_decision,
    )
    from .models import AuthorizationReason, Capability, CapabilityPolicyOperation

    operation = CapabilityPolicyOperation(str(request["operation"]))
    principal_id = str(authenticated_operation["principal_id"])
    capability = Capability(str(request["capability"]))
    with connect(database, immediate=True) as connection:
        accepted = True
        rejection_reason = ""
        if operation is CapabilityPolicyOperation.BOOTSTRAP:
            policy_exists = connection.execute(
                "SELECT 1 FROM capability_policy_state WHERE singleton_id = 1"
            ).fetchone()
            policy_rows = int(
                connection.execute(
                    "SELECT (SELECT COUNT(*) FROM capability_grants) + "
                    "(SELECT COUNT(*) FROM capability_revocations)"
                ).fetchone()[0]
            )
            trusted = connection.execute(
                "SELECT principal_id FROM trusted_principals ORDER BY principal_id"
            ).fetchall()
            if policy_exists is not None or policy_rows:
                decision = denied_decision(
                    principal_id=principal_id,
                    required_capability=Capability.POLICY_MANAGE_CAPABILITIES,
                    reason=AuthorizationReason.POLICY_ALREADY_BOOTSTRAPPED,
                )
                accepted = False
            elif len(trusted) != 1 or str(trusted[0]["principal_id"]) != principal_id:
                decision = denied_decision(
                    principal_id=principal_id,
                    required_capability=Capability.POLICY_MANAGE_CAPABILITIES,
                    reason=AuthorizationReason.REQUEST_BINDING_REJECTED,
                )
                accepted = False
            else:
                decision = bootstrap_decision(principal_id)
        else:
            decision = CapabilityPolicyEvaluator.evaluate(
                connection,
                principal_id=principal_id,
                required_capability=Capability.POLICY_MANAGE_CAPABILITIES,
                actual_prior_state=None,
                requested_state=None,
            )
            accepted = decision.allowed

        if (
            accepted
            and operation
            in {
                CapabilityPolicyOperation.BOOTSTRAP,
                CapabilityPolicyOperation.GRANT,
            }
            and request.get("scope_version") != "1.0"
        ):
            decision = denied_decision(
                principal_id=principal_id,
                required_capability=Capability.POLICY_MANAGE_CAPABILITIES,
                reason=AuthorizationReason.SCOPE_REQUIRED,
            )
            accepted = False

        if accepted and operation is CapabilityPolicyOperation.GRANT:
            subject = connection.execute(
                "SELECT 1 FROM trusted_principals WHERE principal_id = ?",
                (request["subject_principal_id"],),
            ).fetchone()
            if subject is None:
                decision = denied_decision(
                    principal_id=principal_id,
                    required_capability=Capability.POLICY_MANAGE_CAPABILITIES,
                    reason=AuthorizationReason.UNKNOWN_SUBJECT_PRINCIPAL,
                )
                accepted = False
            elif (
                capability
                not in {
                    Capability.POLICY_MANAGE_CAPABILITIES,
                    Capability.EFFECT_MANAGE_BINDINGS,
                }
                and (
                    request.get("scope_version") != "1.0"
                    or None
                    in (
                        request.get("brand_id"),
                        request.get("channel_id"),
                        request.get("destination_id"),
                    )
                )
            ):
                decision = denied_decision(
                    principal_id=principal_id,
                    required_capability=Capability.POLICY_MANAGE_CAPABILITIES,
                    reason=AuthorizationReason.SCOPE_REQUIRED,
                )
                accepted = False

        target_grant: sqlite3.Row | None = None
        if accepted and operation is CapabilityPolicyOperation.REVOKE:
            target_grant = connection.execute(
                "SELECT * FROM capability_grants WHERE grant_id = ?",
                (request["grant_id"],),
            ).fetchone()
            if target_grant is None:
                decision = denied_decision(
                    principal_id=principal_id,
                    required_capability=Capability.POLICY_MANAGE_CAPABILITIES,
                    reason=AuthorizationReason.UNKNOWN_GRANT,
                )
                accepted = False
            else:
                expected_binding = (
                    str(target_grant["subject_principal_id"]),
                    str(target_grant["capability"]),
                    target_grant["expected_prior_state"],
                    target_grant["requested_state"],
                    target_grant["scope_version"],
                    target_grant["brand_id"],
                    target_grant["channel_id"],
                    target_grant["destination_id"],
                )
                requested_binding = (
                    str(request["subject_principal_id"]),
                    capability.value,
                    request.get("expected_prior_state"),
                    request.get("requested_state"),
                    request.get("scope_version"),
                    request.get("brand_id"),
                    request.get("channel_id"),
                    request.get("destination_id"),
                )
                if expected_binding != requested_binding:
                    decision = denied_decision(
                        principal_id=principal_id,
                        required_capability=Capability.POLICY_MANAGE_CAPABILITIES,
                        reason=AuthorizationReason.GRANT_BINDING_MISMATCH,
                    )
                    accepted = False
                elif connection.execute(
                    "SELECT 1 FROM capability_revocations WHERE grant_id = ?",
                    (request["grant_id"],),
                ).fetchone() is not None:
                    decision = denied_decision(
                        principal_id=principal_id,
                        required_capability=Capability.POLICY_MANAGE_CAPABILITIES,
                        reason=AuthorizationReason.GRANT_ALREADY_REVOKED,
                    )
                    accepted = False
                elif capability is Capability.POLICY_MANAGE_CAPABILITIES:
                    remaining_admin = connection.execute(
                        """
                        SELECT 1 FROM capability_grants AS g
                        LEFT JOIN capability_revocations AS r
                          ON r.grant_id = g.grant_id
                        WHERE g.capability = 'policy.manage_capabilities'
                          AND r.revocation_id IS NULL AND g.grant_id <> ?
                        LIMIT 1
                        """,
                        (request["grant_id"],),
                    ).fetchone()
                    if remaining_admin is None:
                        decision = denied_decision(
                            principal_id=principal_id,
                            required_capability=Capability.POLICY_MANAGE_CAPABILITIES,
                            reason=AuthorizationReason.LAST_POLICY_ADMIN,
                        )
                        accepted = False

        if not accepted:
            rejection_reason = f"Authorization denied: {decision.reason.value}"
        event = event_factory(decision, accepted, rejection_reason)
        _validate_authorization_event(
            event, decision, authenticated_operation, accepted=accepted
        )
        stored = insert_transition_event(connection, event)
        insert_authenticated_operation(
            connection,
            authenticated_operation,
            adjudication_event_id=str(event["event_id"]),
            adjudication_outcome="accepted" if accepted else "rejected",
        )
        if not accepted:
            return stored, decision, False

        created_at = str(event["occurred_at_utc"])
        application_version = str(event["application_version"])
        if operation in {
            CapabilityPolicyOperation.BOOTSTRAP,
            CapabilityPolicyOperation.GRANT,
        }:
            grant = {
                "grant_id": request["grant_id"],
                "subject_principal_id": request["subject_principal_id"],
                "capability": capability.value,
                "expected_prior_state": request.get("expected_prior_state"),
                "requested_state": request.get("requested_state"),
                "scope_version": request.get("scope_version"),
                "brand_id": request.get("brand_id"),
                "channel_id": request.get("channel_id"),
                "destination_id": request.get("destination_id"),
                "granted_by_principal_id": principal_id,
                "authenticated_operation_id": authenticated_operation["operation_id"],
                "policy_event_id": event["event_id"],
                "created_at_utc": created_at,
                "application_version": application_version,
            }
            _insert_capability_grant(connection, grant)
            if operation is CapabilityPolicyOperation.BOOTSTRAP:
                connection.execute(
                    """
                    INSERT INTO capability_policy_state (
                        singleton_id, bootstrap_principal_id, bootstrap_grant_id,
                        bootstrap_operation_id, bootstrap_event_id,
                        bootstrapped_at_utc, application_version
                    ) VALUES (1, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        principal_id,
                        request["grant_id"],
                        authenticated_operation["operation_id"],
                        event["event_id"],
                        created_at,
                        application_version,
                    ),
                )
        else:
            _insert_capability_revocation(
                connection,
                {
                    "revocation_id": request["revocation_id"],
                    "grant_id": request["grant_id"],
                    "revoked_by_principal_id": principal_id,
                    "authenticated_operation_id": authenticated_operation[
                        "operation_id"
                    ],
                    "policy_event_id": event["event_id"],
                    "revoked_at_utc": created_at,
                    "application_version": application_version,
                },
            )
        return stored, decision, True


def get_transition_event(database: Path, event_id: str) -> dict[str, object] | None:
    with connect(database) as connection:
        row = connection.execute(
            """
            SELECT e.*, c.chain_version, c.chain_origin, c.event_sequence,
                   c.previous_event_hash, c.event_hash
            FROM transition_events AS e
            LEFT JOIN transition_event_chain_entries AS c
              ON c.event_id = e.event_id
            WHERE e.event_id = ?
            """,
            (event_id,),
        ).fetchone()
    return dict(row) if row is not None else None


def pending_transition_events(database: Path) -> list[dict[str, object]]:
    with connect(database) as connection:
        rows = connection.execute(
            """
            SELECT e.*, c.chain_version, c.chain_origin, c.event_sequence,
                   c.previous_event_hash, c.event_hash
            FROM transition_events AS e
            LEFT JOIN transition_event_chain_entries AS c
              ON c.event_id = e.event_id
            WHERE e.receipt_projected_at_utc IS NULL
            ORDER BY CASE WHEN c.event_sequence IS NULL THEN 0 ELSE 1 END,
                     CASE WHEN c.event_sequence IS NULL THEN e.occurred_at_utc END,
                     CASE WHEN c.event_sequence IS NULL THEN e.event_id END,
                     c.event_sequence
            """
        ).fetchall()
    return [dict(row) for row in rows]


def mark_transition_event_projected(
    database: Path, event_id: str, projected_at_utc: str
) -> None:
    with connect(database) as connection:
        cursor = connection.execute(
            """
            UPDATE transition_events SET receipt_projected_at_utc = ?
            WHERE event_id = ? AND receipt_projected_at_utc IS NULL
            """,
            (projected_at_utc, event_id),
        )
        if cursor.rowcount == 0:
            exists = connection.execute(
                "SELECT 1 FROM transition_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if exists is None:
                raise KeyError(f"Unknown transition event: {event_id}")


def state_counts(database: Path, table: str) -> dict[str, int]:
    if table not in {"candidates", "packets"}:
        raise ValueError("Unsupported table")
    with connect(database) as connection:
        rows = connection.execute(
            f"SELECT state, COUNT(*) AS count FROM {table} GROUP BY state"  # noqa: S608
        ).fetchall()
    return {str(row["state"]): int(row["count"]) for row in rows}
