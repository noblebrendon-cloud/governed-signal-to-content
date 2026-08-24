"""Atomic generation of a fixed seven-file governed content packet."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from . import database
from .config import WorkspacePaths
from .hashing import canonical_json_hash, sha256_file
from .models import ContentInputs, PacketScope, WorkflowState
from .receipts import execution_identity, utc_now
from .state_machine import transition_candidate, transition_packet, validate_transition


ARTIFACT_FILENAMES = (
    "01_linkedin_analysis.md",
    "02_csg_facebook_post.md",
    "03_transient_vs_governed.mmd",
    "04_governed_operating_layers_essay.md",
    "05_repository_note.md",
)
MANIFEST_FILENAMES = (*ARTIFACT_FILENAMES, "sources.json")
PACKET_FILENAMES = (*MANIFEST_FILENAMES, "packet_receipt.json")
TARGET_RANGES = {
    "01_linkedin_analysis.md": (250, 500),
    "02_csg_facebook_post.md": (100, 200),
    "04_governed_operating_layers_essay.md": (800, 1200),
}


class PacketIntegrityError(ValueError):
    """The materialized packet no longer matches its canonical manifest."""

    def __init__(
        self,
        message: str,
        *,
        artifact_hashes: dict[str, str] | None = None,
        manifest_hash: str | None = None,
    ) -> None:
        self.artifact_hashes = artifact_hashes or {}
        self.manifest_hash = manifest_hash
        super().__init__(message)


def recompute_packet_manifest(packet: dict[str, object]) -> tuple[dict[str, str], str]:
    """Recompute and validate the fixed v0.1.0 packet manifest from disk."""
    packet_directory = Path(str(packet["packet_path"]))
    if not packet_directory.is_dir():
        raise PacketIntegrityError(f"Packet directory is missing: {packet_directory}")
    actual_names = {path.name for path in packet_directory.iterdir()}
    expected_names = set(PACKET_FILENAMES)
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        unexpected = sorted(actual_names - expected_names)
        raise PacketIntegrityError(
            f"Packet file set mismatch; missing={missing}, unexpected={unexpected}"
        )
    try:
        artifact_hashes = {
            filename: sha256_file(packet_directory / filename)
            for filename in MANIFEST_FILENAMES
        }
    except OSError as error:
        raise PacketIntegrityError(f"Packet artifact could not be hashed: {error}") from error
    manifest_hash = canonical_json_hash(artifact_hashes)
    scope_values = (
        packet.get("brand_id"),
        packet.get("channel_id"),
        packet.get("destination_id"),
    )
    if packet.get("scope_version") is None and all(
        value is None for value in scope_values
    ):
        canonical_scope: PacketScope | None = None
    elif packet.get("scope_version") == "1.0" and all(
        value is not None for value in scope_values
    ):
        canonical_scope = PacketScope(
            brand_id=packet["brand_id"],
            channel_id=packet["channel_id"],
            destination_id=packet["destination_id"],
        )
    else:
        raise PacketIntegrityError("Canonical packet scope is incomplete or malformed")
    try:
        sources = json.loads(
            (packet_directory / "sources.json").read_text(encoding="utf-8")
        )
        packet_receipt = json.loads(
            (packet_directory / "packet_receipt.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PacketIntegrityError(f"Packet governed metadata is unreadable: {error}") from error
    expected_scope = (
        None if canonical_scope is None else canonical_scope.model_dump(mode="json")
    )
    if sources.get("scope") != expected_scope:
        raise PacketIntegrityError(
            "Packet sources scope does not match canonical packet scope",
            artifact_hashes=artifact_hashes,
            manifest_hash=manifest_hash,
        )
    receipt_checks = {
        "packet_id": str(packet["packet_id"]),
        "candidate_id": str(packet["candidate_id"]),
        "required_artifacts": list(ARTIFACT_FILENAMES),
        "artifact_hashes": artifact_hashes,
        "packet_manifest_hash": manifest_hash,
        "scope": expected_scope,
    }
    for field, expected in receipt_checks.items():
        if packet_receipt.get(field) != expected:
            raise PacketIntegrityError(
                f"Packet receipt {field} does not match materialized packet",
                artifact_hashes=artifact_hashes,
                manifest_hash=manifest_hash,
            )
    materialized_hashes = {
        **artifact_hashes,
        "packet_receipt.json": sha256_file(packet_directory / "packet_receipt.json"),
    }
    return materialized_hashes, manifest_hash


def word_count(text: str) -> int:
    return len(re.findall(r"\b[\w'-]+\b", text, flags=re.UNICODE))


def load_content_inputs(path: Path) -> ContentInputs:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
        return ContentInputs.model_validate(value)
    except (json.JSONDecodeError, ValidationError) as error:
        raise ValueError(f"Invalid content inputs JSON: {error}") from error


def _write_text(path: Path, text: str) -> None:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").rstrip() + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(normalized)


def generate_packet(
    paths: WorkspacePaths, candidate_id: str, content_inputs_path: Path
) -> tuple[str, str, list[str], str]:
    candidate = database.get_candidate(paths.database, candidate_id)
    if candidate is None:
        raise KeyError(f"Unknown candidate: {candidate_id}")
    prior = WorkflowState(str(candidate["state"]))
    validate_transition(prior, WorkflowState.PACKET_GENERATED)
    inputs = load_content_inputs(content_inputs_path)
    scope = inputs.scope
    packet_id = f"pkt_{uuid4().hex}"
    temp_directory = paths.packets / f".{packet_id}.tmp"
    final_directory = paths.packets / packet_id
    if final_directory.exists() or temp_directory.exists():
        raise FileExistsError(f"Packet path already exists for {packet_id}")
    temp_directory.mkdir(parents=False, exist_ok=False)
    text_by_filename = {
        "01_linkedin_analysis.md": inputs.linkedin_analysis,
        "02_csg_facebook_post.md": inputs.csg_facebook_post,
        "03_transient_vs_governed.mmd": inputs.mermaid_diagram,
        "04_governed_operating_layers_essay.md": inputs.governed_operating_layers_essay,
        "05_repository_note.md": inputs.repository_note,
    }
    warnings: list[str] = []
    try:
        for filename, text in text_by_filename.items():
            _write_text(temp_directory / filename, text)
            if filename in TARGET_RANGES:
                minimum, maximum = TARGET_RANGES[filename]
                count = word_count(text)
                if count < minimum or count > maximum:
                    warnings.append(
                        f"{filename}: {count} words; target range is {minimum}-{maximum}."
                    )
        sources_value = {
            "schema_version": "1.0",
            "candidate_id": candidate_id,
            "sources": [str(source) for source in inputs.sources],
            "scope": scope.model_dump(mode="json"),
        }
        _write_text(
            temp_directory / "sources.json",
            json.dumps(sources_value, ensure_ascii=False, indent=2, sort_keys=True),
        )
        artifact_hashes = {
            filename: sha256_file(temp_directory / filename)
            for filename in MANIFEST_FILENAMES
        }
        manifest_hash = canonical_json_hash(artifact_hashes)
        packet_receipt = {
            "schema_version": "1.0",
            "packet_id": packet_id,
            "candidate_id": candidate_id,
            "created_at_utc": utc_now(),
            "required_artifacts": list(ARTIFACT_FILENAMES),
            "artifact_hashes": artifact_hashes,
            "packet_manifest_hash": manifest_hash,
            "scope": scope.model_dump(mode="json"),
            "warnings": warnings,
            "approval_status": "AWAITING_APPROVAL",
        }
        _write_text(
            temp_directory / "packet_receipt.json",
            json.dumps(packet_receipt, ensure_ascii=False, indent=2, sort_keys=True),
        )
        if set(path.name for path in temp_directory.iterdir()) != set(PACKET_FILENAMES):
            raise RuntimeError("Packet contents do not match the required fixed file set")
        os.replace(temp_directory, final_directory)
    except Exception:
        if temp_directory.exists():
            shutil.rmtree(temp_directory)
        raise

    try:
        transition_candidate(
            database_path=paths.database,
            receipt_log=paths.receipt_log,
            candidate_id=candidate_id,
            requested=WorkflowState.PACKET_GENERATED,
            command="generate",
            actor=execution_identity(),
            reason="Validated content inputs were atomically materialized as a fixed packet.",
            file_hashes=artifact_hashes,
            governed_hash=manifest_hash,
            packet={
                "packet_id": packet_id,
                "candidate_id": candidate_id,
                "packet_path": str(final_directory),
                "manifest_hash": manifest_hash,
                "scope_version": scope.scope_version,
                "brand_id": scope.brand_id,
                "channel_id": scope.channel_id,
                "destination_id": scope.destination_id,
                "state": WorkflowState.PACKET_GENERATED.value,
                "created_at_utc": packet_receipt["created_at_utc"],
            },
        )
    except Exception:
        if database.get_packet(paths.database, packet_id) is None:
            shutil.rmtree(final_directory)
        raise
    receipt = transition_packet(
        database_path=paths.database,
        receipt_log=paths.receipt_log,
        packet_id=packet_id,
        requested=WorkflowState.AWAITING_APPROVAL,
        command="generate",
        actor=execution_identity(),
        reason="Generated packet is complete and waiting for explicit human approval.",
        file_hashes={
            **artifact_hashes,
            "packet_receipt.json": sha256_file(final_directory / "packet_receipt.json"),
        },
        governed_hash=manifest_hash,
    )
    return packet_id, receipt.run_id, warnings, manifest_hash
