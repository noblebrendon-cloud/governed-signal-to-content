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
from .models import ContentInputs, WorkflowState
from .receipts import execution_identity, utc_now
from .state_machine import transition_candidate, transition_packet, validate_transition


ARTIFACT_FILENAMES = (
    "01_linkedin_analysis.md",
    "02_csg_facebook_post.md",
    "03_transient_vs_governed.mmd",
    "04_governed_operating_layers_essay.md",
    "05_repository_note.md",
)
PACKET_FILENAMES = (*ARTIFACT_FILENAMES, "sources.json", "packet_receipt.json")
TARGET_RANGES = {
    "01_linkedin_analysis.md": (250, 500),
    "02_csg_facebook_post.md": (100, 200),
    "04_governed_operating_layers_essay.md": (800, 1200),
}


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
        }
        _write_text(
            temp_directory / "sources.json",
            json.dumps(sources_value, ensure_ascii=False, indent=2, sort_keys=True),
        )
        artifact_hashes = {
            filename: sha256_file(temp_directory / filename)
            for filename in (*ARTIFACT_FILENAMES, "sources.json")
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

    database.insert_packet(
        paths.database,
        {
            "packet_id": packet_id,
            "candidate_id": candidate_id,
            "packet_path": str(final_directory),
            "manifest_hash": manifest_hash,
            "state": WorkflowState.PACKET_GENERATED.value,
            "created_at_utc": packet_receipt["created_at_utc"],
        },
    )
    transition_candidate(
        database_path=paths.database,
        receipt_log=paths.receipt_log,
        candidate_id=candidate_id,
        requested=WorkflowState.PACKET_GENERATED,
        command="generate",
        actor=execution_identity(),
        reason="Validated content inputs were atomically materialized as a fixed packet.",
        file_hashes=artifact_hashes,
    )
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
    )
    return packet_id, receipt.run_id, warnings, manifest_hash
