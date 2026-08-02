"""Create candidates and preserve evidence without replacing prior material."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from uuid import uuid4

from . import database
from .config import WorkspacePaths
from .deduplication import extract_development_identifiers, normalize_url
from .hashing import sha256_bytes, sha256_file
from .models import CandidateRecord, EvidenceRecord, WorkflowState
from .receipts import execution_identity, utc_now
from .state_machine import transition_candidate


def _write_json_exclusive(path: Path, value: object) -> None:
    serialized = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(serialized)


def ingest_signal(
    *,
    paths: WorkspacePaths,
    title: str,
    source_url: str,
    source_file: Path | None,
) -> tuple[CandidateRecord, EvidenceRecord, str]:
    candidate_id = f"cand_{uuid4().hex}"
    evidence_id = f"ev_{uuid4().hex}"
    timestamp = utc_now()
    normalized_source_url = normalize_url(source_url)
    preserved_path: str | None = None
    original_filename: str | None = None
    byte_size: int | None = None
    content_preserved = False

    if source_file is not None:
        source_file = source_file.expanduser().resolve(strict=True)
        if not source_file.is_file():
            raise ValueError(f"Evidence source is not a file: {source_file}")
        original_filename = source_file.name
        evidence_directory = paths.evidence / candidate_id
        evidence_directory.mkdir(parents=False, exist_ok=False)
        destination = evidence_directory / original_filename
        with source_file.open("rb") as source, destination.open("xb") as target:
            shutil.copyfileobj(source, target)
        source_hash = sha256_file(source_file)
        if sha256_file(destination) != source_hash:
            raise OSError("Preserved evidence hash does not match the source file")
        byte_size = destination.stat().st_size
        preserved_path = str(destination.relative_to(paths.root)).replace("\\", "/")
        content_preserved = True
    else:
        source_hash = sha256_bytes(normalized_source_url.encode("utf-8"))

    candidate = CandidateRecord(
        candidate_id=candidate_id,
        title=title,
        source_url=source_url,
        normalized_url=None,
        source_identity=source_hash,
        development_identifiers=extract_development_identifiers(normalized_source_url),
        state=WorkflowState.DISCOVERED,
        created_at_utc=timestamp,
    )
    evidence = EvidenceRecord(
        evidence_id=evidence_id,
        candidate_id=candidate_id,
        source_url=source_url,
        original_filename=original_filename,
        preserved_path=preserved_path,
        sha256=source_hash,
        byte_size=byte_size,
        ingested_at_utc=timestamp,
        content_preserved=content_preserved,
    )
    candidate_data = candidate.model_dump(mode="json")
    evidence_data = evidence.model_dump(mode="json")
    database.insert_candidate(paths.database, candidate_data)
    database.insert_evidence(paths.database, evidence_data)
    _write_json_exclusive(paths.candidates / f"{candidate_id}.json", candidate_data)
    _write_json_exclusive(paths.evidence / f"{evidence_id}.json", evidence_data)
    receipt = transition_candidate(
        database_path=paths.database,
        receipt_log=paths.receipt_log,
        candidate_id=candidate_id,
        requested=WorkflowState.EVIDENCE_PRESERVED,
        command="ingest",
        actor=execution_identity(),
        reason=(
            "Evidence bytes copied and verified by SHA-256."
            if content_preserved
            else "Remote evidence reference recorded; remote content was not archived."
        ),
        file_hashes={"evidence_sha256": source_hash},
    )
    return candidate, evidence, receipt.run_id
