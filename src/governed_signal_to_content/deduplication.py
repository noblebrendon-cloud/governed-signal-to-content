"""Deterministic normalization and duplicate checks."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from . import database
from .config import WorkspacePaths
from .hashing import sha256_bytes
from .models import WorkflowState
from .receipts import execution_identity
from .state_machine import transition_candidate, validate_transition


TRACKING_QUERY_PREFIXES = ("utm_",)
TRACKING_QUERY_NAMES = {"fbclid", "gclid"}


def normalize_url(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("Source URL must be an absolute HTTP(S) URL")
    host = parts.hostname.lower()
    port = parts.port
    if port and not (
        (parts.scheme.lower() == "http" and port == 80)
        or (parts.scheme.lower() == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    if path != "/":
        path = path.rstrip("/")
    query_items = [
        (name, value)
        for name, value in parse_qsl(parts.query, keep_blank_values=True)
        if name.lower() not in TRACKING_QUERY_NAMES
        and not name.lower().startswith(TRACKING_QUERY_PREFIXES)
    ]
    query = urlencode(sorted(query_items))
    return urlunsplit((parts.scheme.lower(), host, path, query, ""))


def extract_development_identifiers(url: str) -> list[str]:
    parts = urlsplit(url)
    identifiers: set[str] = set()
    segments = [segment for segment in parts.path.split("/") if segment]
    if parts.hostname and parts.hostname.lower() == "github.com" and len(segments) >= 2:
        identifiers.add(f"github:{segments[0].lower()}/{segments[1].removesuffix('.git').lower()}")
    patterns = {
        "cve": r"\bCVE-\d{4}-\d{4,}\b",
        "rfc": r"\bRFC[-_/ ]?(\d{3,5})\b",
        "pep": r"\bPEP[-_/ ]?(\d{1,5})\b",
    }
    upper_url = url.upper()
    for prefix, pattern in patterns.items():
        for match in re.finditer(pattern, upper_url, flags=re.IGNORECASE):
            value = match.group(1) if match.lastindex else match.group(0).upper()
            identifiers.add(f"{prefix}:{value}")
    return sorted(identifiers)


def normalize_candidate(paths: WorkspacePaths, candidate_id: str) -> str:
    candidate = database.get_candidate(paths.database, candidate_id)
    if candidate is None:
        raise KeyError(f"Unknown candidate: {candidate_id}")
    prior = WorkflowState(str(candidate["state"]))
    validate_transition(prior, WorkflowState.NORMALIZED)
    normalized_url = normalize_url(str(candidate["source_url"]))
    identifiers = extract_development_identifiers(normalized_url)
    normalized = {
        "schema_version": "1.0",
        "candidate_id": candidate_id,
        "normalized_title": " ".join(str(candidate["title"]).split()),
        "normalized_url": normalized_url,
        "development_identifiers": identifiers,
        "normalization_identity": sha256_bytes(normalized_url.encode("utf-8")),
    }
    serialized = json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    output = paths.candidates / f"{candidate_id}.normalized.json"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(serialized)
    database.update_candidate_fields(
        paths.database,
        candidate_id,
        normalized_url=normalized_url,
        development_identifiers_json=json.dumps(identifiers),
        normalized_json=json.dumps(normalized, ensure_ascii=False, sort_keys=True),
    )
    receipt = transition_candidate(
        database_path=paths.database,
        receipt_log=paths.receipt_log,
        candidate_id=candidate_id,
        requested=WorkflowState.NORMALIZED,
        command="normalize",
        actor=execution_identity(),
        reason="Deterministic title, URL, and development identifier normalization completed.",
    )
    return receipt.run_id


def duplicate_reasons(
    candidate: dict[str, object], others: list[dict[str, object]]
) -> list[str]:
    reasons: list[str] = []
    current_ids = set(candidate.get("development_identifiers", []))
    for other in others:
        if candidate["source_identity"] == other["source_identity"]:
            reasons.append(f"source identity matches {other['candidate_id']}")
        if candidate.get("normalized_url") and candidate.get("normalized_url") == other.get(
            "normalized_url"
        ):
            reasons.append(f"normalized URL matches {other['candidate_id']}")
        shared = current_ids.intersection(other.get("development_identifiers", []))
        if shared:
            reasons.append(
                f"development identifiers {sorted(shared)} match {other['candidate_id']}"
            )
    return sorted(set(reasons))


def deduplicate_candidate(paths: WorkspacePaths, candidate_id: str) -> tuple[str, bool, str]:
    candidate = database.get_candidate(paths.database, candidate_id)
    if candidate is None:
        raise KeyError(f"Unknown candidate: {candidate_id}")
    reasons = duplicate_reasons(
        candidate, database.other_candidates(paths.database, candidate_id)
    )
    duplicate = bool(reasons)
    target = WorkflowState.SUPPRESSED if duplicate else WorkflowState.DUPLICATE_CHECKED
    reason = "; ".join(reasons) if reasons else "No matching source identity, URL, or development identifier."
    receipt = transition_candidate(
        database_path=paths.database,
        receipt_log=paths.receipt_log,
        candidate_id=candidate_id,
        requested=target,
        command="deduplicate",
        actor=execution_identity(),
        reason=reason,
    )
    return receipt.run_id, duplicate, reason
