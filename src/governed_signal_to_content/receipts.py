"""Append-only JSONL execution receipts."""

from __future__ import annotations

import getpass
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from . import __version__
from .hashing import canonical_json
from .models import RunReceipt


SENSITIVE_KEY_FRAGMENTS = (
    "authorization",
    "credential",
    "password",
    "secret",
    "token",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def execution_identity() -> str:
    return f"local:{getpass.getuser()}"


def sanitize_for_receipt(value: Any) -> Any:
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS):
                clean[str(key)] = "[REDACTED]"
            else:
                clean[str(key)] = sanitize_for_receipt(item)
        return clean
    if isinstance(value, list):
        return [sanitize_for_receipt(item) for item in value]
    return value


def new_receipt(
    *,
    command: str,
    actor: str,
    input_identifiers: dict[str, Any],
    prior_state: str | None,
    requested_transition: str | None,
    resulting_state: str | None,
    outcome: str,
    reason: str,
    file_hashes: dict[str, str] | None = None,
) -> RunReceipt:
    return RunReceipt(
        run_id=str(uuid4()),
        command=command,
        timestamp_utc=utc_now(),
        actor=actor,
        input_identifiers=sanitize_for_receipt(input_identifiers),
        prior_state=prior_state,
        requested_transition=requested_transition,
        resulting_state=resulting_state,
        outcome=outcome,
        reason=reason,
        file_hashes=file_hashes or {},
        application_version=__version__,
    )


def append_receipt(receipt_log: Path, receipt: RunReceipt) -> None:
    if find_receipt(receipt_log, receipt.run_id) is not None:
        raise ValueError(f"Receipt already exists and is immutable: {receipt.run_id}")
    line = canonical_json(receipt.model_dump(mode="json")) + "\n"
    with receipt_log.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(line)
        stream.flush()


def find_receipt(receipt_log: Path, run_id: str) -> dict[str, Any] | None:
    if not receipt_log.exists():
        return None
    with receipt_log.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("run_id") == run_id:
                return record
    return None
