from __future__ import annotations

import json
from pathlib import Path

import pytest

from governed_signal_to_content.receipts import append_receipt, new_receipt


def make_receipt(**identifiers: str):
    return new_receipt(
        command="test",
        actor="tester",
        input_identifiers=identifiers,
        prior_state="DISCOVERED",
        requested_transition="EVIDENCE_PRESERVED",
        resulting_state="EVIDENCE_PRESERVED",
        outcome="accepted",
        reason="test receipt",
    )


def test_receipts_append_without_mutating_prior_lines(tmp_path: Path) -> None:
    log = tmp_path / "receipts.jsonl"
    first = make_receipt(candidate_id="one")
    second = make_receipt(candidate_id="two")
    append_receipt(log, first)
    first_bytes = log.read_bytes()
    append_receipt(log, second)
    assert log.read_bytes().startswith(first_bytes)
    assert len(log.read_text(encoding="utf-8").splitlines()) == 2
    with pytest.raises(ValueError, match="immutable"):
        append_receipt(log, first)


def test_no_credentials_written_to_receipts(tmp_path: Path) -> None:
    log = tmp_path / "receipts.jsonl"
    receipt = make_receipt(
        candidate_id="one",
        github_token="sensitive-value",
        password="another-sensitive-value",
    )
    append_receipt(log, receipt)
    text = log.read_text(encoding="utf-8")
    assert "sensitive-value" not in text
    assert "another-sensitive-value" not in text
    parsed = json.loads(text)
    assert parsed["input_identifiers"]["github_token"] == "[REDACTED]"
    assert parsed["input_identifiers"]["password"] == "[REDACTED]"
