from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from governed_signal_to_content.receipts import new_receipt


ROOT = Path(__file__).resolve().parents[1]


def validate(schema_name: str, instance: object) -> None:
    schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(instance)


def test_json_schema_examples_validate() -> None:
    validate(
        "candidate.schema.json",
        json.loads((ROOT / "examples" / "candidate.example.json").read_text(encoding="utf-8")),
    )
    validate(
        "classification.schema.json",
        json.loads(
            (ROOT / "examples" / "classification.example.json").read_text(encoding="utf-8")
        ),
    )
    validate(
        "content_packet.schema.json",
        json.loads(
            (ROOT / "content" / "google_agent_registry_example" / "packet_receipt.json").read_text(
                encoding="utf-8"
            )
        ),
    )


def test_evidence_and_run_receipt_schemas_validate() -> None:
    validate(
        "evidence_record.schema.json",
        {
            "schema_version": "1.0",
            "evidence_id": "ev_0123456789abcdef0123456789abcdef",
            "candidate_id": "cand_0123456789abcdef0123456789abcdef",
            "source_url": "https://example.com/source",
            "original_filename": None,
            "preserved_path": None,
            "sha256": "a" * 64,
            "byte_size": None,
            "ingested_at_utc": "2026-08-02T12:00:00Z",
            "content_preserved": False,
        },
    )
    receipt = new_receipt(
        command="test",
        actor="tester",
        input_identifiers={"candidate_id": "cand_example"},
        prior_state="DISCOVERED",
        requested_transition="EVIDENCE_PRESERVED",
        resulting_state="EVIDENCE_PRESERVED",
        outcome="accepted",
        reason="schema test",
    )
    validate("run_receipt.schema.json", receipt.model_dump(mode="json"))
