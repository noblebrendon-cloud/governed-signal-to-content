"""Pure canonical hashing and Ed25519 proof helpers for external effects."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ValidationError

from .hashing import canonical_json, canonical_json_hash, sha256_bytes
from .models import ExecutorResultEnvelope, SignedExecutorResult


EFFECT_REQUEST_DOMAIN = "GS2C_EXTERNAL_EFFECT_REQUEST_V1"
EFFECT_IDEMPOTENCY_DOMAIN = "GS2C_EXTERNAL_EFFECT_IDEMPOTENCY_V1"
EXECUTOR_RESULT_DOMAIN = "GS2C_EXECUTOR_RESULT_V1"

EFFECT_REQUEST_HASH_FIELDS = (
    "schema_version",
    "effect_id",
    "release_event_id",
    "packet_id",
    "candidate_id",
    "approval_id",
    "approval_event_id",
    "authenticated_principal_id",
    "authorizing_grant_id",
    "capability",
    "scope_version",
    "brand_id",
    "channel_id",
    "destination_id",
    "destination_binding_id",
    "adapter_id",
    "external_target_ref",
    "credential_ref",
    "packet_manifest_hash",
    "packet_receipt_hash",
    "release_event_hash",
    "release_event_sequence",
    "idempotency_key",
    "created_at_utc",
    "application_version",
    "request_event_id",
)


def calculate_effect_request_hash(request: Mapping[str, object]) -> str:
    values = {field: request.get(field) for field in EFFECT_REQUEST_HASH_FIELDS}
    # SQLite stores the fixed schema version structurally rather than as a
    # repeated column; model/dict callers may still supply it explicitly.
    values["schema_version"] = request.get("schema_version", "1.0")
    material = {
        "domain": EFFECT_REQUEST_DOMAIN,
        "request": values,
    }
    return canonical_json_hash(material)


def calculate_idempotency_key(effect_id: str, release_event_hash: str) -> str:
    digest = canonical_json_hash(
        {
            "domain": EFFECT_IDEMPOTENCY_DOMAIN,
            "effect_id": effect_id,
            "release_event_hash": release_event_hash,
        }
    )
    return f"idem_{digest}"


def canonical_executor_result_json(envelope: ExecutorResultEnvelope) -> str:
    return canonical_json(
        {
            "domain": EXECUTOR_RESULT_DOMAIN,
            "envelope": envelope.model_dump(mode="json"),
        }
    )


def _executor_key_identity(public_key: Ed25519PublicKey) -> tuple[str, str, str]:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = sha256_bytes(raw)
    return (
        f"ed25519:{fingerprint}",
        fingerprint,
        base64.b64encode(raw).decode("ascii"),
    )


def sign_executor_result(
    envelope: ExecutorResultEnvelope, private_key_path: Path
) -> SignedExecutorResult:
    try:
        loaded = serialization.load_pem_private_key(
            private_key_path.expanduser().resolve(strict=True).read_bytes(),
            password=None,
        )
    except (OSError, ValueError, TypeError) as error:
        raise ValueError("Invalid executor identity private key") from error
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("Executor identity key must be Ed25519")
    key_id, _, _ = _executor_key_identity(loaded.public_key())
    if key_id != envelope.executor_key_id:
        raise ValueError("Executor private key does not match canonical executor identity")
    signature = loaded.sign(canonical_executor_result_json(envelope).encode("utf-8"))
    return SignedExecutorResult(
        envelope=envelope,
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def verify_executor_result_signature(
    signed: SignedExecutorResult, trusted_executor: Mapping[str, object]
) -> tuple[str, str]:
    envelope = signed.envelope
    if (
        envelope.executor_id != trusted_executor.get("executor_id")
        or envelope.executor_key_id != trusted_executor.get("key_id")
        or trusted_executor.get("authentication_scheme") != "ed25519"
    ):
        raise ValueError("Executor result identity does not match a trusted executor")
    try:
        raw_public = base64.b64decode(
            str(trusted_executor["public_key_b64"]), validate=True
        )
        signature = base64.b64decode(signed.signature_b64, validate=True)
        public_key = Ed25519PublicKey.from_public_bytes(raw_public)
        key_id, fingerprint, public_key_b64 = _executor_key_identity(public_key)
        if (
            key_id != trusted_executor.get("key_id")
            or fingerprint != trusted_executor.get("verifier_fingerprint")
            or public_key_b64 != trusted_executor.get("public_key_b64")
        ):
            raise ValueError("Stored executor verifier identity is inconsistent")
        public_key.verify(
            signature, canonical_executor_result_json(envelope).encode("utf-8")
        )
    except (ValueError, binascii.Error, InvalidSignature) as error:
        raise ValueError("Executor result signature verification failed") from error
    envelope_hash = sha256_bytes(
        canonical_executor_result_json(envelope).encode("utf-8")
    )
    proof_hash = canonical_json_hash(signed.model_dump(mode="json"))
    return envelope_hash, proof_hash


def load_signed_executor_result(path: Path) -> SignedExecutorResult:
    try:
        value = json.loads(
            path.expanduser().resolve(strict=True).read_text(encoding="utf-8")
        )
        return SignedExecutorResult.model_validate(value)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as error:
        raise ValueError("Invalid signed executor result") from error
