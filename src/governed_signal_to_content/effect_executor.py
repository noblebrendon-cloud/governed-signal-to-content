"""Separable privileged executor for the fixed offline ``test.capture`` adapter."""

from __future__ import annotations

import json
import os
import re
from base64 import b64encode
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

import typer

from . import database
from .config import require_workspace
from .effect_protocol import sign_executor_result
from .external_effects import ExternalEffectIntegrityError
from .hashing import canonical_json, sha256_bytes
from .integrity import verify_integrity
from .models import (
    ExecutorResultEnvelope,
    ExternalEffectOutcome,
    SignedExecutorResult,
)
from .packets import PACKET_FILENAMES, recompute_packet_manifest
from .receipts import utc_now


class CredentialResolver(Protocol):
    """Executor-local credential lookup; only opaque references cross GS2C."""

    def resolve(self, credential_ref: str) -> str:
        ...


class CredentialUnavailable(LookupError):
    pass


class EnvironmentCredentialResolver:
    """Resolve ``cred_name`` from ``GS2C_CREDENTIAL_NAME`` inside the executor."""

    @staticmethod
    def variable_name(credential_ref: str) -> str:
        suffix = re.sub(r"[^A-Za-z0-9]", "_", credential_ref).upper()
        return f"GS2C_CREDENTIAL_{suffix}"

    def resolve(self, credential_ref: str) -> str:
        value = os.environ.get(self.variable_name(credential_ref))
        if value is None or not value:
            raise CredentialUnavailable("Executor credential reference is unresolved")
        return value


@dataclass(frozen=True, slots=True)
class AdapterResponse:
    remote_reference: str
    response_hash: str


class CaptureAdapter:
    """Offline deterministic capture adapter with idempotent file materialization."""

    adapter_id = "test.capture"

    def __init__(self, capture_directory: Path) -> None:
        self._capture_directory = capture_directory.expanduser().resolve()

    def invoke(
        self,
        *,
        effect: dict[str, object],
        packet: dict[str, object],
        credential: str,
    ) -> AdapterResponse:
        if not credential:
            raise CredentialUnavailable("Executor credential reference is unresolved")
        packet_directory = Path(str(packet["packet_path"]))
        artifacts = {
            name: b64encode((packet_directory / name).read_bytes()).decode("ascii")
            for name in PACKET_FILENAMES
        }
        capture = {
            "schema_version": "1.0",
            "adapter_id": self.adapter_id,
            "effect_id": effect["effect_id"],
            "effect_request_hash": effect["request_hash"],
            "idempotency_key": effect["idempotency_key"],
            "destination_binding_id": effect["destination_binding_id"],
            "external_target_ref": effect["external_target_ref"],
            "scope": {
                "scope_version": effect["scope_version"],
                "brand_id": effect["brand_id"],
                "channel_id": effect["channel_id"],
                "destination_id": effect["destination_id"],
            },
            "packet_id": effect["packet_id"],
            "candidate_id": effect["candidate_id"],
            "packet_manifest_hash": effect["packet_manifest_hash"],
            "artifacts_b64": artifacts,
        }
        content = canonical_json(capture) + "\n"
        response_hash = sha256_bytes(content.encode("utf-8"))
        self._capture_directory.mkdir(parents=True, exist_ok=True)
        output = self._capture_directory / f"{effect['idempotency_key']}.json"
        if output.exists():
            existing = output.read_text(encoding="utf-8")
            if existing != content:
                raise RuntimeError("Idempotency capture collision has different content")
        else:
            with output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
                stream.flush()
        return AdapterResponse(
            remote_reference=f"capture:{effect['idempotency_key']}",
            response_hash=response_hash,
        )


def _trusted_execution_context(
    database_path: Path,
    *,
    effect_id: str,
    dispatch_id: str,
    executor_id: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    with database.connect(database_path) as connection:
        effect = connection.execute(
            "SELECT * FROM external_effect_requests WHERE effect_id = ?", (effect_id,)
        ).fetchone()
        dispatch = connection.execute(
            """
            SELECT * FROM external_effect_dispatches
            WHERE dispatch_id = ? AND effect_id = ?
            """,
            (dispatch_id, effect_id),
        ).fetchone()
        executor = connection.execute(
            "SELECT * FROM trusted_effect_executors WHERE executor_id = ?",
            (executor_id,),
        ).fetchone()
        packet = None
        if effect is not None:
            packet = connection.execute(
                "SELECT * FROM packets WHERE packet_id = ?", (effect["packet_id"],)
            ).fetchone()
        if effect is None or dispatch is None or executor is None or packet is None:
            raise ExternalEffectIntegrityError(
                "Effect, claim, executor, or packet canonical evidence is missing"
            )
        if connection.execute(
            "SELECT 1 FROM external_effect_results WHERE dispatch_id = ?",
            (dispatch_id,),
        ).fetchone() is not None:
            raise ExternalEffectIntegrityError("Execution claim already has a result")
    return dict(effect), dict(dispatch), dict(executor), dict(packet)


def execute_claimed_effect(
    *,
    workspace: Path,
    effect_id: str,
    dispatch_id: str,
    executor_id: str,
    executor_private_key_path: Path,
    capture_directory: Path,
    credential_resolver: CredentialResolver | None = None,
) -> SignedExecutorResult:
    """Verify canonical authority, invoke the offline adapter, and sign the result."""
    paths = require_workspace(workspace)
    verification = verify_integrity(paths.database, paths.receipt_log)
    if not (
        verification.canonical_chain_valid
        and verification.canonical_policy_valid
        and verification.canonical_external_effect_valid
    ):
        raise ExternalEffectIntegrityError(
            "Canonical chain, policy, or external-effect integrity verification failed"
        )
    effect, dispatch, executor, packet = _trusted_execution_context(
        paths.database,
        effect_id=effect_id,
        dispatch_id=dispatch_id,
        executor_id=executor_id,
    )
    allowed = json.loads(str(executor["allowed_adapter_ids_json"]))
    if effect["adapter_id"] != "test.capture" or effect["adapter_id"] not in allowed:
        raise ExternalEffectIntegrityError("No fixed trusted adapter matches the effect")
    if (
        packet["state"] != "RELEASED"
        or dispatch["effect_request_hash"] != effect["request_hash"]
    ):
        raise ExternalEffectIntegrityError("Effect execution authority is inconsistent")
    first_hashes, first_manifest = recompute_packet_manifest(packet)
    if (
        first_manifest != effect["packet_manifest_hash"]
        or first_hashes["packet_receipt.json"] != effect["packet_receipt_hash"]
    ):
        raise ExternalEffectIntegrityError("Governed packet artifacts changed before execution")

    started = utc_now()
    outcome = ExternalEffectOutcome.FAILED
    effect_may_have_occurred = False
    retry_permitted = True
    remote_reference: str | None = None
    response_hash: str | None = None
    error_code: str | None = None
    try:
        second_hashes, second_manifest = recompute_packet_manifest(packet)
        if second_hashes != first_hashes or second_manifest != first_manifest:
            raise ExternalEffectIntegrityError(
                "Governed packet artifacts changed at the execution boundary"
            )
        resolver = credential_resolver or EnvironmentCredentialResolver()
        credential = resolver.resolve(str(effect["credential_ref"]))
        response = CaptureAdapter(capture_directory).invoke(
            effect=effect, packet=packet, credential=credential
        )
        outcome = ExternalEffectOutcome.SUCCEEDED
        effect_may_have_occurred = True
        retry_permitted = False
        remote_reference = response.remote_reference
        response_hash = response.response_hash
    except CredentialUnavailable:
        error_code = "CREDENTIAL_UNAVAILABLE"
    except ExternalEffectIntegrityError:
        raise
    except Exception:
        # Once an adapter is entered, an exception cannot prove that no effect happened.
        outcome = ExternalEffectOutcome.UNKNOWN
        effect_may_have_occurred = True
        retry_permitted = False
        error_code = "ADAPTER_OUTCOME_UNKNOWN"

    envelope = ExecutorResultEnvelope(
        result_id=f"result_{uuid4().hex}",
        executor_id=executor_id,
        executor_key_id=str(executor["key_id"]),
        effect_id=effect_id,
        dispatch_id=dispatch_id,
        effect_request_hash=str(effect["request_hash"]),
        adapter_id=str(effect["adapter_id"]),  # type: ignore[arg-type]
        scope_version=str(effect["scope_version"]),  # type: ignore[arg-type]
        brand_id=str(effect["brand_id"]),
        channel_id=str(effect["channel_id"]),
        destination_id=str(effect["destination_id"]),
        destination_binding_id=str(effect["destination_binding_id"]),
        artifact_hash=str(effect["packet_manifest_hash"]),
        idempotency_key=str(effect["idempotency_key"]),
        outcome=outcome,
        effect_may_have_occurred=effect_may_have_occurred,
        retry_permitted=retry_permitted,
        remote_reference=remote_reference,
        response_hash=response_hash,
        error_code=error_code,
        started_at_utc=started,
        completed_at_utc=utc_now(),
    )
    return sign_executor_result(envelope, executor_private_key_path)


def _write_signed_result(path: Path, result: SignedExecutorResult) -> None:
    output = path.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(
            json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
        )


app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Execute already-claimed effects in a separate privileged process.",
)


@app.callback()
def executor_application() -> None:
    """Keep executor configuration separate from governed GS2C mutation commands."""


@app.command("execute")
def execute_command(
    workspace: Path = typer.Option(..., "--workspace"),
    effect_id: str = typer.Option(..., "--effect-id"),
    dispatch_id: str = typer.Option(..., "--dispatch-id"),
    result_output: Path = typer.Option(..., "--result-output"),
) -> None:
    """Execute one claimed effect using executor-local environment configuration."""
    executor_id = os.environ.get("GS2C_EFFECT_EXECUTOR_ID")
    key_path = os.environ.get("GS2C_EFFECT_EXECUTOR_PRIVATE_KEY_PATH")
    capture_path = os.environ.get("GS2C_TEST_CAPTURE_DIRECTORY")
    if not executor_id or not key_path or not capture_path:
        typer.echo("Error: executor environment configuration is incomplete", err=True)
        raise typer.Exit(code=1)
    try:
        result = execute_claimed_effect(
            workspace=workspace,
            effect_id=effect_id,
            dispatch_id=dispatch_id,
            executor_id=executor_id,
            executor_private_key_path=Path(key_path),
            capture_directory=Path(capture_path),
        )
        _write_signed_result(result_output, result)
        typer.echo(f"Wrote signed executor result: {result_output.expanduser().resolve()}")
    except Exception as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from error
