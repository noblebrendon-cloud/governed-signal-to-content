"""Command-line interface for the governed local workflow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import NoReturn

import typer

from . import __version__, database
from .approvals import load_authenticated_operation
from .authentication import (
    APPROVAL_REASON,
    RELEASE_REASON,
    bootstrap_trusted_principal,
    generate_signing_key,
    load_operation_envelope,
    prepare_destination_binding_operation,
    prepare_executor_registration_operation,
    prepare_operation,
    prepare_policy_operation,
    sign_operation,
    write_json_exclusive,
)
from .config import require_workspace, workspace_paths
from .deduplication import deduplicate_candidate, normalize_candidate
from .evidence import ingest_signal
from .integrity import verify_integrity
from .effect_protocol import load_signed_executor_result
from .external_effects import (
    claim_external_effect,
    create_external_effect_request,
    list_destination_bindings,
    list_external_effects,
    mediate_execution_management,
    record_signed_executor_result,
)
from .packets import generate_packet
from .qualification import qualify_candidate
from .receipts import find_receipt, reconcile_pending_receipts
from .models import AuthorityOperation, Capability, CapabilityPolicyOperation
from .transition_mediator import (
    mediate_signed_policy_operation,
    mediate_signed_transition,
)


app = typer.Typer(
    no_args_is_help=True,
    invoke_without_command=True,
    add_completion=False,
    help=(
        "Prepare evidence-backed publication candidates in a local, deterministic, "
        "human-approved workflow."
    ),
)


def _fail(error: Exception) -> NoReturn:
    typer.echo(f"Error: {error}", err=True)
    raise typer.Exit(code=1)


@app.callback()
def application_version(
    version: bool = typer.Option(
        False, "--version", help="Show the application version and exit.", is_eager=True
    ),
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command("init")
def init_workspace(
    workspace: Path = typer.Option(..., "--workspace", help="Runtime workspace path."),
) -> None:
    """Create governed workspace directories and the SQLite schema."""
    try:
        paths = workspace_paths(workspace)
        database.initialize_workspace(paths)
        typer.echo(f"Initialized governed workspace: {paths.root}")
    except Exception as error:
        _fail(error)


@app.command()
def ingest(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    title: str = typer.Option(..., "--title", help="Candidate title."),
    source_url: str = typer.Option(..., "--source-url", help="Primary HTTP(S) source URL."),
    source_file: Path | None = typer.Option(
        None, "--source-file", help="Optional local evidence file to preserve immutably."
    ),
) -> None:
    """Create a candidate and preserve bytes or an honest URL-only evidence reference."""
    try:
        candidate, evidence, run_id = ingest_signal(
            paths=require_workspace(workspace),
            title=title,
            source_url=source_url,
            source_file=source_file,
        )
        typer.echo(
            json.dumps(
                {
                    "candidate_id": candidate.candidate_id,
                    "evidence_id": evidence.evidence_id,
                    "content_preserved": evidence.content_preserved,
                    "state": "EVIDENCE_PRESERVED",
                    "run_id": run_id,
                },
                indent=2,
            )
        )
    except Exception as error:
        _fail(error)


@app.command()
def normalize(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    candidate_id: str = typer.Option(..., "--candidate-id", help="Candidate stable ID."),
) -> None:
    """Create a deterministic normalized candidate record."""
    try:
        run_id = normalize_candidate(require_workspace(workspace), candidate_id)
        typer.echo(json.dumps({"candidate_id": candidate_id, "state": "NORMALIZED", "run_id": run_id}, indent=2))
    except Exception as error:
        _fail(error)


@app.command()
def deduplicate(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    candidate_id: str = typer.Option(..., "--candidate-id", help="Candidate stable ID."),
) -> None:
    """Check source identity, normalized URL, and known development identifiers."""
    try:
        run_id, duplicate, reason = deduplicate_candidate(
            require_workspace(workspace), candidate_id
        )
        typer.echo(
            json.dumps(
                {
                    "candidate_id": candidate_id,
                    "duplicate": duplicate,
                    "state": "SUPPRESSED" if duplicate else "DUPLICATE_CHECKED",
                    "reason": reason,
                    "run_id": run_id,
                },
                indent=2,
            )
        )
    except Exception as error:
        _fail(error)


@app.command()
def qualify(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    candidate_id: str = typer.Option(..., "--candidate-id", help="Candidate stable ID."),
    classification: Path = typer.Option(
        ..., "--classification", help="Validated classification JSON proposal."
    ),
) -> None:
    """Validate a classification proposal; application logic controls qualification."""
    try:
        run_id, qualified, reason = qualify_candidate(
            require_workspace(workspace), candidate_id, classification
        )
        typer.echo(
            json.dumps(
                {
                    "candidate_id": candidate_id,
                    "qualified": qualified,
                    "state": "QUALIFIED" if qualified else "DUPLICATE_CHECKED",
                    "reason": reason,
                    "run_id": run_id,
                },
                indent=2,
            )
        )
        if not qualified:
            raise typer.Exit(code=2)
    except typer.Exit:
        raise
    except Exception as error:
        _fail(error)


@app.command()
def generate(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    candidate_id: str = typer.Option(..., "--candidate-id", help="Qualified candidate ID."),
    content_inputs: Path = typer.Option(
        ...,
        "--content-inputs",
        help="Validated JSON containing the five drafts, sources, and canonical scope.",
    ),
) -> None:
    """Atomically generate the fixed five-artifact packet plus sources and receipt."""
    try:
        paths = require_workspace(workspace)
        packet_id, run_id, warnings, manifest_hash = generate_packet(
            paths, candidate_id, content_inputs
        )
        packet = database.get_packet(paths.database, packet_id)
        if packet is None:  # pragma: no cover - canonical generation just committed it
            raise RuntimeError("Generated packet disappeared before CLI reporting")
        typer.echo(
            json.dumps(
                {
                    "candidate_id": candidate_id,
                    "packet_id": packet_id,
                    "state": "AWAITING_APPROVAL",
                    "manifest_hash": manifest_hash,
                    "scope": {
                        "scope_version": packet["scope_version"],
                        "brand_id": packet["brand_id"],
                        "channel_id": packet["channel_id"],
                        "destination_id": packet["destination_id"],
                    },
                    "warnings": warnings,
                    "run_id": run_id,
                },
                indent=2,
            )
        )
    except Exception as error:
        _fail(error)


@app.command()
def approve(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    packet_id: str = typer.Option(..., "--packet-id", help="Packet stable ID."),
    actor: str = typer.Option(..., "--actor", help="Asserted human approver identity."),
    authenticated_operation: Path | None = typer.Option(
        None,
        "--authenticated-operation",
        help="Signed exact-operation JSON from a trusted principal.",
    ),
) -> None:
    """Move an AWAITING_APPROVAL packet to APPROVED and record the human actor."""
    try:
        result = mediate_signed_transition(
            paths=require_workspace(workspace),
            signed_operation=load_authenticated_operation(authenticated_operation),
            asserted_actor=actor,
            expected_operation=AuthorityOperation.APPROVE,
            expected_packet_id=packet_id,
            expected_reason=APPROVAL_REASON,
        )
        run_id = result.canonical_event_id
        typer.echo(json.dumps({"packet_id": packet_id, "state": "APPROVED", "run_id": run_id}, indent=2))
    except Exception as error:
        _fail(error)


@app.command()
def reject(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    packet_id: str = typer.Option(..., "--packet-id", help="Packet stable ID."),
    actor: str = typer.Option(..., "--actor", help="Asserted human reviewer identity."),
    reason: str = typer.Option(..., "--reason", help="Required rejection reason."),
    authenticated_operation: Path | None = typer.Option(
        None,
        "--authenticated-operation",
        help="Signed exact-operation JSON from a trusted principal.",
    ),
) -> None:
    """Move an AWAITING_APPROVAL packet to REJECTED and record the reason."""
    try:
        result = mediate_signed_transition(
            paths=require_workspace(workspace),
            signed_operation=load_authenticated_operation(authenticated_operation),
            asserted_actor=actor,
            expected_operation=AuthorityOperation.REJECT,
            expected_packet_id=packet_id,
            expected_reason=reason,
        )
        run_id = result.canonical_event_id
        typer.echo(json.dumps({"packet_id": packet_id, "state": "REJECTED", "run_id": run_id}, indent=2))
    except Exception as error:
        _fail(error)


@app.command()
def release(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    packet_id: str = typer.Option(..., "--packet-id", help="Approved packet stable ID."),
    actor: str = typer.Option(
        ..., "--actor", help="Asserted human release-authorizer identity."
    ),
    authenticated_operation: Path | None = typer.Option(
        None,
        "--authenticated-operation",
        help="Signed exact-operation JSON from a trusted principal.",
    ),
) -> None:
    """Mark APPROVED as RELEASED locally; this authorizes downstream use but posts nothing online."""
    try:
        result = mediate_signed_transition(
            paths=require_workspace(workspace),
            signed_operation=load_authenticated_operation(authenticated_operation),
            asserted_actor=actor,
            expected_operation=AuthorityOperation.RELEASE,
            expected_packet_id=packet_id,
            expected_reason=RELEASE_REASON,
        )
        run_id = result.canonical_event_id
        typer.echo(
            json.dumps(
                {
                    "packet_id": packet_id,
                    "state": "RELEASED",
                    "external_publication": False,
                    "meaning": "Locally authorized for downstream publication; not posted online.",
                    "run_id": run_id,
                },
                indent=2,
            )
        )
    except Exception as error:
        _fail(error)


@app.command("principal-keygen")
def principal_keygen(
    private_key: Path = typer.Option(
        ..., "--private-key", help="New private key path outside workspace and repository."
    ),
    public_key: Path = typer.Option(..., "--public-key", help="New public key path."),
) -> None:
    """Generate a local Ed25519 keypair at explicit non-canonical paths."""
    try:
        identity = generate_signing_key(private_key, public_key)
        typer.echo(
            json.dumps(
                {
                    **identity,
                    "private_key_path": str(private_key.expanduser().resolve()),
                    "public_key_path": str(public_key.expanduser().resolve()),
                    "private_key_persisted_in_workspace": False,
                },
                indent=2,
            )
        )
    except Exception as error:
        _fail(error)


@app.command("principal-bootstrap")
def principal_bootstrap(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    principal_id: str = typer.Option(..., "--principal-id", help="Stable principal ID."),
    public_key: Path = typer.Option(..., "--public-key", help="Ed25519 public key path."),
) -> None:
    """One-time bootstrap of the empty trusted-principal registry."""
    try:
        paths = require_workspace(workspace)
        principal = bootstrap_trusted_principal(
            paths.database, principal_id, public_key
        )
        typer.echo(
            json.dumps(
                {
                    "principal_id": principal.principal_id,
                    "authentication_scheme": principal.authentication_scheme,
                    "key_id": principal.key_id,
                    "verifier_fingerprint": principal.verifier_fingerprint,
                    "private_key_stored": False,
                },
                indent=2,
            )
        )
    except Exception as error:
        _fail(error)


@app.command("prepare-operation")
def prepare_authenticated_operation(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    operation: AuthorityOperation = typer.Option(..., "--operation"),
    packet_id: str = typer.Option(..., "--packet-id"),
    principal_id: str = typer.Option(..., "--principal-id"),
    output: Path = typer.Option(..., "--output", help="New unsigned operation JSON path."),
    reason: str | None = typer.Option(
        None, "--reason", help="Required for reject; fixed for approve/release."
    ),
) -> None:
    """Construct an unsigned exact-operation envelope from current canonical state."""
    try:
        if operation is AuthorityOperation.REJECT:
            if reason is None or not reason.strip():
                raise ValueError("Reject operation requires --reason")
            operation_reason = reason
        elif operation is AuthorityOperation.APPROVE:
            if reason is not None and reason != APPROVAL_REASON:
                raise ValueError("Approve reason is fixed by the canonical CLI operation")
            operation_reason = APPROVAL_REASON
        else:
            if reason is not None and reason != RELEASE_REASON:
                raise ValueError("Release reason is fixed by the canonical CLI operation")
            operation_reason = RELEASE_REASON
        envelope = prepare_operation(
            paths=require_workspace(workspace),
            operation=operation,
            packet_id=packet_id,
            principal_id=principal_id,
            reason=operation_reason,
        )
        write_json_exclusive(output, envelope)
        typer.echo(
            json.dumps(
                {
                    "operation_id": envelope.operation_id,
                    "operation": envelope.operation.value,
                    "packet_id": envelope.target_id,
                    "scope": {
                        "scope_version": envelope.scope_version,
                        "brand_id": envelope.brand_id,
                        "channel_id": envelope.channel_id,
                        "destination_id": envelope.destination_id,
                    },
                    "output": str(output.expanduser().resolve()),
                    "expires_at_utc": envelope.expires_at_utc,
                },
                indent=2,
            )
        )
    except Exception as error:
        _fail(error)


@app.command("prepare-policy-operation")
def prepare_authenticated_policy_operation(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    operation: CapabilityPolicyOperation = typer.Option(..., "--operation"),
    principal_id: str = typer.Option(..., "--principal-id"),
    output: Path = typer.Option(..., "--output", help="New unsigned operation JSON path."),
    reason: str = typer.Option(..., "--reason"),
    subject_principal_id: str | None = typer.Option(
        None, "--subject-principal-id", help="Principal receiving a new grant."
    ),
    capability: Capability | None = typer.Option(
        None, "--capability", help="Fixed capability for a new grant."
    ),
    grant_id: str | None = typer.Option(
        None, "--grant-id", help="Existing immutable grant ID to revoke."
    ),
    brand_id: str | None = typer.Option(
        None, "--brand-id", help="Exact brand scope for an operational grant."
    ),
    channel_id: str | None = typer.Option(
        None, "--channel-id", help="Exact channel scope for an operational grant."
    ),
    destination_id: str | None = typer.Option(
        None,
        "--destination-id",
        help="Exact logical destination scope for an operational grant.",
    ),
) -> None:
    """Construct an unsigned exact capability-policy operation."""
    try:
        envelope = prepare_policy_operation(
            paths=require_workspace(workspace),
            operation=operation,
            principal_id=principal_id,
            reason=reason,
            subject_principal_id=subject_principal_id,
            capability=capability,
            grant_id=grant_id,
            brand_id=brand_id,
            channel_id=channel_id,
            destination_id=destination_id,
        )
        write_json_exclusive(output, envelope)
        typer.echo(
            json.dumps(
                {
                    "operation_id": envelope.operation_id,
                    "operation": envelope.operation.value,
                    "grant_id": envelope.grant_id,
                    "revocation_id": envelope.revocation_id,
                    "subject_principal_id": envelope.subject_principal_id,
                    "capability": envelope.capability.value,
                    "scope": {
                        "scope_version": envelope.scope_version,
                        "brand_id": envelope.brand_id,
                        "channel_id": envelope.channel_id,
                        "destination_id": envelope.destination_id,
                    },
                    "output": str(output.expanduser().resolve()),
                    "expires_at_utc": envelope.expires_at_utc,
                },
                indent=2,
            )
        )
    except Exception as error:
        _fail(error)


@app.command("sign-operation")
def sign_authenticated_operation(
    operation_file: Path = typer.Option(..., "--operation-file"),
    private_key: Path = typer.Option(
        ..., "--private-key", help="Private Ed25519 key outside canonical storage."
    ),
    output: Path = typer.Option(..., "--output", help="New signed operation JSON path."),
) -> None:
    """Sign one canonical operation envelope without opening a workspace database."""
    try:
        envelope = load_operation_envelope(operation_file)
        signed = sign_operation(envelope, private_key)
        write_json_exclusive(output, signed)
        typer.echo(
            json.dumps(
                {
                    "operation_id": envelope.operation_id,
                    "principal_id": envelope.principal_id,
                    "output": str(output.expanduser().resolve()),
                    "workspace_opened": False,
                },
                indent=2,
            )
        )
    except Exception as error:
        _fail(error)


def _apply_policy_operation(
    *,
    workspace: Path,
    actor: str,
    authenticated_operation: Path,
    expected_operation: CapabilityPolicyOperation,
) -> None:
    paths = require_workspace(workspace)
    result = mediate_signed_policy_operation(
        paths=paths,
        signed_operation=load_authenticated_operation(authenticated_operation),
        asserted_actor=actor,
        expected_operation=expected_operation,
    )
    typer.echo(
        json.dumps(
            {
                "operation_id": result.request_id,
                "operation": result.operation.value,
                "grant_id": result.grant_id,
                "revocation_id": result.revocation_id,
                "run_id": result.canonical_event_id,
                "outcome": result.outcome,
            },
            indent=2,
        )
    )


@app.command("bootstrap-policy-admin")
def bootstrap_policy_admin(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    actor: str = typer.Option(..., "--actor", help="Display-only asserted actor."),
    authenticated_operation: Path = typer.Option(..., "--authenticated-operation"),
) -> None:
    """Apply one signed, one-time capability-policy bootstrap operation."""
    try:
        _apply_policy_operation(
            workspace=workspace,
            actor=actor,
            authenticated_operation=authenticated_operation,
            expected_operation=CapabilityPolicyOperation.BOOTSTRAP,
        )
    except Exception as error:
        _fail(error)


@app.command("grant-capability")
def grant_capability(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    actor: str = typer.Option(..., "--actor", help="Display-only asserted actor."),
    authenticated_operation: Path = typer.Option(..., "--authenticated-operation"),
) -> None:
    """Apply one signed capability grant operation."""
    try:
        _apply_policy_operation(
            workspace=workspace,
            actor=actor,
            authenticated_operation=authenticated_operation,
            expected_operation=CapabilityPolicyOperation.GRANT,
        )
    except Exception as error:
        _fail(error)


@app.command("revoke-capability")
def revoke_capability(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    actor: str = typer.Option(..., "--actor", help="Display-only asserted actor."),
    authenticated_operation: Path = typer.Option(..., "--authenticated-operation"),
) -> None:
    """Apply one signed capability revocation operation."""
    try:
        _apply_policy_operation(
            workspace=workspace,
            actor=actor,
            authenticated_operation=authenticated_operation,
            expected_operation=CapabilityPolicyOperation.REVOKE,
        )
    except Exception as error:
        _fail(error)


@app.command("list-capability-grants")
def list_capability_grants(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    principal_id: str | None = typer.Option(None, "--principal-id"),
) -> None:
    """Inspect immutable grants and their current effective status."""
    try:
        paths = require_workspace(workspace)
        grants = database.list_capability_grants(paths.database, principal_id)
        typer.echo(json.dumps({"grants": grants}, indent=2, sort_keys=True))
    except Exception as error:
        _fail(error)


@app.command("prepare-destination-binding")
def prepare_destination_binding(
    workspace: Path = typer.Option(..., "--workspace"),
    principal_id: str = typer.Option(..., "--principal-id"),
    brand_id: str = typer.Option(..., "--brand-id"),
    channel_id: str = typer.Option(..., "--channel-id"),
    destination_id: str = typer.Option(..., "--destination-id"),
    external_target_ref: str = typer.Option(..., "--external-target-ref"),
    credential_ref: str = typer.Option(..., "--credential-ref"),
    reason: str = typer.Option(..., "--reason"),
    output: Path = typer.Option(..., "--output"),
) -> None:
    """Prepare a signed-authority envelope for one immutable logical binding."""
    try:
        envelope = prepare_destination_binding_operation(
            paths=require_workspace(workspace),
            principal_id=principal_id,
            brand_id=brand_id,
            channel_id=channel_id,
            destination_id=destination_id,
            adapter_id="test.capture",
            external_target_ref=external_target_ref,
            credential_ref=credential_ref,
            reason=reason,
        )
        write_json_exclusive(output, envelope)
        typer.echo(
            json.dumps(
                {
                    "operation_id": envelope.operation_id,
                    "binding_id": envelope.target_id,
                    "adapter_id": envelope.adapter_id,
                    "output": str(output.expanduser().resolve()),
                    "expires_at_utc": envelope.expires_at_utc,
                },
                indent=2,
            )
        )
    except Exception as error:
        _fail(error)


@app.command("prepare-effect-executor")
def prepare_effect_executor(
    workspace: Path = typer.Option(..., "--workspace"),
    principal_id: str = typer.Option(..., "--principal-id"),
    executor_id: str = typer.Option(..., "--executor-id"),
    executor_public_key: Path = typer.Option(..., "--executor-public-key"),
    reason: str = typer.Option(..., "--reason"),
    output: Path = typer.Option(..., "--output"),
) -> None:
    """Prepare registration of an executor public verifier identity."""
    try:
        envelope = prepare_executor_registration_operation(
            paths=require_workspace(workspace),
            principal_id=principal_id,
            executor_id=executor_id,
            executor_public_key_path=executor_public_key,
            allowed_adapter_ids=("test.capture",),
            reason=reason,
        )
        write_json_exclusive(output, envelope)
        typer.echo(
            json.dumps(
                {
                    "operation_id": envelope.operation_id,
                    "executor_id": envelope.target_id,
                    "executor_key_id": envelope.executor_key_id,
                    "allowed_adapter_ids": list(envelope.allowed_adapter_ids),
                    "output": str(output.expanduser().resolve()),
                    "private_key_stored": False,
                },
                indent=2,
            )
        )
    except Exception as error:
        _fail(error)


def _apply_execution_management(
    *, workspace: Path, actor: str, authenticated_operation: Path
) -> None:
    result = mediate_execution_management(
        paths=require_workspace(workspace),
        signed_operation=load_authenticated_operation(authenticated_operation),
        asserted_actor=actor,
    )
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))


@app.command("register-destination-binding")
def register_destination_binding(
    workspace: Path = typer.Option(..., "--workspace"),
    actor: str = typer.Option(..., "--actor", help="Display-only asserted actor."),
    authenticated_operation: Path = typer.Option(..., "--authenticated-operation"),
) -> None:
    """Apply one authorized immutable external-destination binding."""
    try:
        _apply_execution_management(
            workspace=workspace,
            actor=actor,
            authenticated_operation=authenticated_operation,
        )
    except Exception as error:
        _fail(error)


@app.command("register-effect-executor")
def register_effect_executor(
    workspace: Path = typer.Option(..., "--workspace"),
    actor: str = typer.Option(..., "--actor", help="Display-only asserted actor."),
    authenticated_operation: Path = typer.Option(..., "--authenticated-operation"),
) -> None:
    """Apply one authorized trusted executor public-identity registration."""
    try:
        _apply_execution_management(
            workspace=workspace,
            actor=actor,
            authenticated_operation=authenticated_operation,
        )
    except Exception as error:
        _fail(error)


@app.command("list-destination-bindings")
def list_bindings(
    workspace: Path = typer.Option(..., "--workspace"),
) -> None:
    """List opaque binding references; credential material is never resolved."""
    try:
        paths = require_workspace(workspace)
        typer.echo(
            json.dumps(
                {"bindings": list_destination_bindings(paths.database)},
                indent=2,
                sort_keys=True,
            )
        )
    except Exception as error:
        _fail(error)


@app.command("create-external-effect")
def create_effect(
    workspace: Path = typer.Option(..., "--workspace"),
    packet_id: str = typer.Option(..., "--packet-id"),
) -> None:
    """Derive a canonical effect request from release authority and its binding."""
    try:
        effect = create_external_effect_request(
            paths=require_workspace(workspace), packet_id=packet_id
        )
        typer.echo(json.dumps(effect.model_dump(mode="json"), indent=2, sort_keys=True))
    except Exception as error:
        _fail(error)


@app.command("claim-external-effect")
def claim_effect(
    workspace: Path = typer.Option(..., "--workspace"),
    effect_id: str = typer.Option(..., "--effect-id"),
) -> None:
    """Acquire the one active dispatch claim for an external effect."""
    try:
        dispatch = claim_external_effect(
            paths=require_workspace(workspace), effect_id=effect_id
        )
        typer.echo(
            json.dumps(dispatch.model_dump(mode="json"), indent=2, sort_keys=True)
        )
    except Exception as error:
        _fail(error)


@app.command("record-external-effect-result")
def record_effect_result(
    workspace: Path = typer.Option(..., "--workspace"),
    signed_result: Path = typer.Option(..., "--signed-result"),
) -> None:
    """Verify and ingest one executor-signed terminal attempt result."""
    try:
        result = record_signed_executor_result(
            paths=require_workspace(workspace),
            signed_result=load_signed_executor_result(signed_result),
        )
        typer.echo(json.dumps(result, indent=2, sort_keys=True))
    except Exception as error:
        _fail(error)


@app.command("list-external-effects")
def list_effects(
    workspace: Path = typer.Option(..., "--workspace"),
) -> None:
    """List derived effect intent, claim, and terminal-result status."""
    try:
        paths = require_workspace(workspace)
        typer.echo(
            json.dumps(
                {"external_effects": list_external_effects(paths.database)},
                indent=2,
                sort_keys=True,
            )
        )
    except Exception as error:
        _fail(error)


@app.command("packet-scope")
def packet_scope(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    packet_id: str = typer.Option(..., "--packet-id", help="Packet stable ID."),
) -> None:
    """Inspect canonical packet scope without migrating or modifying the workspace."""
    try:
        paths = require_workspace(workspace)
        packet = database.get_packet(paths.database, packet_id)
        if packet is None:
            raise KeyError(f"Unknown packet: {packet_id}")
        typer.echo(
            json.dumps(
                {
                    "packet_id": packet_id,
                    "scope_version": packet.get("scope_version"),
                    "brand_id": packet.get("brand_id"),
                    "channel_id": packet.get("channel_id"),
                    "destination_id": packet.get("destination_id"),
                },
                indent=2,
                sort_keys=True,
            )
        )
    except Exception as error:
        _fail(error)


@app.command()
def status(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
) -> None:
    """Show candidate and packet counts grouped by authoritative state."""
    try:
        paths = require_workspace(workspace)
        typer.echo(
            json.dumps(
                {
                    "workspace": str(paths.root),
                    "candidates": database.state_counts(paths.database, "candidates"),
                    "packets": database.state_counts(paths.database, "packets"),
                },
                indent=2,
                sort_keys=True,
            )
        )
    except Exception as error:
        _fail(error)


@app.command("receipt")
def show_receipt(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    run_id: str = typer.Option(..., "--run-id", help="Immutable receipt run UUID."),
) -> None:
    """Display one append-only run receipt without modifying it."""
    try:
        paths = require_workspace(workspace)
        receipt = find_receipt(paths.receipt_log, run_id)
        if receipt is None:
            raise KeyError(f"Unknown run ID: {run_id}")
        typer.echo(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
    except Exception as error:
        _fail(error)


@app.command("reconcile-receipts")
def reconcile_receipts(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
) -> None:
    """Append missing JSONL projections from canonical SQLite transition events."""
    try:
        paths = require_workspace(workspace)
        count = reconcile_pending_receipts(paths.database, paths.receipt_log)
        typer.echo(json.dumps({"projected_transition_events": count}, indent=2))
    except Exception as error:
        _fail(error)


@app.command("verify-integrity")
def verify_workspace_integrity(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
) -> None:
    """Verify chain, policy, external-effect ledger, and JSONL projection."""
    try:
        paths = require_workspace(workspace)
        result = verify_integrity(paths.database, paths.receipt_log)
        typer.echo(
            json.dumps(
                result.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        if (
            not result.canonical_chain_valid
            or not result.canonical_policy_valid
            or not result.canonical_external_effect_valid
            or not result.projection_valid
        ):
            raise typer.Exit(code=1)
    except typer.Exit:
        raise
    except Exception as error:
        _fail(error)
