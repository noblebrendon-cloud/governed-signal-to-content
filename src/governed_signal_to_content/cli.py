"""Command-line interface for the governed local workflow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import NoReturn

import typer

from . import __version__, database
from .approvals import decide_packet, release_packet
from .config import require_workspace, workspace_paths
from .deduplication import deduplicate_candidate, normalize_candidate
from .evidence import ingest_signal
from .packets import generate_packet
from .qualification import qualify_candidate
from .receipts import find_receipt


app = typer.Typer(
    no_args_is_help=True,
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
        ..., "--content-inputs", help="Validated JSON containing the five drafts and sources."
    ),
) -> None:
    """Atomically generate the fixed five-artifact packet plus sources and receipt."""
    try:
        packet_id, run_id, warnings, manifest_hash = generate_packet(
            require_workspace(workspace), candidate_id, content_inputs
        )
        typer.echo(
            json.dumps(
                {
                    "candidate_id": candidate_id,
                    "packet_id": packet_id,
                    "state": "AWAITING_APPROVAL",
                    "manifest_hash": manifest_hash,
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
    actor: str = typer.Option(..., "--actor", help="Human approver identity."),
) -> None:
    """Move an AWAITING_APPROVAL packet to APPROVED and record the human actor."""
    try:
        run_id = decide_packet(
            paths=require_workspace(workspace),
            packet_id=packet_id,
            actor=actor,
            approved=True,
            reason="Explicit human approval recorded.",
        )
        typer.echo(json.dumps({"packet_id": packet_id, "state": "APPROVED", "run_id": run_id}, indent=2))
    except Exception as error:
        _fail(error)


@app.command()
def reject(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    packet_id: str = typer.Option(..., "--packet-id", help="Packet stable ID."),
    actor: str = typer.Option(..., "--actor", help="Human reviewer identity."),
    reason: str = typer.Option(..., "--reason", help="Required rejection reason."),
) -> None:
    """Move an AWAITING_APPROVAL packet to REJECTED and record the reason."""
    try:
        run_id = decide_packet(
            paths=require_workspace(workspace),
            packet_id=packet_id,
            actor=actor,
            approved=False,
            reason=reason,
        )
        typer.echo(json.dumps({"packet_id": packet_id, "state": "REJECTED", "run_id": run_id}, indent=2))
    except Exception as error:
        _fail(error)


@app.command()
def release(
    workspace: Path = typer.Option(..., "--workspace", help="Initialized workspace path."),
    packet_id: str = typer.Option(..., "--packet-id", help="Approved packet stable ID."),
    actor: str = typer.Option(..., "--actor", help="Human release authorizer identity."),
) -> None:
    """Mark APPROVED as RELEASED locally; this authorizes downstream use but posts nothing online."""
    try:
        run_id = release_packet(require_workspace(workspace), packet_id, actor)
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
