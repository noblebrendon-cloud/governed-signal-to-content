from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import pytest

from governed_signal_to_content import database
from governed_signal_to_content.authentication import (
    bootstrap_trusted_principal,
    generate_signing_key,
    prepare_operation,
    prepare_policy_operation,
    sign_operation,
)
from governed_signal_to_content.config import WorkspacePaths, workspace_paths
from governed_signal_to_content.deduplication import (
    deduplicate_candidate,
    normalize_candidate,
)
from governed_signal_to_content.evidence import ingest_signal
from governed_signal_to_content.qualification import qualify_candidate
from governed_signal_to_content.models import (
    AuthorityOperation,
    Capability,
    CapabilityPolicyOperation,
    SignedOperation,
)
from governed_signal_to_content.transition_mediator import (
    mediate_signed_policy_operation,
)


@pytest.fixture()
def workspace(tmp_path: Path) -> WorkspacePaths:
    paths = workspace_paths(tmp_path / "workspace")
    database.initialize_workspace(paths)
    return paths


@pytest.fixture()
def qualified_candidate(workspace: WorkspacePaths, tmp_path: Path) -> tuple[WorkspacePaths, str]:
    candidate, _, _ = ingest_signal(
        paths=workspace,
        title="A governed capability",
        source_url="https://example.com/docs/capability",
        source_file=None,
    )
    normalize_candidate(workspace, candidate.candidate_id)
    _, duplicate, _ = deduplicate_candidate(workspace, candidate.candidate_id)
    assert not duplicate
    classification = {
        "schema_version": "1.0",
        "documented_facts": ["The primary source documents a capability."],
        "reasonable_inferences": ["Durable identity may aid reuse."],
        "direct_similarities": ["Both use durable identity."],
        "broader_industry_trends": ["Capabilities are becoming managed resources."],
        "primary_sources": ["https://example.com/docs/capability"],
        "structural_overlap_dimensions": ["durable operational identity"],
        "qualification_decision": True,
        "qualification_reason": "The bounded structural overlap is substantive.",
    }
    path = tmp_path / "classification.json"
    path.write_text(json.dumps(classification), encoding="utf-8", newline="\n")
    _, qualified, _ = qualify_candidate(workspace, candidate.candidate_id, path)
    assert qualified
    return workspace, candidate.candidate_id


@pytest.fixture()
def content_inputs_path(tmp_path: Path) -> Path:
    value = {
        "schema_version": "1.0",
        "linkedin_analysis": "A governed analysis draft with explicit evidence boundaries.",
        "csg_facebook_post": "A governed social draft with explicit approval boundaries.",
        "mermaid_diagram": "flowchart LR\nA[prompt] --> B[approval]",
        "governed_operating_layers_essay": "A governed essay draft that remains reviewable.",
        "repository_note": "See `src/governed_signal_to_content/state_machine.py`.",
        "sources": ["https://example.com/docs/capability"],
        "scope": {
            "scope_version": "1.0",
            "brand_id": "brand-test",
            "channel_id": "channel-test",
            "destination_id": "destination-test",
        },
    }
    path = tmp_path / "content-inputs.json"
    path.write_text(json.dumps(value), encoding="utf-8", newline="\n")
    return path


@pytest.fixture()
def authentication_material(
    workspace: WorkspacePaths, tmp_path: Path
) -> dict[str, object]:
    principal_id = "principal_test_reviewer"
    private_key = tmp_path / "principal-private.pem"
    public_key = tmp_path / "principal-public.pem"
    generate_signing_key(private_key, public_key)
    bootstrap_trusted_principal(workspace.database, principal_id, public_key)
    return {
        "principal_id": principal_id,
        "private_key": private_key,
        "public_key": public_key,
    }


@pytest.fixture()
def signed_operation(
    workspace: WorkspacePaths,
    authentication_material: dict[str, object],
) -> Callable[[str, AuthorityOperation, str], SignedOperation]:
    principal_id = str(authentication_material["principal_id"])
    private_key = Path(str(authentication_material["private_key"]))
    policy_ready = False

    def establish_test_policy(packet_id: str) -> None:
        nonlocal policy_ready
        if policy_ready:
            return
        packet = database.get_packet(workspace.database, packet_id)
        assert packet is not None
        bootstrap = prepare_policy_operation(
            paths=workspace,
            operation=CapabilityPolicyOperation.BOOTSTRAP,
            principal_id=principal_id,
            reason="Test capability-policy bootstrap.",
        )
        mediate_signed_policy_operation(
            paths=workspace,
            signed_operation=sign_operation(bootstrap, private_key),
            asserted_actor="test-policy-fixture",
            expected_operation=CapabilityPolicyOperation.BOOTSTRAP,
        )
        for capability in (
            Capability.PACKET_APPROVE,
            Capability.PACKET_REJECT,
            Capability.PACKET_RELEASE,
        ):
            grant = prepare_policy_operation(
                paths=workspace,
                operation=CapabilityPolicyOperation.GRANT,
                principal_id=principal_id,
                subject_principal_id=principal_id,
                capability=capability,
                brand_id=str(packet["brand_id"]),
                channel_id=str(packet["channel_id"]),
                destination_id=str(packet["destination_id"]),
                reason=f"Test grant for {capability.value}.",
            )
            mediate_signed_policy_operation(
                paths=workspace,
                signed_operation=sign_operation(grant, private_key),
                asserted_actor="test-policy-fixture",
                expected_operation=CapabilityPolicyOperation.GRANT,
            )
        policy_ready = True

    def make(
        packet_id: str, operation: AuthorityOperation, reason: str
    ) -> SignedOperation:
        establish_test_policy(packet_id)
        envelope = prepare_operation(
            paths=workspace,
            operation=operation,
            packet_id=packet_id,
            principal_id=principal_id,
            reason=reason,
        )
        return sign_operation(envelope, private_key)

    return make
