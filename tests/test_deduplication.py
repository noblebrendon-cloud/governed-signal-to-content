from __future__ import annotations

from governed_signal_to_content import database
from governed_signal_to_content.config import WorkspacePaths
from governed_signal_to_content.deduplication import (
    deduplicate_candidate,
    normalize_candidate,
)
from governed_signal_to_content.evidence import ingest_signal


def test_duplicate_suppression_by_normalized_url(workspace: WorkspacePaths) -> None:
    first, _, _ = ingest_signal(
        paths=workspace,
        title="First",
        source_url="https://EXAMPLE.com/docs/item/?utm_source=test",
        source_file=None,
    )
    normalize_candidate(workspace, first.candidate_id)
    _, duplicate, _ = deduplicate_candidate(workspace, first.candidate_id)
    assert not duplicate

    second, _, _ = ingest_signal(
        paths=workspace,
        title="Second",
        source_url="https://example.com/docs/item",
        source_file=None,
    )
    normalize_candidate(workspace, second.candidate_id)
    _, duplicate, reason = deduplicate_candidate(workspace, second.candidate_id)
    assert duplicate
    assert "normalized URL" in reason
    stored = database.get_candidate(workspace.database, second.candidate_id)
    assert stored is not None
    assert stored["state"] == "SUPPRESSED"
