from __future__ import annotations

import json
from pathlib import Path

import pytest

from governed_signal_to_content.config import WorkspacePaths
from governed_signal_to_content.packets import (
    ARTIFACT_FILENAMES,
    PACKET_FILENAMES,
    generate_packet,
)


def test_required_five_artifact_manifest(
    qualified_candidate: tuple[WorkspacePaths, str], content_inputs_path: Path
) -> None:
    workspace, candidate_id = qualified_candidate
    packet_id, _, warnings, _ = generate_packet(workspace, candidate_id, content_inputs_path)
    packet_dir = workspace.packets / packet_id
    assert {path.name for path in packet_dir.iterdir()} == set(PACKET_FILENAMES)
    receipt = json.loads((packet_dir / "packet_receipt.json").read_text(encoding="utf-8"))
    assert tuple(receipt["required_artifacts"]) == ARTIFACT_FILENAMES
    assert set(ARTIFACT_FILENAMES).issubset(receipt["artifact_hashes"])
    assert warnings


def test_packet_generation_is_atomic_on_write_failure(
    qualified_candidate: tuple[WorkspacePaths, str],
    content_inputs_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, candidate_id = qualified_candidate
    from governed_signal_to_content import packets

    original = packets._write_text
    calls = 0

    def fail_second_write(path: Path, text: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated write failure")
        original(path, text)

    monkeypatch.setattr(packets, "_write_text", fail_second_write)
    with pytest.raises(OSError, match="simulated"):
        generate_packet(workspace, candidate_id, content_inputs_path)
    assert list(workspace.packets.iterdir()) == []
