from __future__ import annotations

import hashlib
from pathlib import Path

from governed_signal_to_content.hashing import canonical_json, canonical_json_hash, sha256_file


def test_sha256_source_identity(tmp_path: Path) -> None:
    source = tmp_path / "evidence.bin"
    source.write_bytes(b"governed evidence\n")
    assert sha256_file(source) == hashlib.sha256(b"governed evidence\n").hexdigest()


def test_canonical_json_hash_ignores_mapping_insertion_order() -> None:
    left = {"b": [2, 1], "a": {"truth": True}}
    right = {"a": {"truth": True}, "b": [2, 1]}
    assert canonical_json(left) == canonical_json(right)
    assert canonical_json_hash(left) == canonical_json_hash(right)
