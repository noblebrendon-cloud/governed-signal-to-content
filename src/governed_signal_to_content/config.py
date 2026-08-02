"""Workspace paths and configuration loading."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class WorkspacePaths:
    root: Path

    @property
    def evidence(self) -> Path:
        return self.root / "evidence"

    @property
    def candidates(self) -> Path:
        return self.root / "candidates"

    @property
    def packets(self) -> Path:
        return self.root / "packets"

    @property
    def approvals(self) -> Path:
        return self.root / "approvals"

    @property
    def receipts(self) -> Path:
        return self.root / "receipts"

    @property
    def receipt_log(self) -> Path:
        return self.receipts / "run_receipts.jsonl"

    @property
    def state(self) -> Path:
        return self.root / "state"

    @property
    def database(self) -> Path:
        return self.state / "watch_state.sqlite"


def workspace_paths(path: Path) -> WorkspacePaths:
    return WorkspacePaths(path.expanduser().resolve())


def require_workspace(path: Path) -> WorkspacePaths:
    paths = workspace_paths(path)
    if not paths.database.is_file() or not paths.receipt_log.is_file():
        raise FileNotFoundError(
            f"Workspace is not initialized: {paths.root}. Run 'gs2c init --workspace PATH'."
        )
    return paths


def load_yaml(path: Path) -> object:
    with path.open("r", encoding="utf-8") as stream:
        return yaml.safe_load(stream)
