"""Future model providers produce proposals, never authoritative transitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class InterpretationProposal:
    classification: dict[str, Any]
    content_inputs: dict[str, Any]


class InterpretationAdapter(Protocol):
    def propose(self, candidate: dict[str, Any]) -> InterpretationProposal:
        """Return a proposal for deterministic validation by application code."""
        ...
