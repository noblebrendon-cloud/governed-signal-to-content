"""Future discovery providers propose signals but cannot mutate workflow state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence


@dataclass(frozen=True)
class DiscoveredSignal:
    title: str
    source_url: str


class DiscoveryAdapter(Protocol):
    def discover(self) -> Sequence[DiscoveredSignal]:
        """Return proposed signals without writing authoritative state."""
        ...
