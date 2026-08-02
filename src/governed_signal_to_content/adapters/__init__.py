"""Contracts for optional discovery and interpretation providers."""

from .discovery import DiscoveredSignal, DiscoveryAdapter
from .interpretation import InterpretationAdapter, InterpretationProposal

__all__ = [
    "DiscoveredSignal",
    "DiscoveryAdapter",
    "InterpretationAdapter",
    "InterpretationProposal",
]
