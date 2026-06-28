"""
DelegateGuard — base detector interface.
All detectors inherit from BaseDetector and implement `run()`.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from slither import Slither

from .finding import Finding


class BaseDetector(ABC):
    """Abstract base for all DelegateGuard detectors."""

    # Subclasses set these
    BUG_CLASS:   str = ""
    TITLE:       str = ""
    DESCRIPTION: str = ""
    POC_REF:     str = ""

    def __init__(self, slither: "Slither"):
        self.slither = slither

    @abstractmethod
    def run(self) -> List[Finding]:
        """Run the detector and return a (possibly empty) list of findings."""
        ...

    # ------------------------------------------------------------------
    # Helpers available to all detectors
    # ------------------------------------------------------------------

    def _all_contracts(self):
        return self.slither.contracts

    def _all_functions(self):
        for c in self._all_contracts():
            yield from c.functions

    def _source_info(self, node) -> tuple:
        """Return (filename, line) for a Slither node, or (None, None)."""
        try:
            loc = node.source_mapping
            return loc.filename.short, loc.lines[0] if loc.lines else None
        except Exception:
            return None, None