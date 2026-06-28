"""
DelegateGuard Scanner — base detector for protocol-assumption bugs. Mirrors analyzer/core/base_detector.py but lives in the scanner package.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from slither import Slither

# Reuse the Finding model from the analyzer core
from analyzer.core.finding import Finding, BugClass  # noqa: F401


class BaseScannerDetector(ABC):
    """Abstract base for all DelegateGuard scanner detectors (PA-*)."""

    BUG_CLASS:   str = ""
    TITLE:       str = ""
    DESCRIPTION: str = ""
    POC_REF:     str = ""

    def __init__(self, slither: "Slither"):
        self.slither = slither

    @abstractmethod
    def run(self) -> List[Finding]:
        """Run the detector and return findings."""
        ...

    def _all_contracts(self):
        return self.slither.contracts

    def _all_functions(self):
        for c in self._all_contracts():
            yield from c.functions

    def _source_info(self, node) -> tuple:
        try:
            loc = node.source_mapping
            return loc.filename.short, loc.lines[0] if loc.lines else None
        except Exception:
            return None, None

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Remove exact duplicate findings (same contract + function + bug_class)."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.bug_class, f.contract, f.function)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique