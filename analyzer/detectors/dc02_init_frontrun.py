"""
DC-02: Unprotected / front-runnable initializer.

Detects initialize() functions that do not verify the caller is the EOA itself (tx.origin == address(this) check or equivalent).
"""
from __future__ import annotations
from typing import List

from ..core.base_detector import BaseDetector
from ..core.finding import Finding, Severity, BugClass


class DC02_InitFrontrunDetector(BaseDetector):

    BUG_CLASS   = BugClass.DC02_INIT_FRONTRUN
    TITLE       = "Unprotected initializer — front-run risk (DC-02)"
    DESCRIPTION = (
        "The initialize() function does not verify the caller is the EOA "
        "itself. An attacker can front-run the victim's initialization and "
        "become the owner of the delegated EOA."
    )
    POC_REF = "lab/test/DC02_InitFrontrun.t.sol"

    _INIT_NAMES = {"initialize", "init", "_initialize", "__init"}

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            for func in contract.functions:
                if func.name.lower() not in self._INIT_NAMES:
                    continue

                # Check if function has any tx.origin or self-auth guard
                if self._has_self_auth(func):
                    continue

                src_file, line = self._source_info(func)
                findings.append(Finding(
                    bug_class=self.BUG_CLASS,
                    severity=Severity.HIGH,
                    title=self.TITLE,
                    description=(
                        f"`{contract.name}.{func.name}()` has no caller authentication. "
                        "Any address can call this before the EOA owner does, "
                        "taking ownership of the delegated account."
                    ),
                    contract=contract.name,
                    function=func.name,
                    line=line,
                    source_file=src_file,
                    recommendation=(
                        "Add `require(msg.sender == tx.origin && tx.origin == address(this), "
                        "'only EOA can initialize')` OR bundle initialization atomically "
                        "with the EIP-7702 authorization in the same transaction."
                    ),
                    poc_ref=self.POC_REF,
                ))

        return findings

    def _has_self_auth(self, func) -> bool:
        """Check if the function references tx.origin in a require/assert."""
        for node in func.nodes:
            src = str(node.expression) if node.expression else ""
            if "tx.origin" in src or "origin" in src.lower():
                return True
            # Also check for OZ Initializable pattern
            if "initializing" in src.lower() or "_initialized" in src.lower():
                return True
        return False