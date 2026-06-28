"""
PA-04: EOA-only reentrancy paths.

The most underappreciated PA bug. Detects functions that:
  1. Make an external call (ETH transfer or .call)
  2. Do NOT have a universal reentrancy guard
  3. Update state AFTER the external call (violates CEI)

Pre-7702: "EOAs can't reenter because they have no code."
Post-7702: A delegated EOA's receive()/fallback() in the delegate
CAN execute logic when ETH is received — enabling reentrancy from
addresses that look like EOAs.
"""
from __future__ import annotations
from typing import List

from slither.slithir.operations import LowLevelCall, Transfer, Send

from ..core.base_detector import BaseScannerDetector
from ..core.finding import Finding, Severity, BugClass


class PA04_EOAReentrancyDetector(BaseScannerDetector):

    BUG_CLASS   = BugClass.PA04_EOA_REENTRANCY
    TITLE       = "EOA-only reentrancy path — bypassable by delegated EOA (PA-04)"
    DESCRIPTION = (
        "Function makes an external call before updating state (violates CEI) "
        "and lacks a universal reentrancy guard. Post-EIP-7702, delegated EOAs "
        "can reenter via their delegate's receive() hook."
    )
    POC_REF = "lab/test/PA04_EOAReentrancy.t.sol"

    _NONREENTRANT_HINTS = {
        "nonReentrant", "nonreentrant", "_locked", "_status",
        "ReentrancyGuard", "reentrancy", "mutex",
    }

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            for func in contract.functions:
                if func.view or func.pure:
                    continue
                if func.visibility not in ("public", "external"):
                    continue

                # Must make an external call
                if not self._makes_external_call(func):
                    continue

                # Skip if proper reentrancy guard present
                if self._has_reentrancy_guard(func):
                    continue

                # Check for CEI violation: state write AFTER external call
                if not self._has_state_write_after_call(func):
                    continue

                src_file, line = self._source_info(func)
                findings.append(Finding(
                    bug_class=self.BUG_CLASS,
                    severity=Severity.CRITICAL,
                    title=self.TITLE,
                    description=(
                        f"`{contract.name}.{func.name}()` sends ETH or makes an "
                        "external call before updating state (CEI violation) "
                        "with no universal reentrancy guard. "
                        "A delegated EOA's receive() hook can reenter this function "
                        "before balances are zeroed."
                    ),
                    contract=contract.name,
                    function=func.name,
                    line=line,
                    source_file=src_file,
                    recommendation=(
                        "Apply two fixes together: "
                        "1. Add a universal `nonReentrant` modifier (no EOA carve-out). "
                        "2. Follow CEI: update all state variables BEFORE making "
                        "external calls. Zero the balance before `.call{value:}()`."
                    ),
                    poc_ref=self.POC_REF,
                ))

        return self._deduplicate(findings)

    def _makes_external_call(self, func) -> bool:
        for node in func.nodes:
            for ir in node.irs:
                if isinstance(ir, (LowLevelCall, Transfer, Send)):
                    return True
            src = str(node.expression) if node.expression else ""
            if ".call{" in src or "transfer(" in src or "send(" in src:
                return True
        return False

    def _has_reentrancy_guard(self, func) -> bool:
        # Check modifiers
        for mod in func.modifiers:
            mod_str = str(mod).lower()
            if any(h in mod_str for h in self._NONREENTRANT_HINTS):
                return True
        # Check function body for mutex pattern
        for node in func.nodes:
            src = str(node.expression) if node.expression else ""
            if any(h in src for h in self._NONREENTRANT_HINTS):
                return True
        return False

    def _has_state_write_after_call(self, func) -> bool:
        """
        Heuristic: look for assignment after a .call / transfer in the node order.
        True CEI analysis requires proper CFG traversal; this is a sound approximation.
        """
        seen_call = False
        for node in func.nodes:
            src = str(node.expression) if node.expression else ""

            if ".call{" in src or "transfer(" in src or "send(" in src:
                seen_call = True
                continue

            if seen_call:
                # Any assignment after a call = potential CEI violation
                for ir in node.irs:
                    from slither.slithir.operations import Assignment, Index
                    if isinstance(ir, (Assignment, Index)):
                        return True
                if "=" in src and "==" not in src and "require" not in src:
                    return True

        return False