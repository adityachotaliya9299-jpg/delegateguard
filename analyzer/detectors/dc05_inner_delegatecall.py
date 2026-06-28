"""
DC-05: Unsafe inner DELEGATECALL.

Detects delegate contracts that themselves issue DELEGATECALL to unconstrained (non-allowlisted) targets. The inner callee executes in the EOA's storage context with no restriction.
"""
from __future__ import annotations
from typing import List

from slither.slithir.operations import LowLevelCall

from ..core.base_detector import BaseDetector
from ..core.finding import Finding, Severity, BugClass


class DC05_InnerDelegatecallDetector(BaseDetector):

    BUG_CLASS   = BugClass.DC05_INNER_DELEGATECALL
    TITLE       = "Unsafe inner DELEGATECALL to unconstrained target (DC-05)"
    DESCRIPTION = (
        "Contract issues a DELEGATECALL to a target that is not restricted "
        "to a pre-approved allowlist. In a 7702 context, the inner callee "
        "executes arbitrary code in the EOA's storage and asset context."
    )
    POC_REF = "lab/test/DC05_InnerDelegatecall.t.sol"

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            for func in contract.functions:
                for node in func.nodes:
                    for ir in node.irs:
                        if not isinstance(ir, LowLevelCall):
                            continue
                        if ir.function_name != "delegatecall":
                            continue

                        # Check if there is an allowlist guard before this call
                        if self._has_allowlist_guard(func, node):
                            continue

                        src_file, line = self._source_info(node)
                        findings.append(Finding(
                            bug_class=self.BUG_CLASS,
                            severity=Severity.CRITICAL,
                            title=self.TITLE,
                            description=(
                                f"`{contract.name}.{func.name}()` issues a DELEGATECALL "
                                f"to `{ir.destination}` with no allowlist check. "
                                "An attacker can pass a malicious contract as the target "
                                "and execute arbitrary code in the EOA's context."
                            ),
                            contract=contract.name,
                            function=func.name,
                            line=line,
                            source_file=src_file,
                            recommendation=(
                                "Maintain an explicit allowlist of approved DELEGATECALL "
                                "targets: `mapping(address => bool) allowedPlugins`. "
                                "Check `require(allowedPlugins[target])` before every delegatecall."
                            ),
                            poc_ref=self.POC_REF,
                        ))

        return findings

    def _has_allowlist_guard(self, func, dc_node) -> bool:
        """
        Heuristic: check if a require/mapping lookup appears in the function
        before the delegatecall node. Looks for 'allowed' or 'whitelist' patterns.
        """
        for node in func.nodes:
            if node == dc_node:
                break
            src = str(node.expression) if node.expression else ""
            if any(kw in src.lower() for kw in ("allowed", "whitelist", "approved", "permit")):
                return True
        return False