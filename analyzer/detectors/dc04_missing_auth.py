"""
DC-04: Missing per-call authentication.

Detects state-changing functions that have no msg.sender check in contracts that appear to be 7702 delegates.
"""
from __future__ import annotations
from typing import List

from slither.core.cfg.node import NodeType

from ..core.base_detector import BaseDetector
from ..core.finding import Finding, Severity, BugClass


class DC04_MissingAuthDetector(BaseDetector):

    BUG_CLASS   = BugClass.DC04_MISSING_AUTH
    TITLE       = "Missing per-call authentication (DC-04)"
    DESCRIPTION = (
        "State-changing function has no msg.sender check. In a 7702 delegate, "
        "any external caller can trigger this function — not just the EOA owner."
    )
    POC_REF = "lab/test/DC04_MissingAuth.t.sol"

    # Functions we skip (read-only or known-safe patterns)
    _SKIP_NAMES  = {"initialize", "init", "receive", "fallback", "constructor"}
    _AUTH_CHECKS = {"msg.sender", "onlyOwner", "onlyRole", "require", "revert"}

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            if not self._looks_like_delegate(contract):
                continue

            for func in contract.functions:
                if func.name.lower() in self._SKIP_NAMES:
                    continue
                if func.view or func.pure:
                    continue
                if func.visibility not in ("public", "external"):
                    continue
                if self._has_sender_check(func):
                    continue

                src_file, line = self._source_info(func)
                findings.append(Finding(
                    bug_class=self.BUG_CLASS,
                    severity=Severity.HIGH,
                    title=self.TITLE,
                    description=(
                        f"`{contract.name}.{func.name}()` is a public/external "
                        "state-changing function with no msg.sender authentication. "
                        "Any external caller can invoke it via the delegated EOA."
                    ),
                    contract=contract.name,
                    function=func.name,
                    line=line,
                    source_file=src_file,
                    recommendation=(
                        "Add an `onlyOwner` modifier or explicit "
                        "`require(msg.sender == owner, 'not owner')` check "
                        "to every state-changing function."
                    ),
                    poc_ref=self.POC_REF,
                ))

        return findings

    def _looks_like_delegate(self, contract) -> bool:
        names = {f.name.lower() for f in contract.functions}
        return "initialize" in names or "initialized" in names

    def _has_sender_check(self, func) -> bool:
        for node in func.nodes:
            src = str(node.expression) if node.expression else ""
            if "msg.sender" in src:
                return True
            # Check for modifier usage
        for mod in func.modifiers:
            mod_src = str(mod)
            if any(kw in mod_src for kw in ("owner", "role", "auth", "only")):
                return True
        return False