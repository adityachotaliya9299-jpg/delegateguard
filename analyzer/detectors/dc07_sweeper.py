"""
DC-07: Sweeper pattern.

Detects delegate contracts with arbitrary external call/transfer functions that have no call-target allowlist. This is the #1 live phishing exploit class post-EIP-7702.
"""
from __future__ import annotations
from typing import List

from slither.slithir.operations import LowLevelCall, Transfer, Send

from ..core.base_detector import BaseDetector
from ..core.finding import Finding, Severity, BugClass


class DC07_SweeperDetector(BaseDetector):

    BUG_CLASS   = BugClass.DC07_SWEEPER
    TITLE       = "Sweeper pattern — arbitrary call with no allowlist (DC-07)"
    DESCRIPTION = (
        "Contract exposes an execute() or similar function that issues an "
        "arbitrary external call with no target allowlist and no strong "
        "authentication. This is the dominant live phishing exploit class "
        "for EIP-7702 delegate contracts."
    )
    POC_REF = "lab/test/DC07_Sweeper.t.sol"

    _EXEC_NAMES = {"execute", "call", "sweep", "drain", "transfer", "send",
                   "executecall", "delegateto", "proxy"}

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            for func in contract.functions:
                if func.view or func.pure:
                    continue
                if func.visibility not in ("public", "external"):
                    continue

                # Check for arbitrary low-level call / transfer in function body
                has_arbitrary_call = self._has_arbitrary_external_call(func)
                if not has_arbitrary_call:
                    continue

                # Check auth and allowlist
                has_auth      = self._has_sender_check(func)
                has_allowlist = self._has_allowlist_check(func)

                if has_auth and has_allowlist:
                    continue  # properly protected

                severity = Severity.CRITICAL if not has_auth else Severity.HIGH
                missing  = []
                if not has_auth:
                    missing.append("caller authentication")
                if not has_allowlist:
                    missing.append("call-target allowlist")

                src_file, line = self._source_info(func)
                findings.append(Finding(
                    bug_class=self.BUG_CLASS,
                    severity=severity,
                    title=self.TITLE,
                    description=(
                        f"`{contract.name}.{func.name}()` issues an arbitrary external "
                        f"call missing: {', '.join(missing)}. "
                        "An attacker who tricks a user into delegating to this contract "
                        "can drain all ETH and tokens in one transaction."
                    ),
                    contract=contract.name,
                    function=func.name,
                    line=line,
                    source_file=src_file,
                    recommendation=(
                        "1. Add `onlyOwner` (require msg.sender == owner). "
                        "2. Maintain an explicit `mapping(address => bool) allowedTargets` "
                        "and check it before every external call. "
                        "3. Consider removing generic execute() entirely in favor of "
                        "purpose-built, constrained functions."
                    ),
                    poc_ref=self.POC_REF,
                ))

        return findings

    def _has_arbitrary_external_call(self, func) -> bool:
        for node in func.nodes:
            for ir in node.irs:
                if isinstance(ir, (LowLevelCall, Transfer, Send)):
                    return True
            # Also catch .call{value:...}(...) via expression string
            src = str(node.expression) if node.expression else ""
            if ".call{" in src or ".call(" in src:
                return True
        return False

    def _has_sender_check(self, func) -> bool:
        for node in func.nodes:
            src = str(node.expression) if node.expression else ""
            if "msg.sender" in src:
                return True
        for mod in func.modifiers:
            if any(kw in str(mod).lower() for kw in ("owner", "auth", "only", "role")):
                return True
        return False

    def _has_allowlist_check(self, func) -> bool:
        for node in func.nodes:
            src = str(node.expression) if node.expression else ""
            if any(kw in src.lower() for kw in
                   ("allowed", "whitelist", "allowlist", "approved", "permitted")):
                return True
        return False