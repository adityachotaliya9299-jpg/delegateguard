"""
DC-06: Batch executor replay / nonce gaps.

Detects signature-based execution functions that use per-target nonces instead of a global nonce, or lack a deadline field in the signed struct.
"""
from __future__ import annotations
from typing import List

from ..core.base_detector import BaseDetector
from ..core.finding import Finding, Severity, BugClass


class DC06_BatchReplayDetector(BaseDetector):

    BUG_CLASS   = BugClass.DC06_BATCH_REPLAY
    TITLE       = "Batch executor replay / nonce gap (DC-06)"
    DESCRIPTION = (
        "Signature-based execution function uses a per-target nonce or lacks "
        "a deadline. Signatures can be replayed against other targets or held "
        "indefinitely and replayed at an attacker-chosen time."
    )
    POC_REF = "lab/test/DC06_BatchReplay.t.sol"

    _EXEC_NAMES  = {"execute", "executebatch", "executesignedcall", "relay", "dispatch"}
    _GLOBAL_NONCE_HINTS = {"globalNonce", "nonce", "_nonce"}
    _DEADLINE_HINTS     = {"deadline", "expiry", "expiration", "validUntil"}

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            for func in contract.functions:
                if func.name.lower() not in self._EXEC_NAMES:
                    continue
                if not self._takes_signature(func):
                    continue

                missing = []
                if not self._has_deadline(func):
                    missing.append("deadline")
                if self._has_per_target_nonce(func):
                    missing.append("global nonce (uses per-target nonce)")

                if not missing:
                    continue

                src_file, line = self._source_info(func)
                findings.append(Finding(
                    bug_class=self.BUG_CLASS,
                    severity=Severity.HIGH,
                    title=self.TITLE,
                    description=(
                        f"`{contract.name}.{func.name}()` is missing: {', '.join(missing)}. "
                        "Per-target nonces allow the same signature to be replayed against "
                        "a different target. Missing deadlines mean signatures are valid forever."
                    ),
                    contract=contract.name,
                    function=func.name,
                    line=line,
                    source_file=src_file,
                    recommendation=(
                        "Use a single monotonically-incrementing global nonce. "
                        "Include a `deadline` (uint256) in the signed struct and check "
                        "`require(block.timestamp <= deadline, 'expired')`."
                    ),
                    poc_ref=self.POC_REF,
                ))

        return findings

    def _takes_signature(self, func) -> bool:
        for param in func.parameters:
            if "sig" in param.name.lower() or "signature" in param.name.lower():
                return True
            if str(param.type) == "bytes":
                return True
        return False

    def _has_deadline(self, func) -> bool:
        for param in func.parameters:
            if any(h in param.name.lower() for h in ("deadline", "expir", "valid")):
                return True
        for node in func.nodes:
            src = str(node.expression) if node.expression else ""
            if any(h in src.lower() for h in self._DEADLINE_HINTS):
                return True
        return False

    def _has_per_target_nonce(self, func) -> bool:
        """
        Heuristic: nonce is looked up in a mapping(address => uint256)
        keyed by the call target, rather than a simple uint256.
        """
        for node in func.nodes:
            src = str(node.expression) if node.expression else ""
            # Per-target pattern: nonces[target] or nonces[msg.sender] keyed per address
            if "nonces[" in src and ("target" in src or "to" in src or "recipient" in src):
                return True
        return False