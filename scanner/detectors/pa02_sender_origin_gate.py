"""
PA-02: msg.sender == tx.origin used as an EOA gate.

This was the canonical "is this caller an EOA?" check pre-7702.
Post-7702: a delegated EOA is still tx.origin for its own transactions,
so this check passes even when the EOA has code and can execute logic.

Any invariant built on "msg.sender == tx.origin => no code => safe" is broken.
"""
from __future__ import annotations
from typing import List

from ..core.base_detector import BaseScannerDetector
from ..core.finding import Finding, Severity, BugClass


class PA02_SenderOriginGateDetector(BaseScannerDetector):

    BUG_CLASS   = BugClass.PA02_SENDER_ORIGIN_GATE
    TITLE       = "msg.sender == tx.origin EOA gate broken by EIP-7702 (PA-02)"
    DESCRIPTION = (
        "`msg.sender == tx.origin` was used as an EOA-only gate. "
        "Post-EIP-7702, delegated EOAs still satisfy this check "
        "but can execute arbitrary code via their delegate."
    )
    POC_REF = "lab/test/PA02_SenderOriginGate.t.sol"

    # Both orderings of the equality check
    _PATTERNS = [
        "msg.sender == tx.origin",
        "tx.origin == msg.sender",
        "msg.sender==tx.origin",
        "tx.origin==msg.sender",
    ]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            for func in contract.functions:
                for node in func.nodes:
                    src = str(node.expression) if node.expression else ""
                    src_stripped = src.replace(" ", "")

                    if not any(p.replace(" ", "") in src_stripped
                               for p in self._PATTERNS):
                        continue

                    src_file, line = self._source_info(node)
                    findings.append(Finding(
                        bug_class=self.BUG_CLASS,
                        severity=Severity.HIGH,
                        title=self.TITLE,
                        description=(
                            f"`{contract.name}.{func.name}()` uses "
                            "`msg.sender == tx.origin` as an EOA-only gate. "
                            "A delegated EOA satisfies this check while having "
                            "full contract-code capabilities via its delegate."
                        ),
                        contract=contract.name,
                        function=func.name,
                        line=line,
                        source_file=src_file,
                        recommendation=(
                            "Remove the `msg.sender == tx.origin` EOA check — it is "
                            "not reliable post-EIP-7702. For Sybil resistance, use a "
                            "Merkle-proof allowlist or ZK proof of personhood. "
                            "For reentrancy protection, use a proper nonReentrant guard."
                        ),
                        poc_ref=self.POC_REF,
                    ))

        return self._deduplicate(findings)