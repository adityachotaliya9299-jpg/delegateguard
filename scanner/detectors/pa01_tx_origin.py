"""
PA-01: tx.origin used for authentication.

"""
from __future__ import annotations
from typing import List

from ..core.base_detector import BaseScannerDetector
from ..core.finding import Finding, Severity, BugClass


class PA01_TxOriginDetector(BaseScannerDetector):

    BUG_CLASS   = BugClass.PA01_TX_ORIGIN
    TITLE       = "tx.origin used for authentication (PA-01)"
    DESCRIPTION = (
        "tx.origin is used for access control. A phishing contract can trick "
        "the victim into calling it, then call this protocol — tx.origin still "
        "passes but msg.sender is the attacker's contract."
    )
    POC_REF = "lab/test/PA01_TxOrigin.t.sol"

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            for func in contract.functions:
                for node in func.nodes:
                    src = str(node.expression) if node.expression else ""

                    # tx.origin in a conditional / require = auth usage
                    if "tx.origin" not in src:
                        continue

                    # Skip purely informational reads (e.g., emitting tx.origin in an event)
                    if self._is_informational(src):
                        continue

                    src_file, line = self._source_info(node)
                    findings.append(Finding(
                        bug_class=self.BUG_CLASS,
                        severity=Severity.HIGH,
                        title=self.TITLE,
                        description=(
                            f"`{contract.name}.{func.name}()` uses `tx.origin` "
                            "for authentication. Post-EIP-7702, a delegated EOA "
                            "can be called via an intermediary contract while "
                            "tx.origin still passes the check."
                        ),
                        contract=contract.name,
                        function=func.name,
                        line=line,
                        source_file=src_file,
                        recommendation=(
                            "Replace `tx.origin` with `msg.sender` for all "
                            "authentication checks. If EOA-only access is required, "
                            "consider an allowlist or off-chain signature verification "
                            "instead of tx.origin."
                        ),
                        poc_ref=self.POC_REF,
                    ))

        return self._deduplicate(findings)

    def _is_informational(self, src: str) -> bool:
        """Heuristic: tx.origin in emit/log/return is informational, not auth."""
        lower = src.lower()
        return any(kw in lower for kw in ("emit ", "log(", "return "))