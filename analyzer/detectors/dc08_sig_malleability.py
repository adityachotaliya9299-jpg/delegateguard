"""
DC-08: Signature malleability in ecrecover-based flows.

Detects raw ecrecover() usage without lower-s enforcement, and signature-bytes-as-key replay protection (which malleability bypasses).
"""
from __future__ import annotations
from typing import List

from ..core.base_detector import BaseDetector
from ..core.finding import Finding, Severity, BugClass


class DC08_SigMalleabilityDetector(BaseDetector):

    BUG_CLASS   = BugClass.DC08_SIG_MALLEABILITY
    TITLE       = "Signature malleability via raw ecrecover (DC-08)"
    DESCRIPTION = (
        "Contract uses raw ecrecover() without enforcing the lower-half s "
        "constraint. Every valid signature has a malleable alternate form "
        "that recovers the same signer but has different bytes. Systems "
        "using keccak256(signature) as a 'used' key are bypassable."
    )
    POC_REF = "lab/test/DC08_SigMalleability.t.sol"

    _SAFE_RECOVER = {"ECDSA.recover", "SignatureChecker", "tryRecover"}
    _HALF_N_HINT  = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            uses_ecrecover    = False
            has_lower_s_check = False
            uses_sig_as_key   = False
            uses_safe_lib     = False

            for func in contract.functions:
                for node in func.nodes:
                    src = str(node.expression) if node.expression else ""

                    if "ecrecover(" in src:
                        uses_ecrecover = True

                    if self._HALF_N_HINT in src or "half" in src.lower():
                        has_lower_s_check = True

                    # Check for safe library usage
                    if any(s in src for s in self._SAFE_RECOVER):
                        uses_safe_lib = True

                    # Check for sig-bytes-as-key pattern
                    if "keccak256(sig" in src.lower() or "keccak256(signature" in src.lower():
                        uses_sig_as_key = True

            if not uses_ecrecover:
                continue
            if uses_safe_lib:
                continue  # using OZ ECDSA — safe
            if has_lower_s_check:
                continue  # manual lower-s enforcement present

            issues = []
            if not has_lower_s_check:
                issues.append("no lower-s enforcement (high-s signatures accepted)")
            if uses_sig_as_key:
                issues.append("keccak256(signature) used as replay key — bypassable via malleable form")

            src_file, line = self._source_info(contract)
            findings.append(Finding(
                bug_class=self.BUG_CLASS,
                severity=Severity.MEDIUM,
                title=self.TITLE,
                description=(
                    f"`{contract.name}` uses raw `ecrecover()` with: "
                    f"{'; '.join(issues)}. "
                    "The malleable form (v', r, n-s) recovers the same signer "
                    "but has different bytes, bypassing signature-bytes-based replay protection."
                ),
                contract=contract.name,
                function=None,
                line=line,
                source_file=src_file,
                recommendation=(
                    "Use OpenZeppelin's `ECDSA.recover()` which enforces lower-s. "
                    "Replace signature-bytes-as-key with a monotonic nonce. "
                    "Validate `v == 27 || v == 28` and "
                    "`s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0`."
                ),
                poc_ref=self.POC_REF,
            ))

        return findings