"""
PA-03: extcodesize(addr) == 0 used to detect EOAs.

Pre-7702: extcodesize == 0 reliably meant "this address has no code = EOA".
Post-7702: a delegated EOA has code (the 23-byte delegation designator
`0xef0100 || delegate_address`), so extcodesize returns 23.

This breaks:
  1. Access controls that only allow EOAs (now blocks 7702 wallet users)
  2. Reentrancy guards that skip the lock for "EOAs" (now bypassable)
  3. Any logic that assumed extcodesize==0 means "safe/simple caller"
"""
from __future__ import annotations
from typing import List

from ..core.base_detector import BaseScannerDetector
from ..core.finding import Finding, Severity, BugClass


class PA03_ExtcodesizeDetector(BaseScannerDetector):

    BUG_CLASS   = BugClass.PA03_EXTCODESIZE
    TITLE       = "extcodesize == 0 EOA check broken by EIP-7702 (PA-03)"
    DESCRIPTION = (
        "`extcodesize(addr) == 0` is used to detect EOAs. "
        "Post-EIP-7702, delegated EOAs have a 23-byte delegation designator "
        "in their code slot, so this check incorrectly classifies them as contracts."
    )
    POC_REF = "lab/test/PA03_ExtcodeSize.t.sol"

    _PATTERNS = [
        "extcodesize",
        "EXTCODESIZE",
        "isContract",      # common OZ helper that wraps extcodesize
        "_isEOA",
    ]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            for func in contract.functions:
                for node in func.nodes:
                    src = str(node.expression) if node.expression else ""

                    # Check inline assembly too
                    asm = str(node.inline_asm) if node.inline_asm else ""
                    combined = src + asm

                    if not any(p in combined for p in self._PATTERNS):
                        continue

                    # Determine if it's access-control or reentrancy context
                    is_reentrancy = self._is_reentrancy_context(func)
                    severity = Severity.HIGH

                    src_file, line = self._source_info(node)
                    findings.append(Finding(
                        bug_class=self.BUG_CLASS,
                        severity=severity,
                        title=self.TITLE,
                        description=(
                            f"`{contract.name}.{func.name}()` uses `extcodesize` "
                            "to identify EOAs. Post-EIP-7702, delegated EOAs have "
                            "a 23-byte code slot and fail this check. "
                            + ("This appears to be a reentrancy guard — delegated EOAs "
                               "can now reenter functions that skip the guard for 'EOAs'."
                               if is_reentrancy else
                               "Access controls using this check will incorrectly block "
                               "or admit EIP-7702 wallet users.")
                        ),
                        contract=contract.name,
                        function=func.name,
                        line=line,
                        source_file=src_file,
                        recommendation=(
                            "Remove extcodesize-based EOA detection. "
                            "For reentrancy: use a universal nonReentrant modifier "
                            "with no EOA carve-out. "
                            "For access control: use explicit allowlists or signatures. "
                            "For Sybil resistance: use Merkle proofs or off-chain attestation."
                        ),
                        poc_ref=self.POC_REF,
                    ))

        return self._deduplicate(findings)

    def _is_reentrancy_context(self, func) -> bool:
        """Heuristic: function does an external call, suggesting reentrancy relevance."""
        for node in func.nodes:
            src = str(node.expression) if node.expression else ""
            if ".call{" in src or ".call(" in src or "transfer(" in src:
                return True
        return False