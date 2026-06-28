"""
PA-05: Airdrop / access gates equating EOA = unique human.

Detects patterns where EOA-hood is used as Sybil resistance:
  - msg.sender == tx.origin combined with a one-per-address mapping
  - extcodesize == 0 combined with a one-per-address mapping
  - "claimed", "hasClaimed", "registered" mappings gated only by EOA checks

Post-7702: an operator can programmatically generate N EOAs, delegate them
all, and claim N times. The EOA check is insufficient for Sybil resistance.
"""
from __future__ import annotations
from typing import List

from ..core.base_detector import BaseScannerDetector
from ..core.finding import Finding, Severity, BugClass


class PA05_EOAUniquenessDetector(BaseScannerDetector):

    BUG_CLASS   = BugClass.PA05_EOA_UNIQUENESS
    TITLE       = "EOA = unique human assumption broken by EIP-7702 (PA-05)"
    DESCRIPTION = (
        "Contract uses EOA status (tx.origin == msg.sender or extcodesize == 0) "
        "as Sybil resistance for an airdrop, vote, or one-per-address gate. "
        "Post-EIP-7702, EOA farms trivially bypass this."
    )
    POC_REF = "lab/test/PA05_EOAUniqueness.t.sol"

    # Mapping names that suggest one-per-address gating
    _CLAIM_HINTS = {
        "claimed", "hasclaimed", "registered", "participated",
        "minted", "allocated", "voted", "airdropped",
    }

    # EOA detection patterns (from PA-01, PA-02, PA-03 — when combined with claims)
    _EOA_GATE_PATTERNS = [
        "msg.sender == tx.origin",
        "tx.origin == msg.sender",
        "extcodesize",
        "_isEOA",
    ]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            # Check if contract has a one-per-address mapping (claim/vote pattern)
            has_claim_mapping = self._has_claim_mapping(contract)
            if not has_claim_mapping:
                continue

            for func in contract.functions:
                has_eoa_gate  = self._has_eoa_gate(func)
                has_allowlist = self._has_allowlist_check(func)

                if not has_eoa_gate:
                    continue
                if has_allowlist:
                    continue  # properly protected with Merkle/allowlist

                src_file, line = self._source_info(func)
                findings.append(Finding(
                    bug_class=self.BUG_CLASS,
                    severity=Severity.MEDIUM,
                    title=self.TITLE,
                    description=(
                        f"`{contract.name}.{func.name}()` gates a one-per-address "
                        "action (airdrop/vote/registration) using an EOA check. "
                        "Post-EIP-7702, an attacker can generate a farm of EOAs, "
                        "delegate them all, and claim the action N times."
                    ),
                    contract=contract.name,
                    function=func.name,
                    line=line,
                    source_file=src_file,
                    recommendation=(
                        "Replace EOA-based Sybil resistance with: "
                        "1. Merkle-proof allowlist (pre-computed off-chain with filtering). "
                        "2. ZK proof of personhood (e.g., World ID, Gitcoin Passport). "
                        "3. On-chain activity thresholds (minimum tx count, age, etc.). "
                        "Do not rely on EOA status alone as a uniqueness primitive."
                    ),
                    poc_ref=self.POC_REF,
                ))

        return self._deduplicate(findings)

    def _has_claim_mapping(self, contract) -> bool:
        for var in contract.state_variables:
            if any(hint in var.name.lower() for hint in self._CLAIM_HINTS):
                return True
        return False

    def _has_eoa_gate(self, func) -> bool:
        for node in func.nodes:
            src = str(node.expression) if node.expression else ""
            src_stripped = src.replace(" ", "")
            if any(p.replace(" ", "") in src_stripped for p in self._EOA_GATE_PATTERNS):
                return True
        return False

    def _has_allowlist_check(self, func) -> bool:
        for node in func.nodes:
            src = str(node.expression) if node.expression else ""
            if any(kw in src.lower() for kw in
                   ("merkle", "proof", "allowlist", "whitelist", "passport", "worldid")):
                return True
        return False