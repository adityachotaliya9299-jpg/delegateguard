"""
DC-03: Cross-chain replay via chain_id = 0.

Detects EIP-712 domain separators that do not include block.chainid, and signature verification functions that are missing chain binding.
"""
from __future__ import annotations
from typing import List

from ..core.base_detector import BaseDetector
from ..core.finding import Finding, Severity, BugClass


class DC03_CrossChainReplayDetector(BaseDetector):

    BUG_CLASS   = BugClass.DC03_CROSS_CHAIN_REPLAY
    TITLE       = "Missing chain_id in domain separator — cross-chain replay (DC-03)"
    DESCRIPTION = (
        "The contract builds an EIP-712 domain separator without including "
        "block.chainid. Signatures produced on one chain can be replayed on "
        "any other EVM chain where the victim has funds."
    )
    POC_REF = "lab/test/DC03_CrossChainReplay.t.sol"

    # Keywords indicating EIP-712 usage
    _EIP712_MARKERS = {"domainSeparator", "DOMAIN_TYPEHASH", "EIP712Domain", "\x19\x01"}
    _CHAINID_MARKERS = {"chainid", "block.chainid", "chainId", "chain_id"}

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            if not self._uses_eip712(contract):
                continue

            if self._has_chainid_binding(contract):
                continue

            src_file, line = self._source_info(contract)
            findings.append(Finding(
                bug_class=self.BUG_CLASS,
                severity=Severity.CRITICAL,
                title=self.TITLE,
                description=(
                    f"`{contract.name}` uses EIP-712 signatures but the domain "
                    "separator does not include `block.chainid`. A signature produced "
                    "on Ethereum mainnet can be replayed on Arbitrum, Base, Optimism, "
                    "and any other EVM chain where the victim has delegated."
                ),
                contract=contract.name,
                function=None,
                line=line,
                source_file=src_file,
                recommendation=(
                    "Include `block.chainid` in the EIP-712 domain separator: "
                    "`keccak256(abi.encode(DOMAIN_TYPEHASH, name, version, block.chainid, address(this)))`. "
                    "Cache the separator and invalidate it if `block.chainid` changes (fork detection)."
                ),
                poc_ref=self.POC_REF,
            ))

        return findings

    def _uses_eip712(self, contract) -> bool:
        for var in contract.state_variables:
            if any(m in var.name for m in ("DOMAIN", "TYPEHASH", "EIP712")):
                return True
        for func in contract.functions:
            for node in func.nodes:
                src = str(node.expression) if node.expression else ""
                if any(m in src for m in self._EIP712_MARKERS):
                    return True
        return False

    def _has_chainid_binding(self, contract) -> bool:
        for func in contract.functions:
            for node in func.nodes:
                src = str(node.expression) if node.expression else ""
                if any(m in src for m in self._CHAINID_MARKERS):
                    return True
        # Also check state variable initializers
        for var in contract.state_variables:
            if any(m in str(var.expression) for m in self._CHAINID_MARKERS
                   if var.expression):
                return True
        return False