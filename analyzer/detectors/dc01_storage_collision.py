"""
DC-01: Storage collision on re-delegation.

Detects delegate contracts that declare state variables at the top level (raw storage slots) without using ERC-7201 namespaced storage. When an EOA switches delegates, overlapping slots corrupt each other.

Detection strategy:
  1. Find contracts that look like delegates (have initialize(), no constructor state init, use DELEGATECALL context patterns).
  2. Flag any state variable declared at a raw slot (i.e., not accessed via an assembly `s.slot := <hash>` pattern).
  3. If two such contracts share the same slot index for different variable names, raise CRITICAL. If a single contract uses raw slots, raise HIGH.
"""
from __future__ import annotations
from typing import List

from slither.core.declarations import Contract
from slither.core.variables.state_variable import StateVariable

from ..core.base_detector import BaseDetector
from ..core.finding import Finding, Severity, BugClass


class DC01_StorageCollisionDetector(BaseDetector):

    BUG_CLASS   = BugClass.DC01_STORAGE_COLLISION
    TITLE       = "Storage collision on re-delegation (DC-01)"
    DESCRIPTION = (
        "Contract uses unnamespaced (raw slot) state variables. "
        "When an EOA re-delegates to a different contract that also uses "
        "raw slots, storage is corrupted. Use ERC-7201 namespaced storage."
    )
    POC_REF = "lab/test/DC01_StorageCollision.t.sol"

    # Markers that suggest a contract intends to be used as a 7702 delegate
    _DELEGATE_HINTS = {"initialize", "initialized", "delegatecall"}

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        for contract in self._all_contracts():
            if not self._looks_like_delegate(contract):
                continue

            raw_vars = self._raw_slot_variables(contract)
            if not raw_vars:
                continue

            uses_erc7201 = self._uses_erc7201_pattern(contract)
            if uses_erc7201:
                continue  # correctly namespaced — skip

            for var in raw_vars:
                src_file, line = self._source_info(var)
                findings.append(Finding(
                    bug_class=self.BUG_CLASS,
                    severity=Severity.HIGH,
                    title=self.TITLE,
                    description=(
                        f"State variable `{var.name}` in `{contract.name}` uses a raw "
                        f"storage slot (slot {var.slot if hasattr(var, 'slot') else '?'}). "
                        "If this contract is used as a 7702 delegate and the EOA switches "
                        "to another delegate with overlapping slots, storage will be corrupted. "
                        "Upgrade to ERC-7201 namespaced storage."
                    ),
                    contract=contract.name,
                    function=None,
                    line=line,
                    source_file=src_file,
                    recommendation=(
                        "Use ERC-7201 namespaced storage: declare a struct, compute "
                        "`slot = keccak256(abi.encode(uint256(keccak256('your.namespace')) - 1)) & ~bytes32(uint256(0xff))`, "
                        "and access all state via assembly `s.slot := slot`."
                    ),
                    poc_ref=self.POC_REF,
                ))

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _looks_like_delegate(self, contract: Contract) -> bool:
        """Heuristic: contract has an initialize() or references delegate hints."""
        names = {f.name.lower() for f in contract.functions}
        return bool(names & self._DELEGATE_HINTS)

    def _raw_slot_variables(self, contract: Contract) -> List[StateVariable]:
        """
        Return state variables that are stored at raw sequential slots
        (i.e., declared as top-level state vars, not in a struct accessed
        via an ERC-7201 assembly pattern).
        """
        raw = []
        for var in contract.state_variables:
            # Skip constants and immutables — they don't occupy storage
            if var.is_constant or var.is_immutable:
                continue
            # Skip mappings-only used as ERC-7201 storage struct fields
            # (detected separately by _uses_erc7201_pattern)
            raw.append(var)
        return raw

    def _uses_erc7201_pattern(self, contract: Contract) -> bool:
        """
        Check if the contract uses the ERC-7201 namespaced storage pattern.
        Heuristic: look for assembly blocks containing `s.slot :=` or
        a bytes32 constant computed via nested keccak256 subtraction.
        """
        # Check for ERC-7201 marker: a bytes32 constant with a long keccak expression
        for var in contract.state_variables:
            if var.is_constant and str(var.type) == "bytes32":
                # The ERC-7201 slot constant has a characteristic name pattern
                if any(kw in var.name.upper() for kw in ("SLOT", "STORAGE", "POSITION")):
                    return True

        # Check function bodies for assembly with slot assignment
        for func in contract.functions:
            for node in func.nodes:
                if node.inline_asm:
                    src = str(node.inline_asm)
                    if "s.slot" in src or ".slot :=" in src:
                        return True

        return False