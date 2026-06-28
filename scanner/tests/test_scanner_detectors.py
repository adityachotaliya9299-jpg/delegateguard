"""
DelegateGuard Scanner — Detector Tests 

Run: pytest scanner/tests/ -v
"""
from __future__ import annotations
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from analyzer.core.finding import BugClass, Severity
from scanner.detectors import (
    PA01_TxOriginDetector,
    PA02_SenderOriginGateDetector,
    PA03_ExtcodesizeDetector,
    PA04_EOAReentrancyDetector,
    PA05_EOAUniquenessDetector,
)


# ---------------------------------------------------------------------------
# Mock helpers (same pattern as analyzer tests)
# ---------------------------------------------------------------------------

def _mock_slither(contracts):
    sl = MagicMock()
    sl.contracts = contracts
    return sl

def _mock_contract(name, state_vars=None, functions=None):
    c = MagicMock()
    c.name = name
    c.state_variables = state_vars or []
    c.functions = functions or []
    return c

def _mock_function(name, visibility="external", view=False, pure=False,
                   nodes=None, modifiers=None, parameters=None):
    f = MagicMock()
    f.name = name
    f.visibility = visibility
    f.view = view
    f.pure = pure
    f.nodes = nodes or []
    f.modifiers = modifiers or []
    f.parameters = parameters or []
    return f

def _mock_node(expr_str="", irs=None, inline_asm=None):
    n = MagicMock()
    n.expression = MagicMock()
    n.expression.__str__ = lambda self: expr_str
    n.irs = irs or []
    n.inline_asm = inline_asm
    n.source_mapping = MagicMock()
    n.source_mapping.filename.short = "test.sol"
    n.source_mapping.lines = [1]
    return n

def _mock_state_var(name):
    v = MagicMock()
    v.name = name
    v.is_constant = False
    v.is_immutable = False
    return v


# ---------------------------------------------------------------------------
# PA-01: tx.origin authentication
# ---------------------------------------------------------------------------

class TestPA01_TxOrigin:

    def test_flags_tx_origin_in_require(self):
        node = _mock_node("require(tx.origin == owner, 'not owner')")
        func = _mock_contract_func("withdrawAll", node)
        contract = _mock_contract("Protocol", functions=[func])
        sl = _mock_slither([contract])
        findings = PA01_TxOriginDetector(sl).run()

        assert len(findings) >= 1
        assert findings[0].bug_class == BugClass.PA01_TX_ORIGIN
        assert findings[0].severity == Severity.HIGH

    def test_no_flag_when_informational(self):
        """tx.origin in emit statement is not an auth check."""
        node = _mock_node("emit Transfer(tx.origin, to, amount)")
        func = _mock_contract_func("transfer", node)
        contract = _mock_contract("Token", functions=[func])
        sl = _mock_slither([contract])
        findings = PA01_TxOriginDetector(sl).run()
        assert len(findings) == 0

    def test_no_flag_without_tx_origin(self):
        node = _mock_node("require(msg.sender == owner)")
        func = _mock_contract_func("withdraw", node)
        contract = _mock_contract("Protocol", functions=[func])
        sl = _mock_slither([contract])
        findings = PA01_TxOriginDetector(sl).run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PA-02: msg.sender == tx.origin gate
# ---------------------------------------------------------------------------

class TestPA02_SenderOriginGate:

    def test_flags_sender_equals_origin(self):
        node = _mock_node("require(msg.sender == tx.origin, 'only EOAs')")
        func = _mock_contract_func("claimAirdrop", node)
        contract = _mock_contract("Airdrop", functions=[func])
        sl = _mock_slither([contract])
        findings = PA02_SenderOriginGateDetector(sl).run()

        assert len(findings) >= 1
        assert findings[0].bug_class == BugClass.PA02_SENDER_ORIGIN_GATE

    def test_flags_reversed_order(self):
        """tx.origin == msg.sender (reversed) should also be caught."""
        node = _mock_node("require(tx.origin == msg.sender)")
        func = _mock_contract_func("register", node)
        contract = _mock_contract("Governance", functions=[func])
        sl = _mock_slither([contract])
        findings = PA02_SenderOriginGateDetector(sl).run()
        assert len(findings) >= 1

    def test_no_flag_without_pattern(self):
        node = _mock_node("require(msg.sender == owner)")
        func = _mock_contract_func("withdraw", node)
        contract = _mock_contract("Protocol", functions=[func])
        sl = _mock_slither([contract])
        findings = PA02_SenderOriginGateDetector(sl).run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PA-03: extcodesize EOA check
# ---------------------------------------------------------------------------

class TestPA03_Extcodesize:

    def test_flags_extcodesize_in_source(self):
        node = _mock_node("require(_isEOA(msg.sender), 'only EOAs')")
        func = _mock_contract_func("deposit", node)
        contract = _mock_contract("Pool", functions=[func])
        sl = _mock_slither([contract])
        findings = PA03_ExtcodesizeDetector(sl).run()

        assert len(findings) >= 1
        assert findings[0].bug_class == BugClass.PA03_EXTCODESIZE

    def test_flags_extcodesize_in_assembly(self):
        node = _mock_node("", inline_asm="size := extcodesize(addr)")
        func = _mock_contract_func("_isEOA", node)
        contract = _mock_contract("Guard", functions=[func])
        sl = _mock_slither([contract])
        findings = PA03_ExtcodesizeDetector(sl).run()
        assert any(f.bug_class == BugClass.PA03_EXTCODESIZE for f in findings)

    def test_no_flag_without_extcodesize(self):
        node = _mock_node("require(!_locked, 'reentrant')")
        func = _mock_contract_func("withdraw", node)
        contract = _mock_contract("Pool", functions=[func])
        sl = _mock_slither([contract])
        findings = PA03_ExtcodesizeDetector(sl).run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# PA-04: EOA-only reentrancy
# ---------------------------------------------------------------------------

class TestPA04_EOAReentrancy:

    def test_flags_missing_guard_with_external_call_and_late_state_update(self):
        """External call before state write with no reentrancy guard."""
        from slither.slithir.operations import LowLevelCall, Assignment
        call_ir = MagicMock(spec=LowLevelCall)
        call_ir.function_name = "call"

        call_node  = _mock_node("msg.sender.call{value: amount}('')", irs=[call_ir])
        write_node = _mock_node("balances[msg.sender] = 0")

        from slither.slithir.operations import Assignment as Assign
        assign_ir = MagicMock(spec=Assign)
        write_node.irs = [assign_ir]

        func = _mock_contract_func("withdraw", call_node, write_node)
        contract = _mock_contract("VulnPool", functions=[func])
        sl = _mock_slither([contract])
        findings = PA04_EOAReentrancyDetector(sl).run()

        assert any(f.bug_class == BugClass.PA04_EOA_REENTRANCY for f in findings)

    def test_no_flag_with_nonreentrant_modifier(self):
        """nonReentrant modifier should suppress finding."""
        call_node  = _mock_node("msg.sender.call{value: amount}('')")
        write_node = _mock_node("balances[msg.sender] = 0")
        func = _mock_contract_func("withdraw", call_node, write_node)

        mod = MagicMock()
        mod.__str__ = lambda self: "nonReentrant"
        func.modifiers = [mod]

        contract = _mock_contract("SafePool", functions=[func])
        sl = _mock_slither([contract])
        findings = PA04_EOAReentrancyDetector(sl).run()
        pa04 = [f for f in findings if f.bug_class == BugClass.PA04_EOA_REENTRANCY]
        assert len(pa04) == 0


# ---------------------------------------------------------------------------
# PA-05: EOA uniqueness assumption
# ---------------------------------------------------------------------------

class TestPA05_EOAUniqueness:

    def test_flags_eoa_gated_claim_mapping(self):
        """Contract with 'claimed' mapping + tx.origin gate should be flagged."""
        claimed_var = _mock_state_var("claimed")
        node = _mock_node("require(msg.sender == tx.origin, 'only EOAs'); require(!claimed[msg.sender])")
        func = _mock_contract_func("claimAirdrop", node)
        contract = _mock_contract("Airdrop",
                                  state_vars=[claimed_var],
                                  functions=[func])
        sl = _mock_slither([contract])
        findings = PA05_EOAUniquenessDetector(sl).run()

        assert any(f.bug_class == BugClass.PA05_EOA_UNIQUENESS for f in findings)

    def test_no_flag_with_merkle_proof(self):
        """Merkle proof suppresses the PA-05 finding."""
        claimed_var = _mock_state_var("claimed")
        node = _mock_node(
            "require(msg.sender == tx.origin); "
            "require(MerkleProof.verify(proof, merkleRoot, leaf))"
        )
        func = _mock_contract_func("claimAirdrop", node)
        contract = _mock_contract("SafeAirdrop",
                                  state_vars=[claimed_var],
                                  functions=[func])
        sl = _mock_slither([contract])
        findings = PA05_EOAUniquenessDetector(sl).run()
        pa05 = [f for f in findings if f.bug_class == BugClass.PA05_EOA_UNIQUENESS]
        assert len(pa05) == 0

    def test_no_flag_without_claim_mapping(self):
        """Contract without a claim-like mapping should not trigger PA-05."""
        node = _mock_node("require(msg.sender == tx.origin)")
        func = _mock_contract_func("doSomething", node)
        contract = _mock_contract("Random", functions=[func])
        sl = _mock_slither([contract])
        findings = PA05_EOAUniquenessDetector(sl).run()
        pa05 = [f for f in findings if f.bug_class == BugClass.PA05_EOA_UNIQUENESS]
        assert len(pa05) == 0


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _mock_contract_func(name, *nodes):
    f = MagicMock()
    f.name = name
    f.visibility = "external"
    f.view = False
    f.pure = False
    f.nodes = list(nodes)
    f.modifiers = []
    f.parameters = []
    return f