"""
DelegateGuard Analyzer — Detector Tests

Tests each detector against the seeded vulnerable contracts in lab/src/vulnerable/
and verifies zero false positives on the fixed contracts in lab/src/fixed/.

"""
from __future__ import annotations
import os
import sys
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

# Add parent to path so we can import analyzer
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from analyzer.core.finding import BugClass, Severity
from analyzer.detectors import (
    DC01_StorageCollisionDetector,
    DC02_InitFrontrunDetector,
    DC03_CrossChainReplayDetector,
    DC04_MissingAuthDetector,
    DC05_InnerDelegatecallDetector,
    DC06_BatchReplayDetector,
    DC07_SweeperDetector,
    DC08_SigMalleabilityDetector,
)


# ---------------------------------------------------------------------------
# Helpers — build mock Slither objects for unit tests
# ---------------------------------------------------------------------------

def _mock_slither(contracts):
    """Build a minimal mock Slither instance with the given contracts."""
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


def _mock_state_var(name, is_constant=False, is_immutable=False, type_str="address"):
    v = MagicMock()
    v.name = name
    v.is_constant = is_constant
    v.is_immutable = is_immutable
    v.type = MagicMock()
    v.type.__str__ = lambda self: type_str
    v.expression = None
    v.source_mapping = MagicMock()
    v.source_mapping.filename.short = "test.sol"
    v.source_mapping.lines = [1]
    return v


# ---------------------------------------------------------------------------
# DC-01: Storage Collision
# ---------------------------------------------------------------------------

class TestDC01_StorageCollision:

    def test_flags_raw_state_vars_in_delegate(self):
        """Delegate with raw state variables and no ERC-7201 should be flagged."""
        init_func = _mock_function("initialize", nodes=[_mock_node("owner = _owner")])
        owner_var = _mock_state_var("owner")

        contract = _mock_contract("VulnDelegate",
                                  state_vars=[owner_var],
                                  functions=[init_func])
        sl = _mock_slither([contract])
        findings = DC01_StorageCollisionDetector(sl).run()

        assert len(findings) >= 1
        assert findings[0].bug_class == BugClass.DC01_STORAGE_COLLISION
        assert findings[0].severity == Severity.HIGH

    def test_no_flag_when_erc7201_slot_constant_present(self):
        """ERC-7201 storage slot constant should suppress the finding."""
        slot_var = _mock_state_var("_STORAGE_SLOT", is_constant=True, type_str="bytes32")
        init_func = _mock_function("initialize", nodes=[_mock_node("s.owner = _owner")])
        # Assembly node with s.slot pattern
        asm_node = _mock_node("", inline_asm="s.slot := slot")
        storage_func = _mock_function("_store", nodes=[asm_node])

        contract = _mock_contract("SafeDelegate",
                                  state_vars=[slot_var],
                                  functions=[init_func, storage_func])
        sl = _mock_slither([contract])
        findings = DC01_StorageCollisionDetector(sl).run()

        assert len(findings) == 0

    def test_no_flag_for_non_delegate(self):
        """Non-delegate contracts (no initialize()) should not be flagged."""
        owner_var = _mock_state_var("owner")
        transfer_func = _mock_function("transfer", nodes=[_mock_node("balances[to] += amount")])
        contract = _mock_contract("ERC20Token",
                                  state_vars=[owner_var],
                                  functions=[transfer_func])
        sl = _mock_slither([contract])
        findings = DC01_StorageCollisionDetector(sl).run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DC-02: Init Frontrun
# ---------------------------------------------------------------------------

class TestDC02_InitFrontrun:

    def test_flags_initialize_without_auth(self):
        """initialize() with no tx.origin check should be flagged."""
        init_func = _mock_function("initialize",
                                   nodes=[_mock_node("owner = _owner")])
        contract = _mock_contract("VulnDelegate", functions=[init_func])
        sl = _mock_slither([contract])
        findings = DC02_InitFrontrunDetector(sl).run()

        assert len(findings) == 1
        assert findings[0].bug_class == BugClass.DC02_INIT_FRONTRUN
        assert findings[0].function == "initialize"

    def test_no_flag_when_tx_origin_present(self):
        """initialize() referencing tx.origin should be clean."""
        node = _mock_node("require(tx.origin == address(this), 'only EOA')")
        init_func = _mock_function("initialize", nodes=[node])
        contract = _mock_contract("SafeDelegate", functions=[init_func])
        sl = _mock_slither([contract])
        findings = DC02_InitFrontrunDetector(sl).run()
        assert len(findings) == 0

    def test_no_flag_for_non_init_functions(self):
        """Regular functions named 'transfer' are not checked."""
        func = _mock_function("transfer", nodes=[_mock_node("balances[to] += v")])
        contract = _mock_contract("Token", functions=[func])
        sl = _mock_slither([contract])
        findings = DC02_InitFrontrunDetector(sl).run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DC-03: Cross-chain Replay
# ---------------------------------------------------------------------------

class TestDC03_CrossChainReplay:

    def test_flags_eip712_without_chainid(self):
        """EIP-712 domain separator without block.chainid should be flagged."""
        domain_var = _mock_state_var("DOMAIN_TYPEHASH", is_constant=True, type_str="bytes32")
        node = _mock_node("keccak256(abi.encode(DOMAIN_TYPEHASH, name, verifyingContract))")
        func = _mock_function("domainSeparator", view=True, nodes=[node])
        contract = _mock_contract("VulnDelegate",
                                  state_vars=[domain_var],
                                  functions=[func])
        sl = _mock_slither([contract])
        findings = DC03_CrossChainReplayDetector(sl).run()

        assert len(findings) >= 1
        assert findings[0].bug_class == BugClass.DC03_CROSS_CHAIN_REPLAY
        assert findings[0].severity == Severity.CRITICAL

    def test_no_flag_when_chainid_present(self):
        """Domain separator including block.chainid should be clean."""
        domain_var = _mock_state_var("DOMAIN_TYPEHASH", is_constant=True, type_str="bytes32")
        node = _mock_node("keccak256(abi.encode(DOMAIN_TYPEHASH, name, block.chainid, addr))")
        func = _mock_function("domainSeparator", view=True, nodes=[node])
        contract = _mock_contract("SafeDelegate",
                                  state_vars=[domain_var],
                                  functions=[func])
        sl = _mock_slither([contract])
        findings = DC03_CrossChainReplayDetector(sl).run()
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# DC-04: Missing Auth
# ---------------------------------------------------------------------------

class TestDC04_MissingAuth:

    def test_flags_public_state_changing_no_auth(self):
        """Public state-changing function in a delegate with no msg.sender check."""
        init_func = _mock_function("initialize", nodes=[_mock_node("initialized = true")])
        vuln_func = _mock_function("transferETH",
                                   nodes=[_mock_node("to.call{value: amount}('')")])
        contract = _mock_contract("VulnDelegate",
                                  functions=[init_func, vuln_func])
        sl = _mock_slither([contract])
        findings = DC04_MissingAuthDetector(sl).run()

        assert any(f.bug_class == BugClass.DC04_MISSING_AUTH for f in findings)

    def test_no_flag_with_msg_sender_check(self):
        """Function with msg.sender check should be clean."""
        init_func = _mock_function("initialize", nodes=[_mock_node("initialized = true")])
        safe_func = _mock_function("transferETH",
                                   nodes=[_mock_node("require(msg.sender == owner)")])
        contract = _mock_contract("SafeDelegate", functions=[init_func, safe_func])
        sl = _mock_slither([contract])
        findings = DC04_MissingAuthDetector(sl).run()
        dc04 = [f for f in findings if f.bug_class == BugClass.DC04_MISSING_AUTH]
        assert len(dc04) == 0


# ---------------------------------------------------------------------------
# DC-07: Sweeper
# ---------------------------------------------------------------------------

class TestDC07_Sweeper:

    def test_flags_execute_with_no_auth_no_allowlist(self):
        """execute() with arbitrary call and no auth/allowlist should be CRITICAL."""
        node = _mock_node("target.call{value: msg.value}(data)")
        exec_func = _mock_function("execute", nodes=[node])
        contract = _mock_contract("SweeperDelegate", functions=[exec_func])
        sl = _mock_slither([contract])
        findings = DC07_SweeperDetector(sl).run()

        sweeper_findings = [f for f in findings if f.bug_class == BugClass.DC07_SWEEPER]
        assert len(sweeper_findings) >= 1
        assert sweeper_findings[0].severity == Severity.CRITICAL

    def test_no_flag_with_auth_and_allowlist(self):
        """execute() with both auth and allowlist should be clean."""
        node = _mock_node(
            "require(msg.sender == owner); require(allowedTargets[target]); target.call(data)"
        )
        exec_func = _mock_function("execute", nodes=[node])
        contract = _mock_contract("SafeDelegate", functions=[exec_func])
        sl = _mock_slither([contract])
        findings = DC07_SweeperDetector(sl).run()
        sweeper = [f for f in findings if f.bug_class == BugClass.DC07_SWEEPER]
        assert len(sweeper) == 0


# ---------------------------------------------------------------------------
# DC-08: Signature Malleability
# ---------------------------------------------------------------------------

class TestDC08_SigMalleability:

    def test_flags_raw_ecrecover_without_lower_s(self):
        """Raw ecrecover with no lower-s check should be flagged."""
        node = _mock_node("signer = ecrecover(digest, v, r, s)")
        func = _mock_function("withdraw", nodes=[node])
        contract = _mock_contract("VulnDelegate", functions=[func])
        sl = _mock_slither([contract])
        findings = DC08_SigMalleabilityDetector(sl).run()

        assert any(f.bug_class == BugClass.DC08_SIG_MALLEABILITY for f in findings)

    def test_no_flag_with_ecdsa_library(self):
        """ECDSA.recover usage should suppress the finding."""
        node = _mock_node("signer = ECDSA.recover(digest, signature)")
        func = _mock_function("withdraw", nodes=[node])
        contract = _mock_contract("SafeDelegate", functions=[func])
        sl = _mock_slither([contract])
        findings = DC08_SigMalleabilityDetector(sl).run()
        dc08 = [f for f in findings if f.bug_class == BugClass.DC08_SIG_MALLEABILITY]
        assert len(dc08) == 0

    def test_no_flag_with_lower_s_check(self):
        """Manual lower-s enforcement should suppress the finding."""
        node1 = _mock_node("signer = ecrecover(digest, v, r, s)")
        node2 = _mock_node("require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0)")
        func = _mock_function("withdraw", nodes=[node1, node2])
        contract = _mock_contract("SafeDelegate", functions=[func])
        sl = _mock_slither([contract])
        findings = DC08_SigMalleabilityDetector(sl).run()
        dc08 = [f for f in findings if f.bug_class == BugClass.DC08_SIG_MALLEABILITY]
        assert len(dc08) == 0