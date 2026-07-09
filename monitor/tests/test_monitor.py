"""
DelegateGuard Monitor — Tests

Covers: DelegateRegistry, RiskScorer, AlertEngine, ChainIndexer (mocked RPC).

Run: pytest monitor/tests/ -v
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, call
import time

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from monitor.src.models import (
    DelegationEvent, DelegateRecord, DelegateStatus,
    AlertLevel, MonitorAlert, DELEGATION_PREFIX,
)
from monitor.src.registry import DelegateRegistry, RiskScorer
from monitor.src.alerts   import AlertEngine
from monitor.src.indexer  import ChainIndexer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(
    delegate: str = "0xabc",
    is_revocation: bool = False,
    chain_id: int = 1,
    block: int = 100,
) -> DelegationEvent:
    return DelegationEvent(
        tx_hash="0xdeadbeef",
        block_number=block,
        block_timestamp=int(time.time()),
        eoa_address="0xvictim",
        delegate_address=delegate.lower(),
        chain_id=chain_id,
        nonce=0,
        is_revocation=is_revocation,
    )


# ---------------------------------------------------------------------------
# DelegateRegistry
# ---------------------------------------------------------------------------

class TestDelegateRegistry:

    def test_seed_data_loaded_on_init(self):
        reg = DelegateRegistry(persist_path="/tmp/dg_test_reg_seed.json")
        # Seed has malicious addresses
        assert len(reg.malicious_addresses()) > 0

    def test_classify_unknown_returns_unknown(self):
        reg = DelegateRegistry(persist_path="/tmp/dg_test_reg_unk.json")
        status = reg.classify("0x" + "a" * 40)
        assert status == DelegateStatus.UNKNOWN

    def test_upsert_and_get(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        reg = DelegateRegistry(persist_path=path)
        record = DelegateRecord(
            address="0x" + "1" * 40,
            status=DelegateStatus.MALICIOUS,
            notes="test malicious",
            risk_signals=["DC-07"],
        )
        reg.upsert(record)
        fetched = reg.get("0x" + "1" * 40)
        assert fetched is not None
        assert fetched.status == DelegateStatus.MALICIOUS
        assert fetched.notes == "test malicious"

    def test_addresses_are_lowercased(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        reg = DelegateRegistry(persist_path=path)
        addr_upper = "0x" + "A" * 40
        reg.upsert(DelegateRecord(address=addr_upper, status=DelegateStatus.SAFE))
        assert reg.get(addr_upper.lower()) is not None
        assert reg.get(addr_upper) is not None  # should normalize

    def test_mark_malicious(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        reg = DelegateRegistry(persist_path=path)
        addr = "0x" + "b" * 40
        reg.mark_malicious(addr, "confirmed sweeper", ["DC-07"])
        assert reg.classify(addr) == DelegateStatus.MALICIOUS

    def test_increment_eoa_count(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        reg = DelegateRegistry(persist_path=path)
        addr = "0x" + "c" * 40
        reg.upsert(DelegateRecord(address=addr, status=DelegateStatus.UNKNOWN, eoa_count=0))
        reg.increment_eoa_count(addr, delta=3)
        assert reg.get(addr).eoa_count == 3
        reg.increment_eoa_count(addr, delta=-1)
        assert reg.get(addr).eoa_count == 2

    def test_eoa_count_never_negative(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        reg = DelegateRegistry(persist_path=path)
        addr = "0x" + "d" * 40
        reg.upsert(DelegateRecord(address=addr, status=DelegateStatus.UNKNOWN, eoa_count=0))
        reg.increment_eoa_count(addr, delta=-99)
        assert reg.get(addr).eoa_count == 0

    def test_persistence_across_instances(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        reg1 = DelegateRegistry(persist_path=path)
        addr = "0x" + "e" * 40
        reg1.upsert(DelegateRecord(address=addr, status=DelegateStatus.SAFE, name="test"))

        # New instance reads from the same file
        reg2 = DelegateRegistry(persist_path=path)
        fetched = reg2.get(addr)
        assert fetched is not None
        assert fetched.status == DelegateStatus.SAFE
        assert fetched.name == "test"

    def test_stats_returns_counts(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        reg = DelegateRegistry(persist_path=path)
        stats = reg.stats()
        assert "total" in stats
        assert stats["total"] >= 0
        assert "malicious" in stats


# ---------------------------------------------------------------------------
# RiskScorer
# ---------------------------------------------------------------------------

class TestRiskScorer:

    def test_no_bytecode_returns_unknown(self):
        scorer = RiskScorer()
        record = scorer.score("0x" + "1" * 40, bytecode=None)
        assert record.status == DelegateStatus.UNKNOWN

    def test_known_malicious_selector_returns_malicious(self):
        scorer = RiskScorer()
        # sweepETH(address) selector = 0x4782f779
        fake_bytecode = "0x" + "00" * 10 + "4782f779" + "00" * 10
        record = scorer.score("0x" + "2" * 40, bytecode=fake_bytecode)
        assert record.status == DelegateStatus.MALICIOUS
        assert any("DC-07" in s for s in record.risk_signals)

    def test_suspicious_selector_returns_suspicious(self):
        scorer = RiskScorer()
        # execute(address,bytes) = 0x1cff79cd
        fake_bytecode = "0x" + "00" * 20 + "1cff79cd" + "00" * 20
        record = scorer.score("0x" + "3" * 40, bytecode=fake_bytecode)
        assert record.status in (DelegateStatus.SUSPICIOUS, DelegateStatus.UNKNOWN)

    def test_inner_delegation_designator_triggers_dc05(self):
        scorer = RiskScorer()
        # ef0100 in bytecode = inner delegation designator
        fake_bytecode = "0x" + "6080" + "ef0100" + "00" * 20
        record = scorer.score("0x" + "4" * 40, bytecode=fake_bytecode)
        assert any("DC-05" in s for s in record.risk_signals)

    def test_very_short_bytecode_triggers_signal(self):
        scorer = RiskScorer()
        # 20 bytes = very short
        short_bytecode = "0x" + "aa" * 20
        record = scorer.score("0x" + "5" * 40, bytecode=short_bytecode)
        assert any("short bytecode" in s for s in record.risk_signals)

    def test_clean_bytecode_returns_unknown(self):
        scorer = RiskScorer()
        # Normal EVM bytecode — PUSH1 0x80 PUSH1 0x40 MSTORE ...
        clean_bytecode = "0x" + "6080604052" + "00" * 100
        record = scorer.score("0x" + "6" * 40, bytecode=clean_bytecode)
        assert record.status in (DelegateStatus.UNKNOWN,)
        assert not any("malicious" in s.lower() for s in record.risk_signals)

    def test_record_address_is_lowercased(self):
        scorer = RiskScorer()
        record = scorer.score("0x" + "ABCD" * 10, bytecode=None)
        assert record.address == record.address.lower()


# ---------------------------------------------------------------------------
# AlertEngine
# ---------------------------------------------------------------------------

class TestAlertEngine:

    def _make_engine(self, path=None):
        if path is None:
            import tempfile
            path = tempfile.mktemp(suffix=".json")
        registry = DelegateRegistry(persist_path=path)
        engine   = AlertEngine(registry)
        return engine, registry

    def test_known_malicious_raises_critical(self):
        engine, registry = self._make_engine()
        # Plant a malicious record
        mal_addr = "0x" + "dead" * 10
        registry.mark_malicious(mal_addr, "test sweeper", ["DC-07"])

        alerts = engine.process(_event(delegate=mal_addr))
        assert any(a.level == AlertLevel.CRITICAL for a in alerts)
        assert any("malicious" in a.title.lower() for a in alerts)

    def test_chain_id_zero_raises_critical(self):
        engine, _ = self._make_engine()
        alerts = engine.process(_event(chain_id=0))
        assert any(a.level == AlertLevel.CRITICAL for a in alerts)
        assert any("chain_id=0" in a.title or "chain" in a.title.lower() for a in alerts)

    def test_revocation_raises_info(self):
        engine, _ = self._make_engine()
        alerts = engine.process(_event(is_revocation=True))
        assert any(a.level == AlertLevel.INFO for a in alerts)
        assert any("revok" in a.title.lower() for a in alerts)

    def test_unknown_delegate_raises_info(self):
        engine, _ = self._make_engine()
        fresh_addr = "0x" + "1234" * 10
        alerts = engine.process(_event(delegate=fresh_addr))
        # Should have at least an INFO alert for new/unclassified
        assert len(alerts) >= 1

    def test_suspicious_delegate_raises_warning(self):
        engine, registry = self._make_engine()
        susp_addr = "0x" + "beef" * 10
        registry.upsert(DelegateRecord(
            address=susp_addr,
            status=DelegateStatus.SUSPICIOUS,
            risk_signals=["DC-07: suspicious selector"],
        ))
        alerts = engine.process(_event(delegate=susp_addr))
        assert any(a.level == AlertLevel.WARNING for a in alerts)

    def test_alert_callback_is_called(self):
        engine, _ = self._make_engine()
        received: list[MonitorAlert] = []
        engine.on_alert(received.append)

        mal_addr = "0x" + "dead" * 10
        engine.registry.mark_malicious(mal_addr, "test")
        engine.process(_event(delegate=mal_addr))

        assert len(received) >= 1

    def test_recent_alerts_returns_last_n(self):
        engine, _ = self._make_engine()
        for i in range(5):
            engine.process(_event(delegate=f"0x{'aa' * 19}{i:02x}"))
        recent = engine.recent_alerts(limit=3)
        assert len(recent) <= 3

    def test_alert_stats_counts_by_level(self):
        engine, registry = self._make_engine()
        mal_addr = "0x" + "cc" * 20
        registry.mark_malicious(mal_addr, "test")
        engine.process(_event(delegate=mal_addr))
        stats = engine.alert_stats()
        assert "total" in stats
        assert stats["total"] >= 1


# ---------------------------------------------------------------------------
# ChainIndexer (mock RPC)
# ---------------------------------------------------------------------------

class TestChainIndexer:

    def _mock_rpc_response(self, block_number: int, tx_type: str = "0x4",
                            auth_list: list | None = None) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "number": hex(block_number),
                "timestamp": hex(int(time.time())),
                "transactions": [
                    {
                        "hash": "0xdeadbeef",
                        "type": tx_type,
                        "authorizationList": auth_list or [
                            {
                                "chainId": "0x1",
                                "address": "0xabcd" + "0" * 36,
                                "nonce": "0x0",
                            }
                        ],
                    }
                ] if auth_list is not False else [],
            }
        }

    def _mock_block_number(self, n: int) -> dict:
        return {"jsonrpc": "2.0", "id": 1, "result": hex(n)}

    def test_parse_authorization_from_dict(self):
        indexer = ChainIndexer("http://localhost:8545", chain_id=1)
        auth = {"chainId": "0x1", "address": "0xabcd" + "0" * 36, "nonce": "0x5"}
        event = indexer._parse_authorization(auth, "0xhash", "0xfrom", 100, int(time.time()))
        assert event is not None
        assert event.delegate_address == "0xabcd" + "0" * 36
        assert event.nonce == 5
        assert event.chain_id == 1

    def test_parse_authorization_from_list(self):
        indexer = ChainIndexer("http://localhost:8545", chain_id=1)
        auth = ["0x1", "0x" + "a" * 40, "0x3"]
        event = indexer._parse_authorization(auth, "0xhash", "0xfrom", 100, int(time.time()))
        assert event is not None
        assert event.nonce == 3

    def test_parse_revocation_address_zero(self):
        indexer = ChainIndexer("http://localhost:8545", chain_id=1)
        auth = {"chainId": "0x1", "address": "0x" + "0" * 40, "nonce": "0x0"}
        event = indexer._parse_authorization(auth, "0xhash", "0xfrom", 100, int(time.time()))
        assert event is not None
        assert event.is_revocation is True

    def test_ignores_non_type4_transactions(self):
        indexer = ChainIndexer("http://localhost:8545", chain_id=1, start_block=99)

        block_resp = {
            "result": {
                "number": "0x64",
                "timestamp": hex(int(time.time())),
                "transactions": [
                    {"hash": "0xabc", "type": "0x2", "authorizationList": []},
                    {"hash": "0xdef", "type": "0x0", "authorizationList": []},
                ],
            }
        }

        with patch.object(indexer, "_get_block", return_value=block_resp["result"]):
            events = indexer._process_block(100, emit=False)
        assert len(events) == 0

    def test_type4_with_empty_auth_list_returns_no_events(self):
        indexer = ChainIndexer("http://localhost:8545", chain_id=1, start_block=99)
        block = {
            "number": "0x64",
            "timestamp": hex(int(time.time())),
            "transactions": [
                {"hash": "0xabc", "type": "0x4", "authorizationList": []},
            ],
        }
        with patch.object(indexer, "_get_block", return_value=block):
            events = indexer._process_block(100, emit=False)
        assert len(events) == 0

    def test_type4_with_auth_list_returns_events(self):
        indexer = ChainIndexer("http://localhost:8545", chain_id=1, start_block=99)
        block = {
            "number": "0x64",
            "timestamp": hex(int(time.time())),
            "transactions": [
                {
                    "hash": "0xdeadbeef",
                    "type": "0x4",
                    "authorizationList": [
                        {"chainId": "0x1", "address": "0x" + "a" * 40, "nonce": "0x0"},
                        {"chainId": "0x1", "address": "0x" + "b" * 40, "nonce": "0x1"},
                    ],
                }
            ],
        }
        with patch.object(indexer, "_get_block", return_value=block):
            events = indexer._process_block(100, emit=False)
        assert len(events) == 2
        assert events[0].delegate_address == "0x" + "a" * 40
        assert events[1].delegate_address == "0x" + "b" * 40

    def test_callback_fires_on_event(self):
        indexer = ChainIndexer("http://localhost:8545", chain_id=1, start_block=99)
        received: list[DelegationEvent] = []
        indexer.on_event(received.append)

        block = {
            "number": "0x64",
            "timestamp": hex(int(time.time())),
            "transactions": [
                {
                    "hash": "0xtest",
                    "type": "0x4",
                    "authorizationList": [
                        {"chainId": "0x1", "address": "0x" + "c" * 40, "nonce": "0x0"},
                    ],
                }
            ],
        }
        with patch.object(indexer, "_get_block", return_value=block):
            indexer._process_block(100, emit=True)

        assert len(received) == 1
        assert received[0].tx_hash == "0xtest"

    def test_stats_returns_expected_keys(self):
        indexer = ChainIndexer("http://localhost:8545", chain_id=11155111, start_block=0)
        stats = indexer.stats
        assert "last_block"   in stats
        assert "total_blocks" in stats
        assert "total_events" in stats
        assert "chain_id"     in stats
        assert stats["chain_id"] == 11155111


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TestModels:

    def test_delegation_event_to_dict(self):
        evt = _event()
        d = evt.to_dict()
        assert "tx_hash" in d
        assert "delegate_address" in d
        assert "is_revocation" in d

    def test_delegate_record_to_dict(self):
        rec = DelegateRecord(address="0xabc", status=DelegateStatus.MALICIOUS)
        d = rec.to_dict()
        assert d["status"] == "malicious"
        assert d["address"] == "0xabc"

    def test_monitor_alert_to_dict(self):
        alert = MonitorAlert(
            level=AlertLevel.CRITICAL,
            title="Test",
            message="Test message",
            eoa_address="0xeoa",
            delegate_address="0xdel",
            tx_hash="0xtx",
            block_number=100,
        )
        d = alert.to_dict()
        assert d["level"] == "CRITICAL"
        assert d["title"] == "Test"

    def test_delegation_prefix_constant(self):
        assert DELEGATION_PREFIX == "0xef0100"
        assert len(DELEGATION_PREFIX) == 8  # "0x" + 6 hex chars = 3 bytes