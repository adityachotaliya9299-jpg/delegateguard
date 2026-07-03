"""
DelegateGuard Monitor — Orchestrator

Wires the ChainIndexer, DelegateRegistry, RiskScorer, and AlertEngine
into a single runnable monitor process.

Usage (CLI):
    delegateguard monitor --rpc https://mainnet.infura.io/v3/KEY --chain 1

Usage (Python):
    monitor = DelegateGuardMonitor(rpc_url="...", chain_id=1)
    monitor.start()   # blocks forever
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional

from .indexer  import ChainIndexer
from .registry import DelegateRegistry, RiskScorer
from .alerts   import AlertEngine
from .models   import MonitorAlert, AlertLevel, DelegationEvent

logger = logging.getLogger("delegateguard.monitor")


class DelegateGuardMonitor:
    """
    Top-level monitor that connects all four components.
    """

    def __init__(
        self,
        rpc_url: str,
        chain_id: int = 1,
        start_block: Optional[int] = None,
        registry_path: Optional[str] = None,
        poll_interval: float = 12.0,
        verbose: bool = False,
    ):
        self.rpc_url       = rpc_url
        self.chain_id      = chain_id
        self.poll_interval = poll_interval

        # Wire components
        self.registry = DelegateRegistry(persist_path=registry_path)
        self.scorer   = RiskScorer()
        self.engine   = AlertEngine(self.registry, self.scorer, rpc_url=rpc_url)
        self.indexer  = ChainIndexer(rpc_url, chain_id=chain_id, start_block=start_block)

        # Connect indexer → alert engine
        self.indexer.on_event(self._on_delegation_event)

        # Default alert handler: print to stdout
        self.engine.on_alert(self._default_alert_handler)

        if verbose:
            logging.basicConfig(
                level=logging.DEBUG,
                format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            )
        else:
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s [DelegateGuard] %(levelname)s: %(message)s",
            )

    def start(self) -> None:
        """Start the monitor (blocks forever)."""
        self._print_banner()
        self.indexer.run(poll_interval=self.poll_interval)

    def check_address(self, address: str) -> dict:
        """
        One-shot: check if a specific delegate address is known/safe/malicious.
        Returns the registry record as a dict.
        """
        record = self.registry.get(address)
        if record:
            return record.to_dict()

        bytecode = self.engine._fetch_bytecode(address)
        record   = self.scorer.score(address, bytecode)
        self.registry.upsert(record)
        return record.to_dict()

    def scan_block(self, block_number: int) -> list[MonitorAlert]:
        """Scan a specific historical block for delegation events."""
        events  = self.indexer.scan_block(block_number)
        alerts: list[MonitorAlert] = []
        for event in events:
            alerts.extend(self.engine.process(event))
        return alerts

    def status(self) -> dict:
        return {
            "indexer":  self.indexer.stats,
            "registry": self.registry.stats(),
            "alerts":   self.engine.alert_stats(),
        }

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _on_delegation_event(self, event: DelegationEvent) -> None:
        self.engine.process(event)

    def _default_alert_handler(self, alert: MonitorAlert) -> None:
        level_color = {
            AlertLevel.CRITICAL: "\033[91m",  # red
            AlertLevel.WARNING:  "\033[93m",  # yellow
            AlertLevel.INFO:     "\033[96m",  # cyan
        }
        reset = "\033[0m"
        color = level_color.get(alert.level, "")

        print(
            f"\n{color}[{alert.level.value}]{reset} {alert.title}\n"
            f"  EOA:      {alert.eoa_address}\n"
            f"  Delegate: {alert.delegate_address}\n"
            f"  Block:    {alert.block_number}\n"
            f"  Tx:       {alert.tx_hash}\n"
            f"  Message:  {alert.message}"
        )
        if alert.risk_signals:
            print(f"  Signals:  {', '.join(alert.risk_signals)}")

    def _print_banner(self) -> None:
        print("\n\033[96m" + "=" * 60)
        print("  DelegateGuard On-Chain Monitor")
        print(f"  Chain ID:  {self.chain_id}")
        print(f"  RPC:       {self.rpc_url[:50]}...")
        print(f"  Registry:  {self.registry.stats()['total']} known delegates")
        print(f"  Poll:      every {self.poll_interval}s")
        print("=" * 60 + "\033[0m\n")