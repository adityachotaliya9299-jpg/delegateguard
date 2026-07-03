"""
DelegateGuard Monitor — Alert Engine

Receives DelegationEvents from the indexer, cross-references them with
the delegate registry, runs risk scoring on unknown delegates, and raises
MonitorAlerts for anything suspicious or malicious.

Alert rules:
  CRITICAL — delegate is in the known-malicious registry
  CRITICAL — delegate matches a known sweeper bytecode selector
  WARNING  — delegate is unverified (unknown) with risk signals
  WARNING  — chain_id == 0 in the authorization (cross-chain replay risk)
  WARNING  — very high EOA count for a single delegate (possible phishing campaign)
  INFO     — new delegate seen for the first time (unknown, no signals)
  INFO     — delegation revoked (EOA cleared its code slot)
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

from ..models import (
    AlertLevel,
    DelegationEvent,
    DelegateStatus,
    MonitorAlert,
)
from ..registry import DelegateRegistry, RiskScorer

logger = logging.getLogger("delegateguard.alerts")

# Alert threshold: if more than this many EOAs delegate to a single address
# in a short time, it may indicate a phishing campaign
CAMPAIGN_THRESHOLD = 10


class AlertEngine:
    """
    Processes DelegationEvents and emits MonitorAlerts.

    Usage:
        registry = DelegateRegistry()
        engine = AlertEngine(registry)
        engine.on_alert(my_callback)
        engine.process(event)
    """

    def __init__(
        self,
        registry: DelegateRegistry,
        scorer: Optional[RiskScorer] = None,
        rpc_url: Optional[str] = None,
    ):
        self.registry  = registry
        self.scorer    = scorer or RiskScorer()
        self.rpc_url   = rpc_url
        self._callbacks: list[Callable[[MonitorAlert], None]] = []
        self._alert_history: list[MonitorAlert] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def on_alert(self, callback: Callable[[MonitorAlert], None]) -> None:
        """Register a callback that fires for each MonitorAlert raised."""
        self._callbacks.append(callback)

    def process(self, event: DelegationEvent) -> list[MonitorAlert]:
        """
        Process a single DelegationEvent and return any alerts raised.
        Also updates the registry with new information.
        """
        alerts: list[MonitorAlert] = []

        # ── Handle revocations ─────────────────────────────────────────
        if event.is_revocation:
            self.registry.increment_eoa_count(event.delegate_address, delta=-1)
            alerts.append(self._make_alert(
                level=AlertLevel.INFO,
                title="Delegation revoked",
                message=f"EOA cleared its delegation (code slot zeroed).",
                event=event,
                signals=["delegation_revoked"],
            ))
            return self._emit(alerts)

        # ── Lookup delegate in registry ────────────────────────────────
        record = self.registry.get(event.delegate_address)

        if record is None:
            # New delegate — score it
            bytecode = self._fetch_bytecode(event.delegate_address)
            record = self.scorer.score(event.delegate_address, bytecode)
            record.first_seen_block = event.block_number
            self.registry.upsert(record)
            logger.info(
                "New delegate %s classified as %s",
                event.delegate_address[:10], record.status.value,
            )

        # Update EOA count for this delegate
        self.registry.increment_eoa_count(event.delegate_address, delta=1)

        # Re-fetch updated record
        record = self.registry.get(event.delegate_address)

        # ── Rule 1: Known malicious delegate ─────────────────────────
        if record and record.status == DelegateStatus.MALICIOUS:
            alerts.append(self._make_alert(
                level=AlertLevel.CRITICAL,
                title="Delegation to known-malicious contract",
                message=(
                    f"EOA delegated to a contract in the malicious registry. "
                    f"Known issue: {record.notes or 'no details'}. "
                    f"This may be a phishing attack targeting this EOA."
                ),
                event=event,
                signals=record.risk_signals,
            ))

        # ── Rule 2: chain_id == 0 (cross-chain replay risk, DC-03) ───
        if event.chain_id == 0:
            alerts.append(self._make_alert(
                level=AlertLevel.CRITICAL,
                title="Authorization signed with chain_id=0 (cross-chain replay risk)",
                message=(
                    "The EIP-7702 authorization tuple was signed with chain_id=0, "
                    "making it valid on EVERY EVM chain. This signature can be replayed "
                    "on Arbitrum, Base, Optimism, and any other chain where this EOA "
                    "holds assets. DC-03 vulnerability."
                ),
                event=event,
                signals=["DC-03: chain_id=0 in authorization"],
            ))

        # ── Rule 3: Suspicious delegate ───────────────────────────────
        elif record and record.status == DelegateStatus.SUSPICIOUS:
            alerts.append(self._make_alert(
                level=AlertLevel.WARNING,
                title="Delegation to suspicious unverified contract",
                message=(
                    f"EOA delegated to an unaudited contract with risk signals. "
                    f"Signals: {', '.join(record.risk_signals) or 'unknown'}. "
                    f"Manual review recommended."
                ),
                event=event,
                signals=record.risk_signals,
            ))

        # ── Rule 4: Campaign detection ────────────────────────────────
        if record and record.eoa_count >= CAMPAIGN_THRESHOLD:
            if not any(a.title.startswith("Possible phishing campaign") for a in self._alert_history[-50:]):
                alerts.append(self._make_alert(
                    level=AlertLevel.WARNING,
                    title="Possible phishing campaign detected",
                    message=(
                        f"{record.eoa_count} EOAs have delegated to the same contract "
                        f"({event.delegate_address[:10]}...). This pattern matches "
                        f"known phishing campaign behavior."
                    ),
                    event=event,
                    signals=["high_eoa_concentration", f"eoa_count={record.eoa_count}"],
                ))

        # ── Rule 5: Unknown delegate (informational) ──────────────────
        if not alerts and record and record.status == DelegateStatus.UNKNOWN:
            alerts.append(self._make_alert(
                level=AlertLevel.INFO,
                title="New delegation to unclassified contract",
                message=(
                    f"EOA delegated to a contract not in the registry. "
                    f"No risk signals detected. Monitoring for activity."
                ),
                event=event,
                signals=[],
            ))

        return self._emit(alerts)

    def recent_alerts(self, limit: int = 50) -> list[MonitorAlert]:
        return self._alert_history[-limit:]

    def alert_stats(self) -> dict:
        counts = {l.value: 0 for l in AlertLevel}
        for a in self._alert_history:
            counts[a.level.value] += 1
        return {"total": len(self._alert_history), **counts}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _make_alert(
        self,
        level: AlertLevel,
        title: str,
        message: str,
        event: DelegationEvent,
        signals: list[str],
    ) -> MonitorAlert:
        return MonitorAlert(
            level=level,
            title=title,
            message=message,
            eoa_address=event.eoa_address,
            delegate_address=event.delegate_address,
            tx_hash=event.tx_hash,
            block_number=event.block_number,
            risk_signals=signals,
        )

    def _emit(self, alerts: list[MonitorAlert]) -> list[MonitorAlert]:
        for alert in alerts:
            self._alert_history.append(alert)
            if alert.level in (AlertLevel.CRITICAL, AlertLevel.WARNING):
                logger.warning("[%s] %s | delegate=%s",
                               alert.level.value, alert.title,
                               alert.delegate_address[:12])
            for cb in self._callbacks:
                try:
                    cb(alert)
                except Exception as e:
                    logger.error("Alert callback error: %s", e)
        return alerts

    def _fetch_bytecode(self, address: str) -> Optional[str]:
        """Fetch runtime bytecode via JSON-RPC eth_getCode."""
        if not self.rpc_url:
            return None
        try:
            import json
            import urllib.request
            payload = json.dumps({
                "jsonrpc": "2.0", "method": "eth_getCode",
                "params": [address, "latest"], "id": 1,
            }).encode()
            req = urllib.request.Request(
                self.rpc_url, data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
            code = data.get("result", "0x")
            return code if code and code != "0x" else None
        except Exception as e:
            logger.debug("Failed to fetch bytecode for %s: %s", address, e)
            return None