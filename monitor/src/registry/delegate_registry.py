"""
DelegateGuard Monitor — Delegate Registry

Maintains the ground truth of known delegate contract classifications.
Seeded with real-world known delegates; auto-updated as the indexer
sees new addresses and the risk scorer classifies them.

In production this would be backed by a SQLite or Postgres DB.
For the open-source version we use an in-memory dict with JSON persistence.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from ..models import DelegateRecord, DelegateStatus



_SEED_REGISTRY: list[dict] = [
    # ── Known SAFE delegates ─────────────────────────────────────────────────
    {
        "address":   "0x000000000000000000000000000000000000000A",
        "status":    "safe",
        "name":      "OpenZeppelin ERC7702Utils v1",
        "notes":     "Audited by OZ team. Uses ERC-7201 namespaced storage.",
        "risk_signals": [],
        "added_by":  "manual",
    },
    {
        "address":   "0x000000000000000000000000000000000000000B",
        "status":    "safe",
        "name":      "MetaMask Delegation Toolkit v1",
        "notes":     "Cyfrin-audited. Safe init, namespaced storage, chain-bound domain sep.",
        "risk_signals": [],
        "added_by":  "manual",
    },
    {
        "address":   "0x000000000000000000000000000000000000000C",
        "status":    "safe",
        "name":      "Coinbase Smart Wallet Delegate",
        "notes":     "Audited. Uses ERC-4337 compatible batch execution with proper nonces.",
        "risk_signals": [],
        "added_by":  "manual",
    },

    # ── Known MALICIOUS delegates ────────────────────────────────────────────
    {
        "address":   "0xDEAD000000000000000000000000000000000001",
        "status":    "malicious",
        "name":      "Sweeper v1 (Aug 2025 campaign)",
        "notes":     "DC-07 sweeper. execute(address,bytes) with no auth or allowlist. "
                     "Used in phishing campaign that drained $1.54M from one victim.",
        "risk_signals": [
            "DC-07: sweeper pattern",
            "no owner check on execute()",
            "arbitrary ETH transfer",
        ],
        "added_by":  "manual",
    },
    {
        "address":   "0xDEAD000000000000000000000000000000000002",
        "status":    "malicious",
        "name":      "Sweeper v2 (Aug 2025 campaign)",
        "notes":     "Variant of the Aug 2025 sweeper. Added sweepERC20() helper.",
        "risk_signals": [
            "DC-07: sweeper pattern",
            "DC-04: no per-call auth",
            "arbitrary token transfer",
        ],
        "added_by":  "manual",
    },
    {
        "address":   "0xDEAD000000000000000000000000000000000003",
        "status":    "malicious",
        "name":      "Cross-chain replay exploit (Sept 2025)",
        "notes":     "DC-03: domain separator has no chainId. Replayed on Base after mainnet drain.",
        "risk_signals": [
            "DC-03: missing chainId in domain separator",
            "cross-chain replay confirmed",
        ],
        "added_by":  "manual",
    },

    # ── SUSPICIOUS (unverified, has signals) ─────────────────────────────────
    {
        "address":   "0xBEEF000000000000000000000000000000000001",
        "status":    "suspicious",
        "name":      None,
        "notes":     "Unaudited. Has execute(address,bytes) but with msg.sender check. "
                     "Missing ERC-7201 storage (DC-01 risk on re-delegation).",
        "risk_signals": [
            "DC-01: raw storage slots",
            "DC-02: unprotected initializer",
        ],
        "added_by":  "auto",
    },
]


class DelegateRegistry:
    """
    In-memory registry of known delegate contracts.
    Persists to a JSON file so the monitor resumes state across restarts.
    """

    def __init__(self, persist_path: Optional[str] = None):
        self._records: dict[str, DelegateRecord] = {}
        self._persist_path = persist_path or os.environ.get(
            "DELEGATE_REGISTRY_PATH",
            str(Path(__file__).parent.parent.parent / "data" / "registry.json"),
        )
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, address: str) -> Optional[DelegateRecord]:
        return self._records.get(address.lower())

    def classify(self, address: str) -> DelegateStatus:
        rec = self.get(address)
        return rec.status if rec else DelegateStatus.UNKNOWN

    def upsert(self, record: DelegateRecord) -> None:
        key = record.address.lower()
        record.address = key
        self._records[key] = record
        self._save()

    def mark_malicious(self, address: str, reason: str, signals: list[str] | None = None) -> None:
        addr = address.lower()
        rec = self._records.get(addr) or DelegateRecord(address=addr, status=DelegateStatus.MALICIOUS)
        rec.status = DelegateStatus.MALICIOUS
        rec.notes = reason
        rec.risk_signals = signals or rec.risk_signals
        self._records[addr] = rec
        self._save()

    def increment_eoa_count(self, delegate_address: str, delta: int = 1) -> None:
        addr = delegate_address.lower()
        if addr in self._records:
            self._records[addr].eoa_count = max(0, self._records[addr].eoa_count + delta)
            self._save()

    def all_records(self) -> list[DelegateRecord]:
        return list(self._records.values())

    def malicious_addresses(self) -> set[str]:
        return {addr for addr, rec in self._records.items()
                if rec.status == DelegateStatus.MALICIOUS}

    def safe_addresses(self) -> set[str]:
        return {addr for addr, rec in self._records.items()
                if rec.status == DelegateStatus.SAFE}

    def stats(self) -> dict:
        counts = {s.value: 0 for s in DelegateStatus}
        for rec in self._records.values():
            counts[rec.status.value] += 1
        return {"total": len(self._records), **counts}

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        # Always seed from the hardcoded list first
        for seed in _SEED_REGISTRY:
            addr = seed["address"].lower()
            self._records[addr] = DelegateRecord(
                address=addr,
                status=DelegateStatus(seed["status"]),
                name=seed.get("name"),
                notes=seed.get("notes"),
                risk_signals=seed.get("risk_signals", []),
                added_by=seed.get("added_by", "manual"),
            )

        # Then overlay with persisted data (may have newer classifications)
        path = Path(self._persist_path)
        if path.exists():
            try:
                data = json.loads(path.read_text())
                for entry in data.get("records", []):
                    addr = entry["address"].lower()
                    self._records[addr] = DelegateRecord(
                        address=addr,
                        status=DelegateStatus(entry.get("status", "unknown")),
                        name=entry.get("name"),
                        notes=entry.get("notes"),
                        risk_signals=entry.get("risk_signals", []),
                        first_seen_block=entry.get("first_seen_block"),
                        eoa_count=entry.get("eoa_count", 0),
                        added_by=entry.get("added_by", "auto"),
                    )
            except Exception:
                pass  # corrupt file — use seed data

    def _save(self) -> None:
        path = Path(self._persist_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {"records": [r.to_dict() for r in self._records.values()]}
        path.write_text(json.dumps(data, indent=2))