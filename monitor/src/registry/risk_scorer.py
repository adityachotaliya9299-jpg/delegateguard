"""
DelegateGuard Monitor — Risk Scorer

When the indexer sees a NEW delegate address it has never encountered,
the risk scorer attempts to classify it by:

1. Bytecode-level checks (delegation designator pattern analysis)
2. Heuristic signals from the bytecode (known sweeper function selectors,
   suspicious opcode patterns)
3. Cross-referencing against known-bad bytecode hashes

In production this would also call out to the DelegateGuard analyzer CLI
to run full Slither analysis. For the monitor we keep it lightweight and
fast so it can run synchronously in the polling loop.
"""
from __future__ import annotations

from typing import Optional

from ..models import DelegateStatus, DelegateRecord


# Known malicious function selectors (4-byte keccak prefix)
# These appear in confirmed sweeper contracts
_MALICIOUS_SELECTORS = {
    # sweepETH(address)
    "0x4782f779",
    # drain(address)
    "0x9890220b",
    # sweepTokens(address,address)
    "0x5f575529",
}

# Selectors that are suspicious but not definitive
_SUSPICIOUS_SELECTORS = {
    # execute(address,bytes) — could be legitimate but high-risk without allowlist
    "0x1cff79cd",
    # delegateTo(address,bytes) — inner delegatecall pattern
    "0x6b5cc770",
}

# Known clean bytecode prefixes (first 8 bytes after PUSH1 0x60 PUSH1 0x40 MSTORE)
# These match audited reference implementations
_SAFE_BYTECODE_PREFIXES: set[str] = set()


class RiskScorer:
    """
    Classifies a delegate contract address based on available signals.
    Called by the indexer whenever a new (unknown) delegate is seen.
    """

    def score(
        self,
        delegate_address: str,
        bytecode: Optional[str] = None,
    ) -> DelegateRecord:
        """
        Score a delegate address and return a DelegateRecord with
        the classification and risk signals found.

        Args:
            delegate_address: The contract address to classify.
            bytecode: Hex-encoded runtime bytecode if available.
                      If None, we return UNKNOWN with a note.

        Returns:
            A DelegateRecord (not yet persisted — caller must upsert).
        """
        addr = delegate_address.lower()
        signals: list[str] = []

        if not bytecode:
            return DelegateRecord(
                address=addr,
                status=DelegateStatus.UNKNOWN,
                notes="No bytecode available for analysis",
                risk_signals=[],
                added_by="auto",
            )

        bytecode_lower = bytecode.lower()

        # ── 1. Check delegation designator ─────────────────────────────────
        # A contract whose own bytecode contains 0xef0100 is a chained
        # delegate — rare but an immediate DC-05 signal
        if "ef0100" in bytecode_lower:
            signals.append("DC-05: bytecode contains inner delegation designator")

        # ── 2. Check known malicious selectors ────────────────────────────
        malicious_hits = []
        for sel in _MALICIOUS_SELECTORS:
            if sel[2:] in bytecode_lower:  # strip 0x prefix for search
                malicious_hits.append(sel)
                signals.append(f"DC-07: known malicious selector {sel}")

        if malicious_hits:
            return DelegateRecord(
                address=addr,
                status=DelegateStatus.MALICIOUS,
                notes=f"Bytecode contains {len(malicious_hits)} known malicious selector(s): {', '.join(malicious_hits)}",
                risk_signals=signals,
                added_by="auto",
            )

        # ── 3. Check suspicious selectors ────────────────────────────────
        for sel in _SUSPICIOUS_SELECTORS:
            if sel[2:] in bytecode_lower:
                signals.append(f"suspicious selector {sel} (may be DC-07 without allowlist)")

        # ── 4. Heuristic: very short bytecode ────────────────────────────
        # Real smart wallet delegates are typically >500 bytes
        # Very short contracts (<100 bytes) are usually minimal sweepers
        raw_bytes = len(bytecode.replace("0x", "")) // 2
        if raw_bytes < 100:
            signals.append(f"very short bytecode ({raw_bytes} bytes) — possible minimal sweeper")

        # ── 5. Check safe prefixes ────────────────────────────────────────
        bytecode_clean = bytecode.replace("0x", "").lower()
        for prefix in _SAFE_BYTECODE_PREFIXES:
            if bytecode_clean.startswith(prefix):
                return DelegateRecord(
                    address=addr,
                    status=DelegateStatus.SAFE,
                    notes="Matches known-safe bytecode prefix",
                    risk_signals=[],
                    added_by="auto",
                )

        # ── 6. Classify based on signals found ───────────────────────────
        if len(signals) >= 2:
            status = DelegateStatus.SUSPICIOUS
            notes = f"Multiple risk signals detected: {len(signals)} signals"
        elif len(signals) == 1:
            status = DelegateStatus.SUSPICIOUS
            notes = f"Risk signal detected: {signals[0]}"
        else:
            status = DelegateStatus.UNKNOWN
            notes = "No risk signals detected. Manual review recommended."

        return DelegateRecord(
            address=addr,
            status=status,
            notes=notes,
            risk_signals=signals,
            added_by="auto",
        )

    def add_safe_prefix(self, prefix: str) -> None:
        """Register a known-safe bytecode prefix (first 32+ hex chars)."""
        _SAFE_BYTECODE_PREFIXES.add(prefix.lower().replace("0x", ""))