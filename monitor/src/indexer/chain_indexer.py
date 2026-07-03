"""
DelegateGuard Monitor — Chain Indexer

Polls an EVM RPC endpoint for new blocks, finds type-4 (EIP-7702)
transactions, parses their authorization lists, and emits DelegationEvents.

EIP-7702 type-4 transaction structure:
    transaction_type = 0x04
    authorization_list = [
        [chain_id, address, nonce, y_parity, r, s],
        ...
    ]

The indexer:
  1. Polls latest block number every POLL_INTERVAL seconds
  2. For each new block, fetches all transactions
  3. Filters for type == "0x4" transactions
  4. Parses authorization_list entries into DelegationEvent objects
  5. Passes events to the AlertEngine for classification

Supported RPCs: any Ethereum-compatible JSON-RPC endpoint
(Infura, Alchemy, public RPCs, local Anvil/Hardhat nodes)
"""
from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error
from typing import Callable, Optional

from ..models import DelegationEvent, DELEGATION_PREFIX

logger = logging.getLogger("delegateguard.indexer")

# EIP-7702 transaction type identifier
EIP7702_TX_TYPE = "0x4"

# How many blocks to fetch in one batch when catching up
BATCH_SIZE = 20


class ChainIndexer:
    """
    Polls an EVM RPC for EIP-7702 type-4 transactions and emits DelegationEvents.

    Usage:
        indexer = ChainIndexer(rpc_url="https://...", chain_id=1)
        indexer.on_event(my_callback)
        indexer.run(poll_interval=12)   # blocks forever
    """

    def __init__(
        self,
        rpc_url: str,
        chain_id: int = 1,
        start_block: Optional[int] = None,
    ):
        self.rpc_url   = rpc_url
        self.chain_id  = chain_id
        self._callbacks: list[Callable[[DelegationEvent], None]] = []
        self._last_block: Optional[int] = start_block
        self._total_events = 0
        self._total_blocks  = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def on_event(self, callback: Callable[[DelegationEvent], None]) -> None:
        """Register a callback that fires for each DelegationEvent found."""
        self._callbacks.append(callback)

    def run(self, poll_interval: float = 12.0) -> None:
        """
        Block forever, polling for new blocks every poll_interval seconds.
        Calls registered callbacks for each DelegationEvent found.
        """
        logger.info(
            "DelegateGuard Monitor starting | chain=%d | rpc=%s",
            self.chain_id, self.rpc_url[:40] + "...",
        )

        if self._last_block is None:
            self._last_block = self._get_latest_block()
            logger.info("Starting from block %d", self._last_block)

        while True:
            try:
                latest = self._get_latest_block()
                if latest > self._last_block:
                    self._process_range(self._last_block + 1, latest)
                    self._last_block = latest
            except Exception as e:
                logger.error("Indexer error: %s — retrying in %ds", e, poll_interval)

            time.sleep(poll_interval)

    def poll_once(self) -> list[DelegationEvent]:
        """
        Poll for new events once and return them (non-blocking, for testing).
        """
        if self._last_block is None:
            self._last_block = self._get_latest_block()

        latest = self._get_latest_block()
        events: list[DelegationEvent] = []

        if latest > self._last_block:
            for block_num in range(self._last_block + 1, latest + 1):
                events.extend(self._process_block(block_num, emit=False))
            self._last_block = latest

        return events

    def scan_block(self, block_number: int) -> list[DelegationEvent]:
        """Scan a specific block for delegation events (useful for backfill)."""
        return self._process_block(block_number, emit=False)

    @property
    def stats(self) -> dict:
        return {
            "last_block":    self._last_block,
            "total_blocks":  self._total_blocks,
            "total_events":  self._total_events,
            "chain_id":      self.chain_id,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _process_range(self, from_block: int, to_block: int) -> None:
        """Process a range of blocks, respecting BATCH_SIZE."""
        for block_num in range(from_block, to_block + 1):
            try:
                self._process_block(block_num, emit=True)
            except Exception as e:
                logger.warning("Failed to process block %d: %s", block_num, e)

    def _process_block(self, block_number: int, emit: bool) -> list[DelegationEvent]:
        """Fetch and parse a single block, return any DelegationEvents found."""
        block = self._get_block(block_number)
        if not block:
            return []

        self._total_blocks += 1
        timestamp = int(block.get("timestamp", "0x0"), 16)
        events: list[DelegationEvent] = []

        for tx in block.get("transactions", []):
            if not isinstance(tx, dict):
                continue
            # EIP-7702 txs have type "0x4"
            if tx.get("type", "").lower() != EIP7702_TX_TYPE:
                continue

            auth_list = tx.get("authorizationList", [])
            if not auth_list:
                continue

            tx_hash = tx.get("hash", "")
            logger.debug(
                "Block %d tx %s has %d authorization(s)",
                block_number, tx_hash[:10], len(auth_list),
            )

            for auth in auth_list:
                event = self._parse_authorization(
                    auth, tx_hash, block_number, timestamp
                )
                if event:
                    events.append(event)
                    self._total_events += 1
                    if emit:
                        for cb in self._callbacks:
                            try:
                                cb(event)
                            except Exception as e:
                                logger.error("Callback error: %s", e)

        return events

    def _parse_authorization(
        self,
        auth: dict,
        tx_hash: str,
        block_number: int,
        timestamp: int,
    ) -> Optional[DelegationEvent]:
        """
        Parse a single authorization list entry into a DelegationEvent.

        Authorization list entry (EIP-7702 spec):
            [chain_id, address, nonce, y_parity, r, s]
        or as a dict from eth_getBlockByNumber with full txs:
            {"chainId": "0x1", "address": "0x...", "nonce": "0x0", ...}
        """
        try:
            if isinstance(auth, (list, tuple)):
                chain_id_raw, address, nonce_raw = auth[0], auth[1], auth[2]
            elif isinstance(auth, dict):
                chain_id_raw = auth.get("chainId", hex(self.chain_id))
                address      = auth.get("address", "")
                nonce_raw    = auth.get("nonce", "0x0")
            else:
                return None

            # Parse hex values
            chain_id = int(chain_id_raw, 16) if isinstance(chain_id_raw, str) else int(chain_id_raw)
            nonce    = int(nonce_raw, 16)    if isinstance(nonce_raw, str)    else int(nonce_raw)

            if not address:
                return None

            # address == 0x0000...0000 means revocation (clearing delegation)
            is_revocation = address == "0x" + "0" * 40

            return DelegationEvent(
                tx_hash=tx_hash,
                block_number=block_number,
                block_timestamp=timestamp,
                eoa_address=tx_hash,      # approximation — real EOA is tx.from
                delegate_address=address.lower(),
                chain_id=chain_id,
                nonce=nonce,
                is_revocation=is_revocation,
            )
        except Exception as e:
            logger.debug("Failed to parse authorization: %s | %s", auth, e)
            return None

    # ------------------------------------------------------------------
    # RPC helpers
    # ------------------------------------------------------------------

    def _rpc(self, method: str, params: list) -> object:
        payload = json.dumps({
            "jsonrpc": "2.0",
            "method":  method,
            "params":  params,
            "id":      1,
        }).encode()
        req = urllib.request.Request(
            self.rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        if "error" in data:
            raise RuntimeError(f"RPC error: {data['error']}")
        return data.get("result")

    def _get_latest_block(self) -> int:
        result = self._rpc("eth_blockNumber", [])
        return int(result, 16)

    def _get_block(self, block_number: int) -> Optional[dict]:
        result = self._rpc(
            "eth_getBlockByNumber",
            [hex(block_number), True],  # True = include full tx objects
        )
        return result