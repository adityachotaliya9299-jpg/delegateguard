"""
DelegateGuard Monitor — WebSocket Indexer (eth_subscribe)

An alternative front-end to ChainIndexer that replaces block *polling* with a
push subscription. It opens a WebSocket to the node, subscribes to
`eth_subscribe("newHeads")`, and on every new header hands the block number to
the existing (already-tested) ChainIndexer parsing path.

Design note — why compose instead of reimplement:
    `newHeads` notifications carry only the block *header*, not its transactions.
    So after each header we still fetch the full block over JSON-RPC and parse it
    with ChainIndexer's proven `_process_block`. The only new surface here is the
    WebSocket transport + reconnect loop; the correctness-critical authorization
    parsing is unchanged and stays covered by test_monitor.py.

This module is intentionally NOT imported by monitor.src.__init__ — the default
monitor keeps using the HTTP poller. Opt in explicitly:

    from monitor.src.indexer.ws_indexer import WebSocketIndexer

Requires the `websocket-client` package (not a core dependency):

    pip install websocket-client

Status: transport glue is unit-testable but needs a live-node smoke test before
being wired into the default monitor. See docs/LIMITATIONS.md (E4).
"""
from __future__ import annotations

import json
import logging
import time
from typing import Callable, Optional

from ..models import DelegationEvent
from .chain_indexer import ChainIndexer

logger = logging.getLogger("delegateguard.ws_indexer")

# Reconnect backoff bounds (seconds)
_BACKOFF_MIN = 1.0
_BACKOFF_MAX = 30.0


class WebSocketIndexer:
    """
    Push-based indexer built on eth_subscribe("newHeads").

    Usage:
        idx = WebSocketIndexer("wss://mainnet.example/ws", chain_id=1)
        idx.on_event(handle_event)
        idx.run()   # blocks, auto-reconnects
    """

    def __init__(self, ws_url: str, chain_id: int = 1, http_url: Optional[str] = None):
        if not ws_url.startswith(("ws://", "wss://")):
            raise ValueError("ws_url must be a ws:// or wss:// endpoint")
        self.ws_url = ws_url
        # Header notifications lack transactions, so block bodies are fetched over
        # HTTP. Derive an http(s) URL from the ws one if the caller didn't pass a
        # dedicated endpoint.
        self._http = ChainIndexer(
            rpc_url=http_url or ws_url.replace("wss://", "https://").replace("ws://", "http://"),
            chain_id=chain_id,
        )

    def on_event(self, callback: Callable[[DelegationEvent], None]) -> None:
        self._http.on_event(callback)

    @property
    def stats(self) -> dict:
        return self._http.stats

    # ------------------------------------------------------------------

    def run(self, max_reconnects: Optional[int] = None) -> None:
        """Block forever, (re)subscribing to newHeads and processing blocks."""
        try:
            import websocket  # websocket-client
        except ImportError as e:  # pragma: no cover - depends on optional dep
            raise RuntimeError(
                "WebSocketIndexer needs the 'websocket-client' package: "
                "pip install websocket-client"
            ) from e

        backoff = _BACKOFF_MIN
        attempts = 0

        while True:
            try:
                logger.info("Connecting to %s", self.ws_url[:48])
                ws = websocket.create_connection(self.ws_url, timeout=30)
                ws.send(json.dumps({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "eth_subscribe", "params": ["newHeads"],
                }))
                ack = json.loads(ws.recv())
                if "error" in ack:
                    raise RuntimeError(f"subscribe failed: {ack['error']}")
                logger.info("Subscribed to newHeads (id=%s)", ack.get("result"))
                backoff = _BACKOFF_MIN  # reset after a clean connect

                self._consume(ws)
            except Exception as e:  # noqa: BLE001 - transport is intentionally broad
                logger.warning("WS connection dropped: %s — reconnecting in %.0fs", e, backoff)

            attempts += 1
            if max_reconnects is not None and attempts > max_reconnects:
                logger.info("Reached max reconnects (%d), stopping.", max_reconnects)
                return
            time.sleep(backoff)
            backoff = min(_BACKOFF_MAX, backoff * 2)

    def _consume(self, ws) -> None:
        """Read newHeads notifications until the socket closes."""
        while True:
            raw = ws.recv()
            if not raw:
                return  # socket closed
            block_number = self._block_number_from_head(raw)
            if block_number is None:
                continue
            try:
                # Reuse ChainIndexer's tested parse + emit path.
                self._http._process_block(block_number, emit=True)
            except Exception as e:  # noqa: BLE001
                logger.warning("Failed to process block %d: %s", block_number, e)

    @staticmethod
    def _block_number_from_head(raw: str) -> Optional[int]:
        """
        Extract the block number from an eth_subscribe newHeads notification.

        Shape:
          {"jsonrpc":"2.0","method":"eth_subscription",
           "params":{"subscription":"0x..","result":{"number":"0x...", ...}}}
        """
        try:
            msg = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return None
        if msg.get("method") != "eth_subscription":
            return None
        result = (msg.get("params") or {}).get("result") or {}
        number = result.get("number")
        if not isinstance(number, str):
            return None
        try:
            return int(number, 16)
        except ValueError:
            return None
