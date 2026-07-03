# DelegateGuard Monitor (Engine 4)

On-chain delegation monitor for EIP-7702. Indexes type-4 transactions,
cross-references delegate addresses against the known-malicious registry,
and alerts on suspicious activity in near-real-time.

---

## Architecture

```
ChainIndexer  →  AlertEngine  →  Console / Webhook
     ↓               ↓
  DelegationEvent  DelegateRegistry + RiskScorer
```

- **ChainIndexer** — polls JSON-RPC for new blocks, parses type-4 tx authorization lists
- **DelegateRegistry** — known-good / known-malicious delegate address database
- **RiskScorer** — classifies unknown delegates via bytecode heuristics
- **AlertEngine** — applies alert rules, emits MonitorAlerts

---

## Usage

```bash
# Watch mainnet
delegateguard monitor --rpc https://mainnet.infura.io/v3/YOUR_KEY

# Watch Sepolia testnet (recommended for testing)
delegateguard monitor --rpc https://sepolia.infura.io/v3/YOUR_KEY --chain 11155111

# Use environment variable
export ETH_RPC_URL=https://mainnet.infura.io/v3/YOUR_KEY
delegateguard monitor

# One-shot: check if a specific address is malicious
delegateguard monitor --rpc $ETH_RPC_URL --check 0xDEAD...

# Start from a specific block (backfill)
delegateguard monitor --rpc $ETH_RPC_URL --start-block 21000000

# Custom registry path (persist across restarts)
delegateguard monitor --rpc $ETH_RPC_URL --registry-path /data/registry.json

# Verbose logging
delegateguard monitor --rpc $ETH_RPC_URL --verbose
```

## Alert rules

| Level    | Condition |
|----------|-----------|
| CRITICAL | Delegate is in the known-malicious registry |
| CRITICAL | Authorization signed with `chain_id = 0` (cross-chain replay, DC-03) |
| WARNING  | Delegate is suspicious (unverified with risk signals) |
| WARNING  | High EOA concentration on one delegate (possible phishing campaign) |
| INFO     | New delegation to unclassified contract |
| INFO     | Delegation revoked (EOA cleared its code slot) |

## Registry

Seeded with:
- Known-safe delegates: OZ ERC7702Utils, MetaMask Delegation Toolkit, Coinbase Smart Wallet
- Known-malicious delegates: August 2025 sweeper campaigns (DC-07)
- Suspicious: unaudited delegates with risk signals

## Zero dependencies

The monitor uses only Python stdlib — no web3.py, no viem, no external packages.
Runs anywhere Python 3.9+ is available.

## Run tests

```bash
pytest monitor/tests/ -v
```