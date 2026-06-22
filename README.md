# DelegateGuard

> Security analysis toolkit for EIP-7702 delegate contracts and post-Pectra protocol assumptions.

EIP-7702 (shipped with Pectra, May 2025) lets any EOA delegate execution to a contract. This collapsed three previously separate security domains — wallet code, delegate contracts, and protocol-side EOA assumptions — into a single attack surface. DelegateGuard is the specialist toolkit for that surface.

---

## What it does

| Engine | Tool | Status |
|--------|------|--------|
| **E1** Delegate-contract analyzer | `delegateguard analyze <contract>` | 🚧 Phase 2 |
| **E2** Protocol-assumption scanner | `delegateguard scan <repo>` | 🚧 Phase 3 |
| **E3** PoC / invariant harness generator | `delegateguard harness <finding>` | 🚧 Phase 4 |
| **E4** On-chain delegation monitor | `delegateguard monitor` | 🚧 Phase 6 |

---

## Project structure

```
delegateguard/
├── docs/               # Threat model, vulnerability catalog, writeups
├── lab/                # Foundry vulnerability PoC lab (Phase 1)
├── analyzer/           # Slither-based delegate-contract analyzer (Phase 2)
├── scanner/            # Protocol-assumption scanner (Phase 3)
├── dashboard/          # Next.js dashboard + CI integration (Phase 5)
└── monitor/            # On-chain delegation monitor (Phase 6)
```

---

## Vulnerability coverage

### Delegate-contract bug classes (E1)
1. Storage collision on re-delegation
2. Unprotected / front-runnable initializer
3. Cross-chain replay via `chain_id = 0`
4. Missing per-call authentication
5. Unsafe inner `DELEGATECALL`
6. Batch executor replay / nonce gaps
7. Sweeper pattern (the live phishing exploit class)
8. Signature malleability in `ecrecover`-based flows

### Protocol-assumption bug classes (E2)
1. `tx.origin` used for authentication
2. `msg.sender == tx.origin` as EOA gate
3. `extcodesize(addr) == 0` to detect EOAs
4. EOA-only reentrancy paths
5. Airdrop / access gates equating EOA = unique human

---

## Docs

- [Threat Model](./docs/THREAT_MODEL.md)
- [Vulnerability Catalog](./docs/VULNERABILITY_CATALOG.md)

---

## License

MIT