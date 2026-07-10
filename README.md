# DelegateGuard

**Security analysis toolkit for EIP-7702 delegate contracts and post-Pectra protocol assumptions.**

DelegateGuard is the only tool doing **code-level security analysis** — not just visibility — of the EIP-7702 attack surface. While every other 7702 tool answers "has this address been delegated, and to what?", DelegateGuard answers: **"is this delegate contract, or this protocol, actually safe in a post-Pectra world?"**

Built solo, from scratch, across 6 phases — 137 tests, all passing.

---

## Why This Exists

EIP-7702 shipped with the Pectra hard fork in May 2025. It lets any EOA set its code slot to `0xef0100 || delegate_address`, making it execute a delegate contract's logic in the EOA's own storage context — like `DELEGATECALL`, but initiated externally.

This collapsed three previously separate security domains into one attack surface: **wallet code, delegate contracts, and protocol-side EOA assumptions.** Phishing crews industrialized the attack immediately — sweeper delegate contracts drained over **$2.5M in August 2025 alone**, with one victim losing $1.54M in a single transaction.

Every major audit firm advertises 7702 audit services. The tooling to back it up is nearly empty. DelegateGuard fills that gap.

---

## Architecture

Four engines, three languages, six phases:

```
delegateguard/
├── lab/        → Solidity      Phase 1  — vulnerability proofs (Foundry PoC tests)
├── analyzer/   → Python        Phase 2  — delegate-contract static analyzer (E1)
├── scanner/    → Python        Phase 3  — protocol-assumption scanner (E2)
├── harness/    → Python        Phase 4  — Foundry harness generator (E3)
├── dashboard/  → TypeScript    Phase 5  — landing page + scan dashboard (Next.js 14)
├── monitor/    → Python        Phase 6  — on-chain delegation monitor (E4)
└── docs/       → Markdown               — threat model, vulnerability catalog
```

- **Solidity** for vulnerability proofs — they run on the EVM.
- **Python** for the analysis engines — [Slither](https://github.com/crytic/slither), the industry-standard static analyzer, is Python.
- **TypeScript / Next.js** for the visible product — the right tool for a web dashboard.

---

## Bug Class Coverage

### Delegate Contract Bugs (DC-01 → DC-08)

| ID | Name | Severity |
|----|------|----------|
| DC-01 | Storage Collision on Re-delegation | HIGH |
| DC-02 | Unprotected Initializer | HIGH |
| DC-03 | Cross-Chain Replay via `chain_id=0` | CRITICAL |
| DC-04 | Missing Per-Call Authentication | HIGH |
| DC-05 | Unsafe Inner `DELEGATECALL` | CRITICAL |
| DC-06 | Batch Executor Replay / Nonce Gaps | HIGH |
| DC-07 | Sweeper Pattern | CRITICAL |
| DC-08 | Signature Malleability | MEDIUM |

### Protocol Assumption Bugs (PA-01 → PA-05)

| ID | Name | Severity |
|----|------|----------|
| PA-01 | `tx.origin` Authentication | HIGH |
| PA-02 | `msg.sender == tx.origin` EOA Gate | HIGH |
| PA-03 | `extcodesize == 0` EOA Check | HIGH |
| PA-04 | EOA-Only Reentrancy Paths | CRITICAL |
| PA-05 | EOA = Unique Human Assumption | MEDIUM |

Full writeups — root cause, exploit path, and fix — for every class live in [`docs/`](./docs).

---

## Quick Start

```bash
# Install
pip install -e .

# Analyze delegate contracts (DC-01..DC-08)
delegateguard analyze <target>

# Scan any protocol for broken EOA assumptions (PA-01..PA-05)
delegateguard scan <target>

# Generate ready-to-run Foundry harness scaffolds from findings
delegateguard harness <target> --out harnesses/

# Monitor live on-chain delegations
delegateguard monitor --rpc <URL>
```

---

## The Four Engines

### 🧪 Phase 1 — Vulnerability Lab (`lab/`)
- 11 vulnerable contracts, 10 fixed contracts, 13 test files
- **51 Foundry tests, all passing** — RED tests prove the exploit, GREEN tests prove the fix
- Uses `vm.etch()` to simulate EIP-7702 delegation without a real type-4 transaction

### 🔍 Phase 2 — Delegate Analyzer (`analyzer/`) — Engine 1
```bash
delegateguard analyze <target> [--severity CRITICAL] [--json] [--out report.json]
```
- 8 Slither-based detector modules, one per DC bug class
- **15 pytest tests, all passing**
- 41 findings on the lab, with exact `file:line` locations

### 🛰️ Phase 3 — Protocol Scanner (`scanner/`) — Engine 2
```bash
delegateguard scan <target> [--severity CRITICAL] [--json] [--out scan.json]
```
- 5 detector modules, one per PA bug class
- **14 pytest tests, all passing**
- 17 findings on the lab, including cross-fire detection (e.g. a delegate flagged for both DC-03 and a real PA-04 CEI violation)

### 🛠️ Phase 4 — Harness Generator (`harness/`) — Engine 3
```bash
delegateguard harness <target> --out harnesses/ [--bug DC-07] [--mode analyze|scan|both]
```
- Turns findings into ready-to-compile Foundry test scaffolds
- 13 templates, one per bug class, with pre-stubbed RED/GREEN tests and TODO markers
- **21 pytest tests, all passing**

### 📊 Phase 5 — Dashboard (`dashboard/`)
- Next.js 14 App Router, TypeScript, Tailwind CSS
- Landing page with an animated EIP-7702 delegation designator hero
- `/dashboard` — scan config, live progress, findings table (filterable by severity and bug class), Markdown/JSON export
- One-command deploy to Vercel

### 📡 Phase 6 — On-Chain Monitor (`monitor/`) — Engine 4
```bash
delegateguard monitor --rpc <URL> [--chain 1] [--check 0x...] [--start-block N]
```
- Polls for live type-4 (`0x4`) transactions, parses `authorizationList`
- Classifies delegates against a seeded registry (known-safe, known-malicious, suspicious)
- Bytecode-based risk scoring for unknown delegates
- 6-rule alert engine (malicious registry hit, `chain_id=0` replay risk, phishing campaign detection via EOA-count threshold, and more)
- **36 pytest tests, all passing**
- One-shot mode (`--check 0x...`) for pre-signature checks or CI integration

---

## Test Coverage

| Layer | Framework | Count | Status |
|---|---|---|---|
| Foundry vulnerability PoCs (Phase 1) | Forge | 51 | ✅ All passing |
| Analyzer detectors (Phase 2) | pytest | 15 | ✅ All passing |
| Scanner detectors (Phase 3) | pytest | 14 | ✅ All passing |
| Harness generator (Phase 4) | pytest | 21 | ✅ All passing |
| Monitor components (Phase 6) | pytest | 36 | ✅ All passing |
| **Total** | | **137** | ✅ **All passing** |

Run everything:
```bash
pytest analyzer/tests/ scanner/tests/ harness/tests/ monitor/tests/ -v
cd lab && forge test -vv
```

---

## Full CLI Reference

```bash
# Analyze delegate contracts
delegateguard analyze <target>
delegateguard analyze <target> --severity CRITICAL --severity HIGH
delegateguard analyze <target> --json --out report.json
delegateguard analyze <target> --solc /path/to/solc

# Scan any protocol
delegateguard scan <target>
delegateguard scan <target> --severity CRITICAL --severity HIGH --severity MEDIUM
delegateguard scan <target> --json --out scan.json

# Generate Foundry harness scaffolds
delegateguard harness <target>
delegateguard harness <target> --out harnesses/ --severity CRITICAL
delegateguard harness <target> --bug DC-07 --bug PA-04
delegateguard harness <target> --mode analyze   # DC only
delegateguard harness <target> --mode scan      # PA only

# Monitor on-chain delegations
delegateguard monitor --rpc <URL>
delegateguard monitor --rpc <URL> --chain 11155111   # Sepolia
delegateguard monitor --rpc <URL> --start-block 21000000
delegateguard monitor --rpc <URL> --check 0xDEAD...  # one-shot
delegateguard monitor --rpc <URL> --registry-path /data/registry.json
delegateguard monitor --rpc <URL> --verbose
```

---

## Who This Is For

- **Wallet teams** shipping delegate contracts — need DC-01..DC-08 coverage
- **Paymaster / AA-infrastructure providers** — interact directly with delegated EOAs
- **DeFi protocols** accepting EOA calls under old assumptions — need PA-01..PA-05 coverage

## Services

The CLI is open source and free to run. Beyond the tool:
- Scoped EIP-7702 security audits
- CI tier — GitHub Action wrapping the CLI for continuous scanning
- Monitoring retainer — ongoing on-chain delegation monitoring for a protocol's EOA user base

Get in touch via GitHub Issues or the contact link on the [dashboard](#).

---

## Docs

Threat model and full vulnerability catalog: [`docs/`](./docs)

---

## License

MIT (or update as appropriate)

---

*Built by [Aditya](https://github.com/adityachotaliya9299-jpg) — solo, across all 6 phases.*