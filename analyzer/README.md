# DelegateGuard Scanner (Engine 2)

Scans any Solidity codebase for protocol-side EOA assumptions that break
under EIP-7702 (PA-01 through PA-05).

Unlike the analyzer (which targets delegate contracts), the scanner targets
**protocols** — DeFi contracts, airdrops, governance systems — anything
that interacts with EOAs and makes assumptions about what EOAs can or cannot do.

---

## Usage

```bash
# Scan any protocol codebase
delegateguard scan contracts/

# Scan a specific file
delegateguard scan contracts/Pool.sol

# Output JSON report
delegateguard scan contracts/ --json --out scan-report.json

# Filter severity
delegateguard scan contracts/ --severity CRITICAL HIGH
```

## Detectors

| ID | Detector | Severity |
|----|----------|----------|
| PA-01 | tx.origin used for authentication | HIGH |
| PA-02 | msg.sender == tx.origin EOA gate | HIGH |
| PA-03 | extcodesize == 0 EOA check | HIGH |
| PA-04 | EOA-only reentrancy paths | CRITICAL |
| PA-05 | EOA = unique human assumption | MEDIUM |

## Run tests

```bash
pytest scanner/tests/ -v
```