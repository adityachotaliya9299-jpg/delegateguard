# DelegateGuard Harness Generator (Engine 3)

Auto-generates runnable Foundry test scaffolds from analyzer/scanner findings.

---

## Usage

```bash
# Generate harnesses for all findings in a contract
delegateguard harness contracts/MyDelegate.sol

# Only CRITICAL and HIGH findings
delegateguard harness contracts/ --severity CRITICAL --severity HIGH

# Only specific bug classes
delegateguard harness contracts/ --bug DC-07 --bug PA-04

# Only delegate-contract bugs (analyzer)
delegateguard harness contracts/ --mode analyze

# Custom output directory
delegateguard harness contracts/ --out audit/harnesses/
```

## What gets generated

For each finding, a `.t.sol` file containing:

- `setUp()` with 7702 simulation via `vm.etch()`
- RED tests (exploit path) pre-stubbed with TODO markers
- GREEN tests (fix verification) pre-stubbed
- Exact source file and line from the finding
- `_etch7702()` helper for delegation simulation

## Workflow

```bash
# 1. Run harness generator
delegateguard harness target-contracts/ --out harnesses/

# 2. Copy to your Foundry project
cp harnesses/*.t.sol my-audit/test/delegateguard/

# 3. Fill in the TODOs (import the contract, uncomment assertions)

# 4. Run
forge test --match-contract DC07 -vv
```

## Run tests

```bash
pytest harness/tests/ -v
```