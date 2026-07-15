# DelegateGuard — Detection Limitations

DelegateGuard's analyzer and scanner are **heuristic static-analysis tools**. They
flag *candidates* for human review, not confirmed exploits. This document is
deliberately explicit about where the heuristics stop — audit firms and protocol
teams trust a tool more when its author is upfront about the boundaries.

If you are relying on DelegateGuard as part of a security process, read this first.

---

## Guarantees we do and don't make

- **A finding is a candidate, not a verdict.** Every finding ships with a Foundry
  proof-of-concept reference so a reviewer can confirm or dismiss it. Treat an
  unreviewed finding as "worth ten minutes," not "confirmed vulnerability."
- **Absence of findings is not a proof of safety.** A clean scan means none of the
  implemented heuristics matched. It does not mean the contract is safe, and it
  never substitutes for a manual audit.
- **Severity is worst-case.** Severities assume a post-Pectra threat model where any
  EOA may execute arbitrary delegate code. A finding's real-world severity depends
  on deployment context the tool cannot see.

---

## Per-detector boundaries

### Delegate-contract detectors (E1, DC-01 … DC-08)

| ID | Known false-negative / false-positive boundary |
|----|-----------------------------------------------|
| **DC-01** Storage collision | Detects raw state variables outside an ERC-7201 layout. Recognizes the common `*_STORAGE_SLOT` / `*_LOCATION` naming conventions for namespaced slots; **projects that hand-roll assembly slot math with an unconventional constant name may be flagged as a false positive.** Teach it your convention via the detector config (see below). |
| **DC-02** Unprotected initializer | Flags externally reachable `initialize()`-style functions with no caller check. **Does not model initializers protected indirectly** (e.g. a modifier that reads an external registry) and may false-positive on those. |
| **DC-03** Cross-chain replay | Flags EIP-712 domain separators built without `block.chainid`. Catches inline `block.chainid` use and chainid stored in a state-variable initializer. **A chainid cached in the constructor body and only *conditionally* re-mixed into the separator (fork-recovery patterns) can still slip through** — this is the primary DC-03 false-negative and is on the Phase 7 roadmap. |
| **DC-04** Missing per-call auth | Flags public/external state-changing functions with no `msg.sender` / signature check. **View/pure functions and functions guarded by an unrecognized custom modifier** may be misclassified in either direction. |
| **DC-05** Unsafe inner delegatecall | Flags `delegatecall` to a target not validated against an allowlist. Recognizes common allowlist keywords (`allow*`, `approved*`, `whitelist*`, `trusted*`). **An allowlist stored under an unconventional name may cause a false positive**; extend the keyword set via config. |
| **DC-06** Batch replay / nonce gaps | Flags signed-struct layouts missing a global nonce or deadline. **Cannot always distinguish a per-target nonce that is nonetheless globally unique** by construction. |
| **DC-07** Sweeper pattern | Matches the shape *arbitrary external call + no auth + no allowlist*. High precision on the in-the-wild sweeper family; **a heavily obfuscated or proxied sweeper may not match the source-level shape** (the on-chain monitor's bytecode scoring is the backstop for those). |
| **DC-08** Signature malleability | Flags raw `ecrecover` and signature-bytes-based replay guards. **Does not flag `ecrecover` wrapped in an unrecognized helper** that already enforces low-s. |

### Protocol-assumption detectors (E2, PA-01 … PA-05)

| ID | Known boundary |
|----|----------------|
| **PA-01** `tx.origin` auth | Flags `tx.origin` in comparisons. **Cannot always tell an auth comparison from a benign telemetry/logging read**, so a non-security `tx.origin` use may be flagged (strict mode raises these, heuristic mode is more conservative). |
| **PA-02** `msg.sender == tx.origin` gate | Flags the EOA-only gate pattern. **Does not evaluate whether a compensating control** (rate limit, oracle) makes the gate non-load-bearing. |
| **PA-03** `extcodesize` EOA check | Flags `extcodesize` / `address.code.length` used as a caller-type gate. **Legitimate size checks unrelated to caller classification** may be flagged. |
| **PA-04** EOA-only reentrancy | Cross-references CEI violations with EOA-gated paths. **Reentrancy reachability is approximated from the call graph**; deep cross-contract paths may be missed. |
| **PA-05** EOA = unique human | Flags one-per-address gates relying on EOA classification. **Cannot see off-chain Sybil resistance** (KYC, proof-of-personhood) that may already mitigate the issue. |

---

## `--strict` vs `--heuristic` (roadmap)

Detectors that trade precision for recall (notably PA-01) are being split behind an
explicit mode:

- `--heuristic` (default) — conservative: fewer false positives, may miss edge cases.
- `--strict` — aggressive: surfaces every candidate, including ambiguous ones, for a
  reviewer to triage. Recommended for a formal audit pass.

Until this ships, assume the current behavior is the conservative `--heuristic` set.

---

## Detector configuration (roadmap)

Naming-convention false positives (DC-01 slot constants, DC-05 allowlist names) will
be teachable via a `delegateguard.toml` at the project root:

```toml
[dc01]
# extra constant-name patterns that indicate a namespaced storage slot
slot_constants = ["MY_STORAGE_POSITION", "_layout"]

[dc05]
# extra state-variable names that count as a delegatecall allowlist
allowlist_names = ["approvedModules", "trustedImpls"]
```

---

## On-chain monitor (E4)

- **Registry classifications are seeded and community-updatable.** A delegate marked
  `unknown` simply has not been classified yet — it is not an assertion of safety.
- **Bytecode risk scoring is a heuristic**, not disassembly-level proof. A high score
  means "resembles known-bad shapes," not "confirmed malicious."
- **Malicious-address entries are sourced from public incident reporting.** They are
  labelled with their source and the campaign they were observed in. Always
  cross-check against a block explorer before acting on a live classification.

---

## Reporting a gap

Found a false positive or a missed case? That is exactly the feedback that improves
the detectors. Open an issue with a minimal Solidity repro and the expected result.
The Phase 7 hardening pass is prioritized by real-world reports over theoretical ones.
