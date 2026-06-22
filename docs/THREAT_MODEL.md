# EIP-7702 Threat Model

**Project:** DelegateGuard  
**Author:** Aditya  
**Last updated:** June 2026  
**Scope:** EIP-7702 delegate contracts, delegating EOAs, and protocols whose security model assumes callers are un-delegated EOAs.

---

## 1. Background: what EIP-7702 actually does

EIP-7702 (EIP: https://eips.ethereum.org/EIPS/eip-7702), activated with the Pectra hard fork (May 2025), introduces a new transaction type (`0x04`) that lets an EOA set its own code by signing an authorization tuple:

```
authorization = MAGIC || rlp([chain_id, address, nonce]) 
              signed with the EOA's private key
```

After a successful type-4 transaction, the EOA's code slot is set to:

```
0xef0100 || <delegate_address>  (23 bytes)
```

This is the **delegation designator**. When the EVM executes code at the EOA's address, it follows this pointer to the delegate contract and executes *in the EOA's storage context* — exactly like `DELEGATECALL`, but initiated externally.

**Key mechanics auditors must internalize:**
- The EOA remains an EOA for nonce purposes. It still signs standard transactions.
- The delegation is overwritable: a new type-4 tx from the same EOA replaces the delegate.
- `chain_id = 0` in the authorization tuple makes the signature valid on *every* EVM chain.
- During the delegated call, `msg.sender` is whoever called the EOA, and `address(this)` is the EOA itself.

---

## 2. Trust boundary collapse

Before EIP-7702, three security domains were cleanly separated:

| Domain | Pre-7702 invariant |
|--------|--------------------|
| EOA | Cannot execute arbitrary code; `EXTCODESIZE` returns 0 |
| Delegate/implementation contract | Executes in *its own* storage context |
| Protocol caller validation | `tx.origin == msg.sender` reliably meant "this is a human-controlled EOA with no code" |

EIP-7702 collapses all three. An EOA can now:
1. Have code (via delegation designator)
2. Execute that code in its own storage context
3. Be called by other contracts while *also* being a `tx.origin`

Any security invariant that relied on the separation of these domains is now potentially broken.

---

## 3. Attacker capabilities

### 3.1 Phishing / social engineering (the dominant live threat)
An attacker crafts a malicious delegate contract (the "sweeper") and tricks a user into signing an authorization tuple — often disguised as a routine approval or wallet-upgrade prompt. Once signed and broadcast:
- The attacker (or a bot) calls the EOA
- The sweeper delegate executes in the EOA's storage/context
- All assets (tokens, ETH, NFTs) that the EOA can access are drained

**Real losses:** $2.5M+ drained in August 2025 alone. One victim lost $1.54M after signing what appeared to be a swap authorization.

### 3.2 Protocol-level exploitation
An attacker interacts with a DeFi protocol *as a delegated EOA*:
- Bypasses `extcodesize == 0` checks (the EOA now has code)
- Abuses `tx.origin`-based auth (still passes because the EOA is still `tx.origin` for its own txs)
- Reenters functions that were assumed safe from EOA callers

### 3.3 Cross-chain replay
A delegate authorization signed with `chain_id = 0` is valid on every EVM chain. An attacker who obtains such a signature can replay it on any chain where the victim has assets.

### 3.4 Re-delegation storage corruption
If a user switches from DelegateA to DelegateB, and the two contracts use overlapping storage slots without ERC-7201 namespacing, the new delegate reads corrupted storage — potentially unlocking funds or bypassing access controls.

---

## 4. Vulnerability classes

### 4.1 Delegate-contract bugs (target: the delegate/implementation contract)

#### DC-01: Storage collision on re-delegation
**Mechanism:** Delegate contracts that use unnamespaced storage (raw slot numbers, inherited layout) will corrupt each other's data when an EOA switches delegates.  
**Root cause:** No use of ERC-7201 (`keccak256(abi.encode(uint256(keccak256("namespace")) - 1)) & ~0xff`) namespaced storage.  
**Impact:** Arbitrary storage corruption in the EOA's context; potential fund loss or access-control bypass.

#### DC-02: Unprotected / front-runnable initializer
**Mechanism:** Delegate contracts often need initialization (setting owner, config). If `initialize()` is not protected (or has no protection between authorization and first call), an attacker can front-run it.  
**Root cause:** Missing initializer guard (`initializing` flag), or one-tx authorization + initialization not enforced.  
**Impact:** Attacker becomes the owner of the delegated EOA's smart-account logic.

#### DC-03: Cross-chain replay via chain_id = 0
**Mechanism:** EIP-7702 allows `chain_id = 0` in the authorization tuple, making the signature chain-agnostic. If the delegate's own signature-based functions (e.g., batch executors) also fail to bind to a specific chain, signatures are replayable everywhere.  
**Root cause:** Missing `block.chainid` binding in EIP-712 domain separator, or use of `chain_id = 0` in authorization.  
**Impact:** One signed authorization drains the victim on every chain they have assets on.

#### DC-04: Missing per-call authentication
**Mechanism:** Delegate assumes it will only ever be called by "its" EOA and skips `msg.sender` checks on sensitive functions.  
**Root cause:** Developer mental model: "the EOA won't call this unless it wants to." But anyone can call the EOA externally, which triggers the delegate.  
**Impact:** Any external caller can invoke privileged delegate functions.

#### DC-05: Unsafe inner DELEGATECALL
**Mechanism:** A delegate contract that itself issues a `DELEGATECALL` to a third address compounds trust chains. The innermost callee executes in the EOA's storage context with no attestation of who authorized what.  
**Root cause:** Unconstrained `delegatecall` targets in the delegate's logic.  
**Impact:** Arbitrary code execution in the EOA's storage context; complete asset loss.

#### DC-06: Batch executor replay / nonce gaps
**Mechanism:** `BatchCallAndSponsor`-style delegates that execute multiple calls in one tx with weak nonce or replay protection. A replayed batch re-executes all sub-calls.  
**Root cause:** Non-monotonic nonces, missing domain separators, or nonce-per-target rather than global nonce.  
**Impact:** Replayed transactions drain approved amounts or re-trigger state changes.

#### DC-07: Sweeper pattern
**Mechanism:** A delegate with an `execute(address target, bytes calldata data)` function and no allowlist. The attacker calls the EOA; the delegate executes an arbitrary transfer.  
**Root cause:** No call target allowlist; no asset-transfer constraints.  
**Impact:** All assets accessible by the EOA can be drained in one call. This is the dominant live phishing exploit class.

#### DC-08: Signature malleability
**Mechanism:** Batch-and-sponsor delegates that use raw `ecrecover` (without OpenZeppelin's `ECDSA.recover`) are vulnerable to signature malleability — the same logical signature can have two valid `(v, r, s)` encodings.  
**Root cause:** Using `ecrecover` directly; not normalizing `s` to the lower half.  
**Impact:** Replay of a different encoding of a previously valid signature.

---

### 4.2 Protocol-assumption bugs (target: protocols that interact with EOAs)

#### PA-01: tx.origin authentication
**Mechanism:** `require(msg.sender == tx.origin)` was a common "is this an EOA?" check. Post-7702, a delegated EOA is still `tx.origin` for its own transactions, so this check passes even when the caller has code.  
**Root cause:** Misuse of `tx.origin` as an EOA-detection primitive.  
**Impact:** Bypasses access controls designed to exclude contracts from sensitive functions.

#### PA-02: msg.sender == tx.origin as EOA gate
**Same as PA-01** but expressed differently in code. Flagged separately because it appears in a different syntactic pattern.

#### PA-03: extcodesize == 0 as EOA check
**Mechanism:** `require(extcodesize(addr) == 0)` was used to verify a caller has no code. Post-7702, a delegated EOA has code (the delegation designator), so this check fails — or, depending on implementation, may still return non-zero unexpectedly.  
**Root cause:** `EXTCODESIZE` was a reliable EOA-detection primitive before 7702.  
**Impact:** Contracts, reentrancy guards, or access controls that relied on this check are bypassed.

#### PA-04: EOA-only reentrancy paths
**Mechanism:** Functions that skipped reentrancy guards because "EOAs can't reenter." Post-7702, a delegated EOA *can* reenter because its delegate code can call back into the protocol mid-execution.  
**Root cause:** Reentrancy guards only placed on paths expected to be called by contracts.  
**Impact:** Classic reentrancy attacks are now possible from addresses that look like EOAs. **This is underappreciated and high-value.**

#### PA-05: Airdrop / access gates equating EOA = unique human
**Mechanism:** Systems that used EOA status as a Sybil-resistance primitive (one EOA = one airdrop claim) are invalidated. A single human can now create and control many delegated EOA smart accounts.  
**Root cause:** EOA-hood was treated as proof of uniqueness.  
**Impact:** Airdrop farming, governance manipulation, access to rate-limited resources.

---

## 5. Attack surface map

```
                    ┌─────────────────────────────────┐
                    │         Attacker                │
                    └──────────────┬──────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                   │                    │
              ▼                   ▼                    ▼
   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
   │  Phishing:      │  │  Protocol       │  │  Cross-chain    │
   │  trick user     │  │  exploitation:  │  │  replay:        │
   │  into signing   │  │  call delegated │  │  reuse chain_id │
   │  bad auth tuple │  │  EOA into       │  │  = 0 sig on     │
   │                 │  │  vulnerable     │  │  other chains   │
   │  → DC-07        │  │  protocol       │  │                 │
   │  (sweeper)      │  │  → PA-01..PA-05 │  │  → DC-03        │
   └─────────────────┘  └─────────────────┘  └─────────────────┘
              │
              ▼
   ┌─────────────────┐
   │  Delegated EOA  │◄──── 0xef0100 || delegate_address
   │  (victim)       │
   └────────┬────────┘
            │ DELEGATECALL (implicit)
            ▼
   ┌─────────────────┐
   │  Delegate       │
   │  Contract       │  ← DC-01..DC-08 bugs live here
   └─────────────────┘
```

---

## 6. Out of scope

- ERC-4337 bundler/paymaster composition bugs (tracked separately; future DelegateGuard scope)
- Standard smart contract bugs unrelated to 7702 delegation mechanics
- Social engineering attacks that don't exploit the 7702 authorization mechanism

---

## 7. References

- [EIP-7702 Specification](https://eips.ethereum.org/EIPS/eip-7702)
- [Pectra Hard Fork — EIP-7702 Activation](https://ethereum.org/en/history/)
- [ERC-7201: Namespaced Storage Layout](https://eips.ethereum.org/EIPS/eip-7201)
- [OpenZeppelin ERC-7702 utilities](https://github.com/OpenZeppelin/openzeppelin-contracts)
- [MetaMask Delegation Toolkit (Cyfrin-audited)](https://github.com/MetaMask/delegation-framework)