import type { BugClass, Severity } from "./types";

export interface BugEntry {
  id: BugClass;
  name: string;
  severity: Severity;
  family: "DC" | "PA";
  oneLiner: string;
  rootCause: string;
  exploitPath: string[];
  fix: string;
  detector: string;
  poc: string;
  seenInWild?: string;
}

export const CATALOG: BugEntry[] = [
  {
    id: "DC-01",
    name: "Storage Collision on Re-delegation",
    severity: "HIGH",
    family: "DC",
    oneLiner: "Two delegates, one EOA storage space. Raw slots collide when the user switches delegates.",
    rootCause:
      "EIP-7702 delegates execute in the EOA's own storage context. A delegate that declares state variables at raw slots (slot 0, 1, 2…) will read and write whatever the previous delegate left there. Switching delegates does not clear storage.",
    exploitPath: [
      "User delegates to WalletV1, which stores `owner` at slot 0",
      "User later re-delegates to WalletV2, which stores `paused` (bool) at slot 0",
      "Old owner address is now interpreted as a non-zero bool — contract is permanently 'paused', or worse, an attacker-controlled value becomes a privileged address",
    ],
    fix: "Use ERC-7201 namespaced storage: derive a unique slot from a namespace hash and access state through it, so no two delegates can collide.",
    detector: "Flags any state variable declared outside an ERC-7201 namespaced layout in a delegate contract.",
    poc: "lab/test/DC01_StorageCollision.t.sol",
  },
  {
    id: "DC-02",
    name: "Unprotected Initializer",
    severity: "HIGH",
    family: "DC",
    oneLiner: "Anyone can call initialize() on a freshly delegated EOA before the owner does.",
    rootCause:
      "Delegation and initialization are two separate transactions. Between them, the delegate's `initialize()` is callable by anyone — and it usually assigns ownership.",
    exploitPath: [
      "Victim signs an EIP-7702 authorization for a wallet delegate",
      "Attacker watches the mempool for the type-4 transaction",
      "Attacker front-runs the victim's `initialize()` call with their own, becoming `owner` of the victim's account",
    ],
    fix: "Require that the initializer can only be executed by the account itself (msg.sender == address(this)) or bundle initialization atomically with the authorization.",
    detector: "Finds externally callable initializers with no caller check in delegate contracts.",
    poc: "lab/test/DC02_InitFrontrun.t.sol",
  },
  {
    id: "DC-03",
    name: "Cross-Chain Replay via chain_id = 0",
    severity: "CRITICAL",
    family: "DC",
    oneLiner: "An authorization signed with chain_id 0 is valid on every EVM chain at once.",
    rootCause:
      "EIP-7702 explicitly allows `chain_id = 0` in the authorization tuple as a wildcard. A delegate whose signatures also omit `block.chainid` from its EIP-712 domain compounds this: one signature, every chain.",
    exploitPath: [
      "Victim signs a batch-execution payload on mainnet; domain separator has no chainid",
      "Attacker replays the identical signature on Base, Arbitrum, Optimism…",
      "Every chain where the victim has funds executes the same drain",
    ],
    fix: "Include `block.chainid` in every domain separator, and never sign delegate authorizations with chain_id 0 unless multi-chain execution is the explicit intent.",
    detector: "Detects domain separators built without chainid — including cached-in-constructor patterns, not just missing `block.chainid` literals.",
    poc: "lab/test/DC03_CrossChainReplay.t.sol",
  },
  {
    id: "DC-04",
    name: "Missing Per-Call Authentication",
    severity: "HIGH",
    family: "DC",
    oneLiner: "State-changing delegate functions with no msg.sender check — anyone can drive the account.",
    rootCause:
      "Delegate authors assume only the EOA owner will call the delegate's functions. But once delegated, the code is reachable by any external caller at the EOA's address.",
    exploitPath: [
      "Delegate exposes `transferETH(address,uint256)` with no auth",
      "Attacker calls it directly on the delegated EOA address",
      "Funds move; no signature from the owner was ever required",
    ],
    fix: "Every state-changing entry point needs an explicit owner check or signature validation. There is no implicit caller trust in a delegate.",
    detector: "Flags public/external state-changing functions in delegates that lack any authentication path.",
    poc: "lab/test/DC04_MissingAuth.t.sol",
  },
  {
    id: "DC-05",
    name: "Unsafe Inner DELEGATECALL",
    severity: "CRITICAL",
    family: "DC",
    oneLiner: "A delegatecall to an unconstrained target hands the whole account to whoever supplies the address.",
    rootCause:
      "Plugin-style delegates forward execution via an inner DELEGATECALL. Without an allowlist, the 'plugin' parameter is an arbitrary-code-execution primitive running in the EOA's storage context.",
    exploitPath: [
      "Delegate exposes `executePlugin(address plugin, bytes data)`",
      "Attacker passes a contract that rewrites owner storage and sweeps assets",
      "The inner delegatecall executes it with full authority over the EOA",
    ],
    fix: "Maintain an explicit allowlist of approved plugin targets and check it before every inner delegatecall.",
    detector: "Traces delegatecall targets through the CFG; flags any target not validated against storage-held allowlists.",
    poc: "lab/test/DC05_InnerDelegatecall.t.sol",
  },
  {
    id: "DC-06",
    name: "Batch Executor Replay / Nonce Gaps",
    severity: "HIGH",
    family: "DC",
    oneLiner: "Per-target nonces and missing deadlines let old signatures execute again.",
    rootCause:
      "Batch executors that scope nonces per target (instead of one global nonce) or omit deadlines allow a signature authorized for one context to be replayed in another.",
    exploitPath: [
      "Victim signs a call for target A at nonce 0",
      "Attacker replays the same signature against target B — its nonce counter is also 0",
      "Stale approvals resurrect months later because nothing ever expires",
    ],
    fix: "One global monotonic nonce per account plus a signed deadline checked against block.timestamp.",
    detector: "Checks signed-struct layouts for global nonce and deadline fields; flags per-target nonce maps.",
    poc: "lab/test/DC06_BatchReplay.t.sol",
  },
  {
    id: "DC-07",
    name: "Sweeper Pattern",
    severity: "CRITICAL",
    family: "DC",
    oneLiner: "The weaponized delegate: arbitrary external calls, zero checks, built to drain.",
    rootCause:
      "The dominant in-the-wild abuse of EIP-7702. Phishing crews get victims to sign an authorization for a 'sweeper' delegate — an execute() that makes arbitrary calls with no authentication and no target restrictions.",
    exploitPath: [
      "Victim signs what looks like a routine wallet-upgrade authorization",
      "The delegate is a sweeper; attacker calls execute() on the victim's address",
      "ETH and every approved token leave in one transaction",
    ],
    fix: "From the defense side: pre-signature delegate inspection. From the protocol side: never assume a delegated EOA acts on its owner's intent.",
    detector: "Matches the sweeper shape — arbitrary call + no auth + no allowlist — in any candidate delegate bytecode or source.",
    poc: "lab/test/DC07_Sweeper.t.sol",
    seenInWild: "Sweeper delegates drained over $2.5M in August 2025 alone; one victim lost $1.54M in a single transaction.",
  },
  {
    id: "DC-08",
    name: "Signature Malleability",
    severity: "MEDIUM",
    family: "DC",
    oneLiner: "ecrecover accepts two valid encodings of every signature — replay protection built on sig hashes breaks.",
    rootCause:
      "Delegates that use raw `ecrecover` without enforcing the low-s form, or that key replay protection on the signature bytes rather than a nonce, can have 'used' signatures transformed into fresh ones.",
    exploitPath: [
      "Delegate marks signatures as used by hashing the (v,r,s) bytes",
      "Attacker flips s to the curve-order complement — same signer, different bytes",
      "The 'new' signature passes the used-check and executes again",
    ],
    fix: "Use OpenZeppelin ECDSA (enforces canonical s), and key replay protection on nonces, never on signature bytes.",
    detector: "Flags raw ecrecover use and signature-hash-based replay guards.",
    poc: "lab/test/DC08_SigMalleability.t.sol",
  },
  {
    id: "PA-01",
    name: "tx.origin Authentication",
    severity: "HIGH",
    family: "PA",
    oneLiner: "tx.origin auth was always fragile. Post-7702, a delegated EOA makes it a self-service exploit.",
    rootCause:
      "Protocols using `tx.origin` for auth assume the transaction originator is a human at a wallet. A delegated EOA executes attacker-authored code while keeping its tx.origin identity.",
    exploitPath: [
      "Protocol checks `tx.origin == owner` on withdraw",
      "Owner's EOA is phished into delegating to a malicious contract",
      "Any call the delegate makes into the protocol passes the check — the attacker withdraws as the owner",
    ],
    fix: "Replace tx.origin with msg.sender everywhere authentication is intended.",
    detector: "Flags tx.origin in any comparison used for authorization.",
    poc: "lab/test/PA01_TxOrigin.t.sol",
  },
  {
    id: "PA-02",
    name: "msg.sender == tx.origin EOA Gate",
    severity: "HIGH",
    family: "PA",
    oneLiner: "The classic 'no contracts allowed' gate no longer means what it used to.",
    rootCause:
      "`msg.sender == tx.origin` used to guarantee the caller was a plain EOA with no code. A delegated EOA still satisfies it — while executing arbitrary contract logic mid-call.",
    exploitPath: [
      "Protocol gates a flash-loan-sensitive function with msg.sender == tx.origin",
      "Attacker routes the call through a delegated EOA",
      "The gate passes; the 'EOA' is running attack logic with callbacks",
    ],
    fix: "Stop treating EOA-ness as a security boundary. Use reentrancy guards, oracles, and rate limits that hold for contract callers.",
    detector: "Finds msg.sender == tx.origin comparisons guarding state-changing paths.",
    poc: "lab/test/PA02_SenderOriginGate.t.sol",
  },
  {
    id: "PA-03",
    name: "extcodesize == 0 EOA Check",
    severity: "HIGH",
    family: "PA",
    oneLiner: "Delegated EOAs carry a 23-byte code slot — every extcodesize gate now misfires.",
    rootCause:
      "Post-Pectra, a delegated EOA's code slot holds the 0xef0100‖address designator (23 bytes). Checks in both directions break: 'no code' no longer implies safe, and legitimate delegated users fail 'EOA-only' gates.",
    exploitPath: [
      "Protocol treats extcodesize == 0 callers as reentrancy-safe humans",
      "A delegated EOA has code but can also be msg.sender via its delegate",
      "Either the gate locks out real users, or attack logic slips past the 'human' assumption",
    ],
    fix: "Remove extcodesize-based caller classification entirely. Use universal reentrancy guards with no EOA carve-outs.",
    detector: "Flags extcodesize/address.code.length caller checks used as security gates.",
    poc: "lab/test/PA03_ExtcodeSize.t.sol",
  },
  {
    id: "PA-04",
    name: "EOA-Only Reentrancy Paths",
    severity: "CRITICAL",
    family: "PA",
    oneLiner: "CEI violations 'protected' by an EOA check are naked once EOAs can have receive() hooks.",
    rootCause:
      "Some protocols skip reentrancy guards on paths they believe only EOAs can reach. A delegated EOA has a receive() hook — the mid-call control transfer those paths were never designed for.",
    exploitPath: [
      "LendingPool.withdraw() sends ETH before zeroing the balance, guarded only by an EOA gate",
      "Delegated EOA's receive() re-enters withdraw() during the transfer",
      "Balance is drained N times before state is written once",
    ],
    fix: "Universal nonReentrant modifiers and strict checks-effects-interactions on every external-call path — no caller-type exemptions.",
    detector: "Cross-references CEI violations with EOA-gated call paths in the CFG.",
    poc: "lab/test/PA04_EOAReentrancy.t.sol",
  },
  {
    id: "PA-05",
    name: "EOA = Unique Human Assumption",
    severity: "MEDIUM",
    family: "PA",
    oneLiner: "One-per-address logic assumed addresses were expensive to operate. Delegation made them programmable.",
    rootCause:
      "Airdrops, mints, and rate limits that use 'one EOA = one human' as Sybil resistance. Delegation lets one operator drive thousands of EOAs through identical contract logic, cheaply and atomically.",
    exploitPath: [
      "Airdrop allows one claim per EOA, gated by an EOA check",
      "Operator generates a farm of EOAs, delegates them all to one claim contract",
      "One transaction batch claims N allocations",
    ],
    fix: "Real Sybil resistance: Merkle allowlists from historical state, proof-of-personhood, or per-identity attestations — not address-shape checks.",
    detector: "Flags one-per-address gates that rely on EOA classification.",
    poc: "lab/test/PA05_EOAUniqueness.t.sol",
  },
];

export const DC_ENTRIES = CATALOG.filter((b) => b.family === "DC");
export const PA_ENTRIES = CATALOG.filter((b) => b.family === "PA");
