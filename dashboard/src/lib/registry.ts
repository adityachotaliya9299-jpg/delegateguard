export type DelegateTag = "SAFE" | "MALICIOUS" | "SUSPICIOUS" | "UNKNOWN";

export interface DelegateRecord {
  address: string;
  label: string;
  tag: DelegateTag;
  eoaCount: number;
  firstSeen: string;
  lastSeen: string;
  chains: string[];
  bytecodeHash: string;
  riskNotes: string;
  drained?: string;
}

// Seeded intelligence records. In production this is the persisted output of
// the Phase 6 monitor; here it mirrors the registry.json shape the CLI ships.
export const REGISTRY: DelegateRecord[] = [
  {
    address: "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b",
    label: "MetaMask EIP-7702 Delegator",
    tag: "SAFE",
    eoaCount: 148_211,
    firstSeen: "2025-05-07",
    lastSeen: "2026-07-12",
    chains: ["Ethereum", "Base", "Arbitrum", "Optimism"],
    bytecodeHash: "0x8c1f…a2e4",
    riskNotes: "Audited delegator with per-call auth, namespaced storage, and chain-bound signatures. Reference implementation for DC-01/DC-03/DC-04 compliance.",
  },
  {
    address: "0xe25a0499f7ac0e475b0f7a1bde527ff431a68b45",
    label: "Ambire Batcher v2",
    tag: "SAFE",
    eoaCount: 31_904,
    firstSeen: "2025-05-19",
    lastSeen: "2026-07-13",
    chains: ["Ethereum", "Base", "Polygon"],
    bytecodeHash: "0x22b7…91cd",
    riskNotes: "Global-nonce batch executor with signed deadlines. Clean DC-06 profile.",
  },
  {
    address: "0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b",
    label: "CrimeEnjoyor sweeper family",
    tag: "MALICIOUS",
    eoaCount: 2_713,
    firstSeen: "2025-06-02",
    lastSeen: "2026-07-14",
    chains: ["Ethereum", "BSC"],
    bytecodeHash: "0xdead…7702",
    riskNotes: "Textbook DC-07: execute() with arbitrary call, no auth, no allowlist. Deployed by phishing kit; delegations spike within minutes of signature-drainer campaigns.",
    drained: "$1.54M (single largest tx)",
  },
  {
    address: "0x7a4e2f3ccd9a91c68d94b7cf5e17c4a09f3b1290",
    label: "Sweeper variant — batch drain",
    tag: "MALICIOUS",
    eoaCount: 1_186,
    firstSeen: "2025-08-04",
    lastSeen: "2026-06-30",
    chains: ["Ethereum"],
    bytecodeHash: "0x51ac…0be9",
    riskNotes: "DC-07 + DC-03: sweeper with chain_id=0 authorizations, replayable across every EVM chain the victim holds funds on.",
    drained: "$2.5M+ (Aug 2025 campaign)",
  },
  {
    address: "0xf19308f923582a6f7c465e5ce7a9dc1bec6665b1",
    label: "Unverified plugin router",
    tag: "SUSPICIOUS",
    eoaCount: 412,
    firstSeen: "2026-03-11",
    lastSeen: "2026-07-14",
    chains: ["Base"],
    bytecodeHash: "0x9c30…44f7",
    riskNotes: "Inner DELEGATECALL with no visible allowlist (DC-05 shape). Source unverified; EOA count growing ~8%/week. Monitoring.",
  },
  {
    address: "0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e",
    label: "Fresh delegate — 2h old",
    tag: "SUSPICIOUS",
    eoaCount: 267,
    firstSeen: "2026-07-14",
    lastSeen: "2026-07-14",
    chains: ["Ethereum"],
    bytecodeHash: "0x03e8…c1aa",
    riskNotes: "Alert rule 4 fired: new bytecode, 267 EOAs delegated within two hours of deployment. Pattern consistent with an active phishing campaign.",
  },
  {
    address: "0xab5801a7d398351b8be11c439e05c5b3259aec9b",
    label: "Unlabeled batch helper",
    tag: "UNKNOWN",
    eoaCount: 89,
    firstSeen: "2026-05-22",
    lastSeen: "2026-07-10",
    chains: ["Arbitrum"],
    bytecodeHash: "0x7731…d05f",
    riskNotes: "Bytecode risk score 41/100 — has auth checks but per-target nonces (possible DC-06). Awaiting source verification.",
  },
  {
    address: "0x40aa958dd87fc8305b97f2ba922cddca374bcd7f",
    label: "Coinbase Smart Wallet delegate",
    tag: "SAFE",
    eoaCount: 96_530,
    firstSeen: "2025-05-08",
    lastSeen: "2026-07-13",
    chains: ["Base", "Ethereum"],
    bytecodeHash: "0x1b2f…88ce",
    riskNotes: "Audited. ERC-7201 storage, deadline-bound signatures, allowlisted modules.",
  },
];

export function tagCounts() {
  const out: Record<DelegateTag, number> = { SAFE: 0, MALICIOUS: 0, SUSPICIOUS: 0, UNKNOWN: 0 };
  for (const r of REGISTRY) out[r.tag] += 1;
  return out;
}
