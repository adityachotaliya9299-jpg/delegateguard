import type { DelegateTag } from "./registry";

export interface FeedEvent {
  id: number;
  kind: "delegation" | "revocation" | "alert";
  eoa: string;
  delegate: string;
  delegateLabel: string;
  tag: DelegateTag;
  chain: string;
  block: number;
  alertRule?: string;
}

const HEX = "0123456789abcdef";

function addr(rng: () => number) {
  let s = "0x";
  for (let i = 0; i < 40; i++) s += HEX[Math.floor(rng() * 16)];
  return s;
}

// deterministic-ish PRNG so the stream feels alive but stable per session
export function mulberry32(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const KNOWN: { delegate: string; label: string; tag: DelegateTag; weight: number }[] = [
  { delegate: "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b", label: "MetaMask Delegator", tag: "SAFE", weight: 42 },
  { delegate: "0x40aa958dd87fc8305b97f2ba922cddca374bcd7f", label: "Coinbase SW delegate", tag: "SAFE", weight: 26 },
  { delegate: "0xe25a0499f7ac0e475b0f7a1bde527ff431a68b45", label: "Ambire Batcher v2", tag: "SAFE", weight: 12 },
  { delegate: "0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b", label: "CrimeEnjoyor sweeper", tag: "MALICIOUS", weight: 5 },
  { delegate: "0x1d96f2f6bef1202e4ce1ff6dad0c2cb002861d3e", label: "Fresh delegate (2h)", tag: "SUSPICIOUS", weight: 7 },
  { delegate: "0xf19308f923582a6f7c465e5ce7a9dc1bec6665b1", label: "Unverified plugin router", tag: "SUSPICIOUS", weight: 4 },
];

const CHAINS = ["Ethereum", "Base", "Arbitrum", "Optimism"];

const ALERT_RULES: Record<string, string> = {
  MALICIOUS: "RULE-1 · registry hit: known-malicious delegate",
  SUSPICIOUS: "RULE-4 · campaign heuristic: EOA velocity threshold",
};

export function nextEvent(rng: () => number, id: number, baseBlock: number): FeedEvent {
  const roll = rng() * 100;
  let acc = 0;
  let pick = KNOWN[0];
  for (const k of KNOWN) {
    acc += k.weight;
    if (roll < acc) { pick = k; break; }
  }
  // the remainder of the distribution is unknown one-off delegates
  const unknown = roll >= acc;
  const tag: DelegateTag = unknown ? "UNKNOWN" : pick.tag;
  const revoke = rng() < 0.08;
  const bad = tag === "MALICIOUS" || (tag === "SUSPICIOUS" && rng() < 0.5);

  return {
    id,
    kind: revoke ? "revocation" : bad ? "alert" : "delegation",
    eoa: addr(rng),
    delegate: unknown ? addr(rng) : pick.delegate,
    delegateLabel: unknown ? "unregistered bytecode" : pick.label,
    tag: revoke ? "SAFE" : tag,
    chain: CHAINS[Math.floor(rng() * CHAINS.length)],
    block: baseBlock + Math.floor(id / 3),
    alertRule: bad && !revoke ? ALERT_RULES[tag] : undefined,
  };
}

export const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;
