export interface ProtocolRow {
  rank: number;
  name: string;
  category: string;
  score: number;
  criticals: number;
  highs: number;
  mediums: number;
  trend: "up" | "down" | "flat";
  lastScan: string;
  note: string;
}

// Sample leaderboard data. Names are placeholders — the public board ranks
// protocols that opted in to publishing their scan results. Scores come from
// the same deduction model the scanner uses (see lib/score.ts).
export const LEADERBOARD: ProtocolRow[] = [
  { rank: 1, name: "Northbeam Vaults", category: "Yield", score: 98, criticals: 0, highs: 0, mediums: 1, trend: "flat", lastScan: "2026-07-11", note: "Universal reentrancy guards, no EOA gates anywhere in the call graph." },
  { rank: 2, name: "Kestrel Swap", category: "DEX", score: 95, criticals: 0, highs: 0, mediums: 2, trend: "up", lastScan: "2026-07-09", note: "Removed extcodesize checks in v3.1 after a PA-03 report." },
  { rank: 3, name: "Ledgerline", category: "Lending", score: 93, criticals: 0, highs: 1, mediums: 0, trend: "up", lastScan: "2026-07-12", note: "One tx.origin telemetry path — not auth-bearing, still flagged by strict mode." },
  { rank: 4, name: "Palisade Staking", category: "Restaking", score: 88, criticals: 0, highs: 1, mediums: 1, trend: "flat", lastScan: "2026-07-08", note: "PA-02 gate on a keeper path; compensating rate limit present." },
  { rank: 5, name: "Fenwick Perps", category: "Perpetuals", score: 84, criticals: 0, highs: 2, mediums: 0, trend: "down", lastScan: "2026-07-13", note: "New gauge contract reintroduced a msg.sender == tx.origin check." },
  { rank: 6, name: "Cairn Rewards", category: "Incentives", score: 71, criticals: 0, highs: 2, mediums: 3, trend: "flat", lastScan: "2026-07-05", note: "Multiple PA-05 one-per-address assumptions in rewards logic." },
  { rank: 7, name: "Skerry Drop", category: "Airdrop infra", score: 52, criticals: 1, highs: 2, mediums: 1, trend: "down", lastScan: "2026-07-10", note: "PA-04: EOA-gated claim path with a CEI violation. Team notified 2026-07-10." },
  { rank: 8, name: "Bellwether Yield", category: "Yield", score: 38, criticals: 2, highs: 1, mediums: 2, trend: "down", lastScan: "2026-07-13", note: "tx.origin auth on withdraw + EOA-only reentrancy path. Disclosure window open." },
];
