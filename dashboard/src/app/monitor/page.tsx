"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { mulberry32, nextEvent, short, type FeedEvent } from "@/lib/feed";

const ALERT_RULES = [
  { id: "RULE-1", name: "Malicious registry hit", desc: "Delegate matches a known-malicious bytecode hash." },
  { id: "RULE-2", name: "chain_id = 0 authorization", desc: "Wildcard authorization — replayable on every EVM chain." },
  { id: "RULE-3", name: "Sweeper shape match", desc: "Unregistered delegate whose bytecode matches the DC-07 pattern." },
  { id: "RULE-4", name: "Campaign velocity", desc: "New delegate crossing the EOA-count threshold within hours of deploy." },
  { id: "RULE-5", name: "Mass re-delegation", desc: "Cluster of EOAs switching delegates in the same block range." },
  { id: "RULE-6", name: "Suspicious initializer race", desc: "initialize() called by a non-owner right after authorization." },
];

const BASE_BLOCK = 23_481_207;

export default function MonitorPage() {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [chainFilter, setChainFilter] = useState<string>("all");
  const rng = useRef(mulberry32(0x7702));
  const counter = useRef(0);

  useEffect(() => {
    // pre-fill so the page doesn't open empty
    if (counter.current === 0) {
      const first: FeedEvent[] = [];
      for (let i = 0; i < 9; i++) first.push(nextEvent(rng.current, ++counter.current, BASE_BLOCK));
      setEvents(first.reverse());
    }
    if (paused) return;
    const t = setInterval(() => {
      setEvents((cur) => [nextEvent(rng.current, ++counter.current, BASE_BLOCK), ...cur].slice(0, 48));
    }, 1900);
    return () => clearInterval(t);
  }, [paused]);

  const visible = useMemo(
    () => (chainFilter === "all" ? events : events.filter((e) => e.chain === chainFilter)),
    [events, chainFilter]
  );

  const stats = useMemo(() => {
    const alerts = events.filter((e) => e.kind === "alert").length;
    const delegates = new Set(events.map((e) => e.delegate)).size;
    return { seen: events.length, delegates, alerts };
  }, [events]);

  return (
    <div className="wrap py-12">
      <p className="kicker">Engine E4 · live wire</p>
      <div className="mt-4 flex flex-wrap items-end justify-between gap-4">
        <h1 className="display" style={{ fontSize: "clamp(30px, 4vw, 44px)" }}>
          Delegations, as they land.
        </h1>
        <p className="meta max-w-sm">
          SIMULATED STREAM — THE CLI ATTACHES TO A REAL RPC:{" "}
          <span style={{ color: "var(--ink)" }}>delegateguard monitor --rpc $URL</span>
        </p>
      </div>

      {/* stat strip */}
      <div className="mt-10 grid grid-cols-2 md:grid-cols-4 gap-px" style={{ background: "var(--rule-strong)", border: "1px solid var(--rule-strong)" }}>
        {[
          ["TYPE-4 TXS OBSERVED", stats.seen, "var(--ink)"],
          ["UNIQUE DELEGATES", stats.delegates, "var(--ink)"],
          ["ALERTS FIRED", stats.alerts, "var(--sev-critical)"],
          ["ALERT RULES ARMED", 6, "var(--safe)"],
        ].map(([label, val, color]) => (
          <div key={label as string} className="p-6" style={{ background: "var(--paper)" }}>
            <p className="num" style={{ fontSize: 34, fontWeight: 700, color: color as string }}>{val}</p>
            <p className="meta mt-1">{label}</p>
          </div>
        ))}
      </div>

      <div className="mt-8 grid gap-6 lg:grid-cols-[1.5fr_1fr]">
        {/* feed */}
        <div className="term">
          <div className="term-bar">
            <span className="blip" style={{ background: paused ? "var(--term-dim)" : "var(--term-green)" }} />
            <span>authorization feed · eth_subscribe(newHeads)</span>
            <span className="ml-auto flex items-center gap-2">
              <select
                value={chainFilter}
                onChange={(e) => setChainFilter(e.target.value)}
                className="mono"
                style={{ background: "var(--term-bg)", color: "var(--term-ink)", border: "1px solid var(--term-edge)", fontSize: 10.5, padding: "2px 6px" }}
              >
                <option value="all">ALL CHAINS</option>
                {["Ethereum", "Base", "Arbitrum", "Optimism"].map((c) => (
                  <option key={c} value={c}>{c.toUpperCase()}</option>
                ))}
              </select>
              <button
                onClick={() => setPaused((v) => !v)}
                className="mono cursor-pointer"
                style={{ background: "transparent", color: "var(--term-hot)", border: "1px solid var(--term-edge)", fontSize: 10.5, padding: "2px 8px" }}
              >
                {paused ? "RESUME" : "PAUSE"}
              </button>
            </span>
          </div>
          <div className="term-body" style={{ height: 520, overflowY: "auto" }}>
            {visible.map((e) => (
              <div key={e.id} className="feed-item py-1.5" style={{ borderBottom: "1px solid var(--term-edge)" }}>
                <p>
                  <span className="dim">#{e.block} </span>
                  <span style={{ color: e.kind === "alert" ? "var(--term-red)" : e.kind === "revocation" ? "var(--term-dim)" : "var(--term-green)" }}>
                    {e.kind === "alert" ? "⚠ ALERT" : e.kind === "revocation" ? "revoked" : "delegated"}
                  </span>
                  <span className="dim"> · {e.chain.toLowerCase()}</span>
                </p>
                <p className="dim" style={{ fontSize: 11.5 }}>
                  {short(e.eoa)} → <span style={{ color: "var(--term-ink)" }}>{short(e.delegate)}</span>{" "}
                  <span style={{ color: e.tag === "MALICIOUS" ? "var(--term-red)" : e.tag === "SUSPICIOUS" ? "var(--term-hot)" : "var(--term-dim)" }}>
                    [{e.delegateLabel}]
                  </span>
                </p>
                {e.alertRule && (
                  <p style={{ color: "var(--term-red)", fontSize: 11.5 }}>  └ {e.alertRule}</p>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* rules + pre-sign check */}
        <div className="space-y-6">
          <div className="panel p-0">
            <div className="panel-head"><span>Alert engine — 6 rules</span><span>ARMED</span></div>
            <ul>
              {ALERT_RULES.map((r) => (
                <li key={r.id} className="flex gap-4 px-5 py-3.5" style={{ borderBottom: "1px solid var(--rule)" }}>
                  <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: "var(--brand)", minWidth: 52 }}>{r.id}</span>
                  <div>
                    <p style={{ fontSize: 13.5, fontWeight: 600 }}>{r.name}</p>
                    <p style={{ fontSize: 12.5, color: "var(--ink-soft)" }}>{r.desc}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>

          <div className="panel ticked p-6">
            <p className="meta">PRE-SIGNATURE CHECK</p>
            <p className="mt-2" style={{ fontSize: 13.5, color: "var(--ink-soft)" }}>
              About to sign an authorization? One-shot mode classifies any delegate before you commit:
            </p>
            <div className="term mt-4" style={{ boxShadow: "none" }}>
              <div className="term-body" style={{ padding: "10px 14px", fontSize: 11.5 }}>
                <p><span className="dim">$ </span><span className="p">delegateguard monitor --check 0x930f…0d0b</span></p>
                <p className="bad">✗ MALICIOUS — CrimeEnjoyor sweeper family</p>
                <p className="dim">  2,713 EOAs delegated · drained $1.54M in one tx</p>
              </div>
            </div>
            <Link href="/registry" className="btn btn-line w-full justify-center mt-5">
              Browse the delegate registry →
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
