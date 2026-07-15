"use client";

import { useMemo, useState } from "react";
import Stamp from "@/components/Stamp";
import { REGISTRY, tagCounts, type DelegateTag } from "@/lib/registry";
import { short } from "@/lib/feed";

const TAGS: (DelegateTag | "ALL")[] = ["ALL", "MALICIOUS", "SUSPICIOUS", "UNKNOWN", "SAFE"];

export default function RegistryPage() {
  const [q, setQ] = useState("");
  const [tag, setTag] = useState<DelegateTag | "ALL">("ALL");
  const [openAddr, setOpenAddr] = useState<string | null>(null);
  const counts = tagCounts();

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return REGISTRY.filter((r) => {
      if (tag !== "ALL" && r.tag !== tag) return false;
      if (!needle) return true;
      return (
        r.address.includes(needle) ||
        r.label.toLowerCase().includes(needle) ||
        r.chains.some((c) => c.toLowerCase().includes(needle))
      );
    }).sort((a, b) => b.eoaCount - a.eoaCount);
  }, [q, tag]);

  return (
    <div className="wrap py-12">
      <p className="kicker">Risk intelligence</p>
      <div className="mt-4 flex flex-wrap items-end justify-between gap-4">
        <h1 className="display" style={{ fontSize: "clamp(30px, 4vw, 44px)" }}>
          The delegate registry.
        </h1>
        <p className="meta max-w-sm">
          EVERY DELEGATE THE MONITOR HAS SEEN — FIRST SEEN, LAST SEEN, EOA COUNT, VERDICT.
          CHECK BEFORE YOU SIGN.
        </p>
      </div>

      {/* tag summary */}
      <div className="mt-10 grid grid-cols-2 md:grid-cols-4 gap-px" style={{ background: "var(--rule-strong)", border: "1px solid var(--rule-strong)" }}>
        {(["MALICIOUS", "SUSPICIOUS", "UNKNOWN", "SAFE"] as DelegateTag[]).map((t) => (
          <button
            key={t}
            onClick={() => setTag(tag === t ? "ALL" : t)}
            className="p-5 text-left cursor-pointer"
            style={{ background: tag === t ? "var(--paper-sunk)" : "var(--paper)" }}
          >
            <p className="num" style={{ fontSize: 30, fontWeight: 700 }}>{counts[t]}</p>
            <Stamp label={t} />
          </button>
        ))}
      </div>

      {/* search */}
      <div className="mt-8 flex flex-wrap gap-3 items-center">
        <input
          className="field"
          style={{ maxWidth: 420 }}
          placeholder="Search address, label, or chain…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          spellCheck={false}
        />
        <div className="flex flex-wrap gap-2">
          {TAGS.map((t) => (
            <button key={t} className={`choice ${tag === t ? "on" : ""}`} onClick={() => setTag(t)}>
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* ledger */}
      <div className="panel mt-6 p-0 overflow-x-auto">
        <table className="ledger">
          <thead>
            <tr>
              <th>Delegate</th>
              <th>Verdict</th>
              <th style={{ textAlign: "right" }}>EOAs</th>
              <th>First seen</th>
              <th>Last seen</th>
              <th>Chains</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const open = openAddr === r.address;
              return [
                <tr key={r.address} onClick={() => setOpenAddr(open ? null : r.address)} style={{ cursor: "pointer" }}>
                  <td>
                    <p style={{ fontWeight: 600, fontSize: 13.5 }}>{r.label}</p>
                    <p className="mono" style={{ fontSize: 11.5, color: "var(--ink-faint)" }}>{short(r.address)}</p>
                  </td>
                  <td><Stamp label={r.tag} /></td>
                  <td className="num" style={{ textAlign: "right", fontWeight: 600 }}>{r.eoaCount.toLocaleString()}</td>
                  <td className="num" style={{ color: "var(--ink-soft)" }}>{r.firstSeen}</td>
                  <td className="num" style={{ color: "var(--ink-soft)" }}>{r.lastSeen}</td>
                  <td style={{ fontSize: 12.5, color: "var(--ink-soft)" }}>{r.chains.join(" · ")}</td>
                  <td className="mono" style={{ color: "var(--ink-faint)" }}>{open ? "−" : "+"}</td>
                </tr>,
                open ? (
                  <tr key={`${r.address}-detail`}>
                    <td colSpan={7} style={{ background: "var(--paper-sunk)" }}>
                      <div className="grid gap-6 md:grid-cols-[1.3fr_1fr] py-2">
                        <div>
                          <p className="meta mb-2">ANALYST NOTES</p>
                          <p style={{ fontSize: 13.5, color: "var(--ink-soft)" }}>{r.riskNotes}</p>
                          {r.drained && (
                            <p className="mt-3 mono" style={{ fontSize: 12.5, color: "var(--sev-critical)", fontWeight: 600 }}>
                              CONFIRMED LOSSES: {r.drained}
                            </p>
                          )}
                        </div>
                        <div className="mono" style={{ fontSize: 12 }}>
                          <div className="dotted-leader py-1.5">
                            <span style={{ color: "var(--ink-faint)" }}>address</span>
                            <span style={{ wordBreak: "break-all" }}>{r.address}</span>
                          </div>
                          <div className="dotted-leader py-1.5">
                            <span style={{ color: "var(--ink-faint)" }}>bytecode hash</span>
                            <span>{r.bytecodeHash}</span>
                          </div>
                          <div className="dotted-leader py-1.5">
                            <span style={{ color: "var(--ink-faint)" }}>one-shot check</span>
                            <span>--check {short(r.address)}</span>
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                ) : null,
              ];
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={7} className="meta text-center py-10">NO DELEGATES MATCH THIS QUERY.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <p className="meta mt-5">
        SEEDED DEMO SNAPSHOT · PRODUCTION REGISTRY IS FED CONTINUOUSLY BY THE PHASE-6 MONITOR
      </p>
    </div>
  );
}
