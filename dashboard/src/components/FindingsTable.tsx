"use client";
import { useState } from "react";
import { Finding, Severity, BugClass } from "@/lib/types";
import { ChevronDown, ChevronRight } from "lucide-react";

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "#FF3B3B",
  HIGH: "#FFB800",
  MEDIUM: "#818CF8",
  INFO: "#00E5FF",
};

const SEV_BG: Record<Severity, string> = {
  CRITICAL: "rgba(255,59,59,0.12)",
  HIGH: "rgba(255,184,0,0.10)",
  MEDIUM: "rgba(129,140,248,0.12)",
  INFO: "rgba(0,229,255,0.10)",
};

function FindingRow({ f, index }: { f: Finding; index: number }) {
  const [open, setOpen] = useState(false);
  const color = SEV_COLOR[f.severity];
  const bg = SEV_BG[f.severity];

  return (
    <>
      <tr
        onClick={() => setOpen(o => !o)}
        style={{
          cursor: "pointer",
          borderBottom: "1px solid var(--border)",
          background: open ? "var(--bg-elevated)" : "transparent",
          transition: "background 0.12s",
        }}
      >
        <td style={{ padding: "11px 14px", width: 28 }}>
          <span style={{ color: "var(--text-muted)", fontFamily: "monospace", fontSize: 11 }}>{index + 1}</span>
        </td>
        <td style={{ padding: "11px 8px", width: 90 }}>
          <span style={{
            display: "inline-block",
            background: bg, color, border: `1px solid ${color}30`,
            fontFamily: "monospace", fontSize: 10, fontWeight: 600,
            padding: "2px 7px", borderRadius: 4,
          }}>
            {f.severity}
          </span>
        </td>
        <td style={{ padding: "11px 8px", width: 60 }}>
          <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--cyan)", fontWeight: 600 }}>
            {f.bug_class}
          </span>
        </td>
        <td style={{ padding: "11px 8px" }}>
          <span style={{ fontSize: 13, color: "var(--text)" }}>{f.title.split("(")[0].trim()}</span>
        </td>
        <td style={{ padding: "11px 8px" }}>
          <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text-secondary)" }}>{f.contract}</span>
        </td>
        <td style={{ padding: "11px 8px" }}>
          <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--cyan-dim)" }}>
            {f.function ? `${f.function}()` : "—"}
          </span>
        </td>
        <td style={{ padding: "11px 14px", textAlign: "right" }}>
          {open ? <ChevronDown size={13} color="var(--text-muted)" /> : <ChevronRight size={13} color="var(--text-muted)" />}
        </td>
      </tr>

      {open && (
        <tr style={{ background: "var(--bg-elevated)" }}>
          <td colSpan={7} style={{ padding: "0 14px 16px 14px" }}>
            <div style={{ paddingTop: 12, display: "flex", flexDirection: "column", gap: 10 }}>
              {/* Location */}
              {f.source_file && (
                <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Location:</span>
                  <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--text-secondary)" }}>
                    {f.source_file}:{f.line}
                  </span>
                </div>
              )}

              {/* Description */}
              <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.65 }}>{f.description}</p>

              {/* Recommendation */}
              <div style={{
                background: "rgba(0,230,118,0.06)",
                border: "1px solid rgba(0,230,118,0.15)",
                borderRadius: 6, padding: "10px 14px",
              }}>
                <p style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.05em" }}>Fix</p>
                <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6 }}>{f.recommendation}</p>
              </div>

              {/* PoC ref */}
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <span style={{ fontSize: 11, color: "var(--text-muted)" }}>PoC:</span>
                <span style={{ fontFamily: "monospace", fontSize: 11, color: "var(--cyan-dim)" }}>{f.poc_ref}</span>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function FindingsTable({ findings }: { findings: Finding[] }) {
  const [severityFilter, setSeverityFilter] = useState<Severity | "ALL">("ALL");
  const [bugFilter, setBugFilter] = useState<"ALL" | "DC" | "PA">("ALL");

  const filtered = findings.filter(f => {
    const sevOk = severityFilter === "ALL" || f.severity === severityFilter;
    const bugOk = bugFilter === "ALL" || f.bug_class.startsWith(bugFilter);
    return sevOk && bugOk;
  });

  return (
    <div>
      {/* Filter bar */}
      <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
        {(["ALL", "CRITICAL", "HIGH", "MEDIUM", "INFO"] as const).map(s => (
          <button key={s} onClick={() => setSeverityFilter(s)} style={{
            fontFamily: "monospace", fontSize: 11, padding: "4px 12px", borderRadius: 5,
            border: `1px solid ${severityFilter === s ? (s === "ALL" ? "var(--cyan)" : SEV_COLOR[s as Severity] || "var(--cyan)") : "var(--border)"}`,
            background: severityFilter === s ? "var(--bg-elevated)" : "transparent",
            color: severityFilter === s ? (s === "ALL" ? "var(--cyan)" : SEV_COLOR[s as Severity] || "var(--cyan)") : "var(--text-muted)",
            cursor: "pointer", transition: "all 0.12s",
          }}>{s}</button>
        ))}
        <div style={{ width: 1, height: 24, background: "var(--border)", alignSelf: "center" }} />
        {(["ALL", "DC", "PA"] as const).map(b => (
          <button key={b} onClick={() => setBugFilter(b)} style={{
            fontFamily: "monospace", fontSize: 11, padding: "4px 12px", borderRadius: 5,
            border: `1px solid ${bugFilter === b ? "var(--cyan)" : "var(--border)"}`,
            background: bugFilter === b ? "var(--bg-elevated)" : "transparent",
            color: bugFilter === b ? "var(--cyan)" : "var(--text-muted)",
            cursor: "pointer", transition: "all 0.12s",
          }}>{b === "ALL" ? "ALL" : b === "DC" ? "Delegate bugs" : "Protocol bugs"}</button>
        ))}
        <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--text-muted)", alignSelf: "center" }}>
          {filtered.length} of {findings.length}
        </span>
      </div>

      {/* Table */}
      <div style={{ borderRadius: 8, border: "1px solid var(--border)", overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid var(--border-strong)", background: "var(--bg-elevated)" }}>
              {["#", "Severity", "ID", "Title", "Contract", "Function", ""].map(h => (
                <th key={h} style={{
                  padding: "9px 8px", textAlign: "left",
                  fontFamily: "monospace", fontSize: 10, fontWeight: 600,
                  color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.08em",
                }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((f, i) => <FindingRow key={`${f.bug_class}-${f.contract}-${f.function}-${i}`} f={f} index={i} />)}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} style={{ padding: "32px", textAlign: "center", color: "var(--text-muted)", fontFamily: "monospace", fontSize: 13 }}>
                  No findings match filters
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}