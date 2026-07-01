"use client";
import { Finding, Severity } from "@/lib/types";

const SEV_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "INFO"];
const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "#FF3B3B",
  HIGH: "#FFB800",
  MEDIUM: "#818CF8",
  INFO: "#00E5FF",
};

export default function SeverityChart({ findings }: { findings: Finding[] }) {
  const counts = SEV_ORDER.reduce((acc, s) => {
    acc[s] = findings.filter(f => f.severity === s).length;
    return acc;
  }, {} as Record<Severity, number>);

  const max = Math.max(...Object.values(counts), 1);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {SEV_ORDER.map(sev => {
        const count = counts[sev];
        const pct = (count / max) * 100;
        return (
          <div key={sev} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{
              fontFamily: "monospace", fontSize: 10, fontWeight: 600,
              color: SEV_COLOR[sev], width: 60, letterSpacing: "0.05em",
            }}>
              {sev}
            </span>
            <div style={{ flex: 1, height: 6, background: "var(--bg-elevated)", borderRadius: 3, overflow: "hidden" }}>
              <div style={{
                width: `${pct}%`, height: "100%",
                background: SEV_COLOR[sev],
                borderRadius: 3,
                transition: "width 0.5s ease",
                opacity: count === 0 ? 0.2 : 1,
              }} />
            </div>
            <span style={{ fontFamily: "monospace", fontSize: 12, color: count > 0 ? SEV_COLOR[sev] : "var(--text-muted)", minWidth: 20, textAlign: "right" }}>
              {count}
            </span>
          </div>
        );
      })}
    </div>
  );
}