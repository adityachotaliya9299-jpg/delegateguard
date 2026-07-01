interface FindingCardProps {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";
  title: string;
  contract: string;
  fn?: string;
  file?: string;
  line?: number;
  description: string;
  recommendation: string;
  poc: string;
}

const SEV_STYLE: Record<string, { badge: string; dot: string }> = {
  CRITICAL: { badge: "badge-critical", dot: "#FF3B3B" },
  HIGH:     { badge: "badge-high",     dot: "#FFB800" },
  MEDIUM:   { badge: "badge-medium",   dot: "#818CF8" },
  INFO:     { badge: "badge-info",     dot: "#00E5FF" },
};

export default function FindingCard({ id, severity, title, contract, fn, file, line, description, recommendation, poc }: FindingCardProps) {
  const sev = SEV_STYLE[severity] ?? SEV_STYLE.INFO;

  return (
    <div className="card" style={{ padding: "18px 20px", marginBottom: 10 }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12, marginBottom: 10 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <span className={sev.badge}>{severity}</span>
          <span className="mono" style={{ fontSize: 12, color: "var(--cyan)", fontWeight: 600 }}>{id}</span>
          <span style={{ fontSize: 14, fontWeight: 500, color: "var(--text)" }}>{title}</span>
        </div>
        {file && (
          <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)", whiteSpace: "nowrap", flexShrink: 0 }}>
            {file.split("/").pop()}:{line}
          </span>
        )}
      </div>

      <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }}>
        <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
          <span style={{ color: "var(--text-muted)" }}>contract</span>{" "}
          <span className="mono" style={{ color: "var(--text)" }}>{contract}</span>
        </span>
        {fn && (
          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
            <span style={{ color: "var(--text-muted)" }}>fn</span>{" "}
            <span className="mono" style={{ color: "var(--cyan-dim)" }}>{fn}()</span>
          </span>
        )}
      </div>

      <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 10 }}>{description}</p>

      <div style={{
        background: "var(--bg-elevated)", borderRadius: 6,
        padding: "10px 14px", marginBottom: 8,
        borderLeft: "2px solid var(--green)",
      }}>
        <p style={{ fontSize: 12, color: "var(--text-muted)", marginBottom: 2 }}>Recommendation</p>
        <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>{recommendation}</p>
      </div>

      <span style={{ fontSize: 11, color: "var(--text-muted)" }}>
        PoC: <span className="mono" style={{ color: "var(--cyan-dim)" }}>{poc}</span>
      </span>
    </div>
  );
}