"use client";
import { useState } from "react";
import Link from "next/link";
import { Shield, Play, Download, RefreshCw, AlertTriangle, CheckCircle, Clock, ChevronLeft, FileCode } from "lucide-react";
import { ScanResult, ScanMode, Severity } from "@/lib/types";
import FindingsTable from "@/components/FindingsTable";
import SeverityChart from "@/components/SeverityChart";

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: "#FF3B3B",
  HIGH: "#FFB800",
  MEDIUM: "#818CF8",
  INFO: "#00E5FF",
};

type ScanState = "idle" | "scanning" | "done" | "error";

export default function DashboardPage() {
  const [targetUrl, setTargetUrl] = useState("");
  const [mode, setMode] = useState<ScanMode>("both");
  const [state, setState] = useState<ScanState>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState(0);

  async function runScan() {
    if (state === "scanning") return;
    setState("scanning");
    setError("");
    setResult(null);
    setProgress(0);

    // Animate progress bar
    const interval = setInterval(() => {
      setProgress(p => Math.min(p + Math.random() * 12, 88));
    }, 180);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: targetUrl, mode }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: ScanResult = await res.json();
      setProgress(100);
      setTimeout(() => { setResult(data); setState("done"); }, 300);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Scan failed");
      setState("error");
    } finally {
      clearInterval(interval);
    }
  }

  function exportJson() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "delegateguard-report.json"; a.click();
    URL.revokeObjectURL(url);
  }

  function exportMarkdown() {
    if (!result) return;
    const lines = [
      "# DelegateGuard Security Report",
      "",
      `**Target:** ${result.target}`,
      `**Date:** ${new Date(result.timestamp).toLocaleString()}`,
      `**Mode:** ${result.mode}`,
      `**Total findings:** ${result.total}`,
      "",
      "## Summary",
      "",
      ...["CRITICAL","HIGH","MEDIUM","INFO"].map(s => {
        const count = result.findings.filter(f => f.severity === s).length;
        return count > 0 ? `- **${s}:** ${count}` : "";
      }).filter(Boolean),
      "",
      "## Findings",
      "",
      ...result.findings.map((f, i) => [
        `### ${i+1}. [${f.severity}] ${f.bug_class} — ${f.title}`,
        "",
        `**Contract:** \`${f.contract}\`${f.function ? `  **Function:** \`${f.function}()\`` : ""}`,
        f.source_file ? `**Location:** \`${f.source_file}:${f.line}\`` : "",
        "",
        f.description,
        "",
        "**Recommendation:**",
        f.recommendation,
        "",
        `**PoC:** \`${f.poc_ref}\``,
        "",
        "---",
        "",
      ].filter(l => l !== null).join("\n")),
    ].join("\n");
    const blob = new Blob([lines], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "delegateguard-report.md"; a.click();
    URL.revokeObjectURL(url);
  }

  const critCount = result?.findings.filter(f => f.severity === "CRITICAL").length ?? 0;
  const highCount = result?.findings.filter(f => f.severity === "HIGH").length ?? 0;

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg)" }}>
      {/* Top bar */}
      <header style={{
        borderBottom: "1px solid var(--border)",
        background: "var(--bg-card)",
        padding: "0 24px",
        position: "sticky", top: 0, zIndex: 40,
      }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", height: 52, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <Link href="/" style={{ display: "flex", alignItems: "center", gap: 6, textDecoration: "none", color: "var(--text-secondary)" }}
              className="hover:text-white transition-colors">
              <ChevronLeft size={15} />
              <Shield size={16} color="var(--cyan)" />
              <span className="mono" style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>DelegateGuard</span>
            </Link>
            <span style={{ color: "var(--border-strong)" }}>/</span>
            <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>Dashboard</span>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            {result && (
              <>
                <button onClick={exportMarkdown} className="btn-ghost" style={{ fontSize: 12, padding: "5px 12px" }}>
                  <Download size={13} /> Export MD
                </button>
                <button onClick={exportJson} className="btn-ghost" style={{ fontSize: 12, padding: "5px 12px" }}>
                  <Download size={13} /> Export JSON
                </button>
              </>
            )}
          </div>
        </div>
      </header>

      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "32px 24px" }}>

        {/* Scan control panel */}
        <div className="card" style={{ padding: "22px 24px", marginBottom: 24 }}>
          <p className="mono" style={{ fontSize: 11, color: "var(--cyan)", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 14 }}>
            Configure scan
          </p>

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}>
            {/* Target input */}
            <div style={{ flex: 1, minWidth: 260 }}>
              <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 6, fontFamily: "monospace" }}>
                Target (GitHub URL or leave empty for demo)
              </label>
              <input
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                placeholder="https://github.com/org/repo  or  contracts/"
                style={{
                  width: "100%", background: "var(--bg-elevated)",
                  border: "1px solid var(--border-strong)", borderRadius: 7,
                  padding: "9px 13px", fontSize: 13, color: "var(--text)",
                  fontFamily: "monospace", outline: "none",
                }}
                onFocus={e => { e.target.style.borderColor = "var(--cyan)"; }}
                onBlur={e => { e.target.style.borderColor = "var(--border-strong)"; }}
              />
            </div>

            {/* Mode selector */}
            <div>
              <label style={{ fontSize: 11, color: "var(--text-muted)", display: "block", marginBottom: 6, fontFamily: "monospace" }}>
                Mode
              </label>
              <div style={{ display: "flex", gap: 4 }}>
                {([
                  { v: "both", label: "Both" },
                  { v: "analyze", label: "Delegate (DC)" },
                  { v: "scan", label: "Protocol (PA)" },
                ] as const).map(opt => (
                  <button key={opt.v} onClick={() => setMode(opt.v)} style={{
                    fontFamily: "monospace", fontSize: 11, padding: "9px 13px", borderRadius: 6,
                    border: `1px solid ${mode === opt.v ? "var(--cyan)" : "var(--border)"}`,
                    background: mode === opt.v ? "var(--cyan-glow)" : "var(--bg-elevated)",
                    color: mode === opt.v ? "var(--cyan)" : "var(--text-secondary)",
                    cursor: "pointer", transition: "all 0.12s",
                  }}>{opt.label}</button>
                ))}
              </div>
            </div>

            {/* Run button */}
            <button
              onClick={runScan}
              disabled={state === "scanning"}
              className="btn-primary"
              style={{ fontSize: 13, padding: "9px 20px", opacity: state === "scanning" ? 0.7 : 1 }}
            >
              {state === "scanning"
                ? <><RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} /> Scanning...</>
                : <><Play size={14} /> Run scan</>}
            </button>
          </div>

          {/* Progress bar */}
          {state === "scanning" && (
            <div style={{ marginTop: 16, height: 2, background: "var(--bg-elevated)", borderRadius: 1, overflow: "hidden" }}>
              <div style={{
                height: "100%", width: `${progress}%`,
                background: "linear-gradient(90deg, var(--cyan), var(--cyan-dim))",
                borderRadius: 1, transition: "width 0.2s ease",
              }} />
            </div>
          )}

          {state === "error" && (
            <div style={{ marginTop: 12, display: "flex", gap: 8, alignItems: "center", color: "var(--red)", fontSize: 13 }}>
              <AlertTriangle size={14} /> {error}
            </div>
          )}
        </div>

        {/* Results */}
        {result && (
          <div style={{ animation: "fadeUp 0.4s ease forwards" }}>
            {/* Summary cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 24 }}>
              {[
                { label: "Total findings", value: result.total, color: "var(--text)", icon: <AlertTriangle size={14} /> },
                { label: "Critical", value: critCount, color: SEV_COLOR.CRITICAL, icon: <AlertTriangle size={14} /> },
                { label: "High", value: highCount, color: SEV_COLOR.HIGH, icon: <AlertTriangle size={14} /> },
                { label: "Scan duration", value: `${(result.duration_ms / 1000).toFixed(1)}s`, color: "var(--text-secondary)", icon: <Clock size={14} /> },
              ].map(card => (
                <div key={card.label} className="card" style={{ padding: "16px 18px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, color: "var(--text-muted)", marginBottom: 6 }}>
                    <span style={{ color: card.color }}>{card.icon}</span>
                    <span style={{ fontSize: 11, fontFamily: "monospace" }}>{card.label}</span>
                  </div>
                  <div className="mono" style={{ fontSize: 26, fontWeight: 700, color: card.color, letterSpacing: "-0.02em" }}>
                    {card.value}
                  </div>
                </div>
              ))}
            </div>

            {/* Chart + meta */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 16, marginBottom: 24 }}>
              <div className="card" style={{ padding: "20px 22px" }}>
                <p className="mono" style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 14 }}>
                  Severity breakdown
                </p>
                <SeverityChart findings={result.findings} />
              </div>

              <div className="card" style={{ padding: "20px 22px" }}>
                <p className="mono" style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 14 }}>
                  Scan metadata
                </p>
                {[
                  { label: "Target", value: result.target },
                  { label: "Mode", value: result.mode },
                  { label: "Timestamp", value: new Date(result.timestamp).toLocaleTimeString() },
                  { label: "Engine", value: "DelegateGuard v0.1.0" },
                ].map(row => (
                  <div key={row.label} style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 8 }}>
                    <span style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "monospace" }}>{row.label}</span>
                    <span style={{ fontSize: 11, color: "var(--text-secondary)", fontFamily: "monospace", textAlign: "right", maxWidth: 160, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{row.value}</span>
                  </div>
                ))}

                <div style={{ marginTop: 14, display: "flex", gap: 6 }}>
                  <button onClick={exportMarkdown} style={{
                    flex: 1, fontSize: 11, padding: "7px 8px", borderRadius: 5,
                    border: "1px solid var(--border)", background: "var(--bg-elevated)",
                    color: "var(--text-secondary)", cursor: "pointer", fontFamily: "monospace",
                    display: "flex", alignItems: "center", justifyContent: "center", gap: 4,
                  }} className="hover:border-cyan-400 transition-colors">
                    <Download size={11} /> MD
                  </button>
                  <button onClick={exportJson} style={{
                    flex: 1, fontSize: 11, padding: "7px 8px", borderRadius: 5,
                    border: "1px solid var(--border)", background: "var(--bg-elevated)",
                    color: "var(--text-secondary)", cursor: "pointer", fontFamily: "monospace",
                    display: "flex", alignItems: "center", justifyContent: "center", gap: 4,
                  }} className="hover:border-cyan-400 transition-colors">
                    <Download size={11} /> JSON
                  </button>
                </div>
              </div>
            </div>

            {/* Findings table */}
            <div className="card" style={{ padding: "20px 22px" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
                <p className="mono" style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                  Findings ({result.total})
                </p>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <CheckCircle size={12} color="var(--green)" />
                  <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Click a row to expand</span>
                </div>
              </div>
              <FindingsTable findings={result.findings} />
            </div>
          </div>
        )}

        {/* Empty state */}
        {state === "idle" && (
          <div style={{ textAlign: "center", padding: "72px 24px" }}>
            <div style={{
              width: 60, height: 60, borderRadius: "50%",
              background: "var(--cyan-glow)", border: "1px solid rgba(0,229,255,0.2)",
              display: "flex", alignItems: "center", justifyContent: "center",
              margin: "0 auto 20px",
            }}>
              <Shield size={24} color="var(--cyan)" />
            </div>
            <h2 className="mono" style={{ fontSize: 20, fontWeight: 600, marginBottom: 8, letterSpacing: "-0.02em" }}>
              Ready to scan
            </h2>
            <p style={{ fontSize: 14, color: "var(--text-secondary)", maxWidth: 360, margin: "0 auto 28px", lineHeight: 1.6 }}>
              Enter a target URL or leave empty to run on the demo dataset. Supports analyze (DC-01..08), scan (PA-01..05), or both.
            </p>
            <div style={{ display: "flex", gap: 12, justifyContent: "center" }}>
              <button onClick={runScan} className="btn-primary" style={{ fontSize: 14 }}>
                <Play size={14} /> Run demo scan
              </button>
            </div>
            <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 20, fontFamily: "monospace" }}>
              Or run locally: <span style={{ color: "var(--cyan-dim)" }}>delegateguard analyze contracts/ --json</span>
            </p>
          </div>
        )}
      </div>

      <style>{`
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes fadeUp { from{opacity:0;transform:translateY(12px)} to{opacity:1;transform:translateY(0)} }
      `}</style>
    </div>
  );
}