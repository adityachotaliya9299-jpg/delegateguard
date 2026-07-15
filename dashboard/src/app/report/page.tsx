"use client";

import { useMemo, useState } from "react";
import Stamp from "@/components/Stamp";
import { Mark } from "@/components/Logo";
import { MOCK_SCAN } from "@/lib/mock-findings";
import { BUG_META, CVSS_BY_SEVERITY } from "@/lib/bug-meta";
import { countBySeverity, grade, gradeColor, securityScore } from "@/lib/score";
import type { Finding, ScanMode, Severity } from "@/lib/types";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "INFO"];

function findingsFor(mode: ScanMode): Finding[] {
  if (mode === "analyze") return MOCK_SCAN.findings.filter((f) => f.bug_class.startsWith("DC"));
  if (mode === "scan") return MOCK_SCAN.findings.filter((f) => f.bug_class.startsWith("PA"));
  return MOCK_SCAN.findings;
}

export default function ReportPage() {
  const [project, setProject] = useState("Acme Protocol");
  const [target, setTarget] = useState("github.com/acme/protocol");
  const [mode, setMode] = useState<ScanMode>("both");
  const [auditor, setAuditor] = useState("DelegateGuard — EIP-7702 Assessment");

  const findings = useMemo(() => findingsFor(mode), [mode]);
  const counts = countBySeverity(findings);
  const score = securityScore(findings);
  const today = new Date().toISOString().slice(0, 10);
  const ref = `DG-${today.replace(/-/g, "")}-${mode.slice(0, 1).toUpperCase()}`;

  return (
    <div className="wrap py-12">
      {/* config bar — hidden when printing */}
      <div className="no-print">
        <p className="kicker">Audit report generator</p>
        <div className="mt-4 flex flex-wrap items-end justify-between gap-4">
          <h1 className="display" style={{ fontSize: "clamp(28px, 4vw, 42px)" }}>Turn findings into a deliverable.</h1>
          <button className="btn btn-brand" onClick={() => window.print()}>Print / Save as PDF →</button>
        </div>

        <div className="panel mt-8 p-6 grid gap-5 md:grid-cols-2">
          <div>
            <label className="meta block mb-2">CLIENT / PROJECT</label>
            <input className="field" value={project} onChange={(e) => setProject(e.target.value)} />
          </div>
          <div>
            <label className="meta block mb-2">TARGET</label>
            <input className="field" value={target} onChange={(e) => setTarget(e.target.value)} />
          </div>
          <div>
            <label className="meta block mb-2">PREPARED BY</label>
            <input className="field" value={auditor} onChange={(e) => setAuditor(e.target.value)} />
          </div>
          <div>
            <label className="meta block mb-2">SCOPE</label>
            <div className="flex gap-2">
              {([["analyze", "Delegates"], ["scan", "Protocol"], ["both", "Both"]] as [ScanMode, string][]).map(([m, l]) => (
                <button key={m} className={`choice ${mode === m ? "on" : ""}`} onClick={() => setMode(m)}>{l}</button>
              ))}
            </div>
          </div>
        </div>
        <hr className="rule-x mt-10" />
      </div>

      {/* the report itself */}
      <article className="report mt-10">
        {/* cover */}
        <header className="report-cover">
          <div className="flex items-center gap-3" style={{ color: "var(--ink)" }}>
            <Mark size={34} />
            <span className="display" style={{ fontSize: 22, fontWeight: 640 }}>DelegateGuard</span>
          </div>
          <p className="kicker mt-10">Security assessment</p>
          <h1 className="display mt-3" style={{ fontSize: 44, lineHeight: 1.05 }}>
            EIP-7702 attack-surface review<br />— {project}
          </h1>
          <dl className="report-facts mt-10">
            {[
              ["Reference", ref],
              ["Target", target],
              ["Scope", mode === "both" ? "Delegate contracts (DC) + protocol assumptions (PA)" : mode === "analyze" ? "Delegate contracts (DC-01…08)" : "Protocol assumptions (PA-01…05)"],
              ["Date", today],
              ["Prepared by", auditor],
              ["Methodology", "Slither-based static analysis + heuristic detectors, DelegateGuard E1/E2"],
            ].map(([k, v]) => (
              <div key={k} className="dotted-leader py-2">
                <dt className="meta">{k.toUpperCase()}</dt>
                <dd style={{ fontSize: 13.5 }}>{v}</dd>
              </div>
            ))}
          </dl>
        </header>

        {/* 1. executive summary */}
        <section className="report-section">
          <h2 className="report-h2">1 — Executive summary</h2>
          <div className="grid gap-8 md:grid-cols-[1fr_260px] items-start">
            <div>
              <p style={{ fontSize: 14.5, lineHeight: 1.7 }}>
                This assessment evaluated <strong>{target}</strong> against DelegateGuard&apos;s catalogue of
                {mode === "scan" ? " five protocol-assumption" : mode === "analyze" ? " eight delegate-contract" : " thirteen"} EIP-7702
                bug classes. The review surfaced <strong>{findings.length} finding{findings.length === 1 ? "" : "s"}</strong>
                {counts.CRITICAL > 0 && <>, including <strong style={{ color: "var(--sev-critical)" }}>{counts.CRITICAL} critical</strong></>}
                {counts.HIGH > 0 && <> and <strong style={{ color: "var(--sev-high)" }}>{counts.HIGH} high-severity</strong></>}
                {" "}issue{findings.length === 1 ? "" : "s"} requiring remediation before mainnet exposure.
              </p>
              <p className="mt-4" style={{ fontSize: 14.5, lineHeight: 1.7 }}>
                {counts.CRITICAL > 0
                  ? "Critical findings permit direct loss of user funds under a post-Pectra threat model and should be treated as release-blocking."
                  : counts.HIGH > 0
                  ? "No critical issues were identified, but high-severity findings weaken guarantees the protocol relies on and should be resolved this cycle."
                  : "No critical or high findings were identified. Remaining items are hardening recommendations."}
                {" "}Each finding below includes a reproducible Foundry proof-of-concept reference.
              </p>
            </div>
            <div className="report-score" style={{ borderColor: gradeColor(score) }}>
              <p className="meta">SECURITY SCORE</p>
              <p className="num" style={{ fontSize: 56, fontWeight: 700, lineHeight: 1, color: gradeColor(score) }}>{score}</p>
              <p className="display" style={{ fontSize: 22, color: gradeColor(score) }}>{grade(score)}</p>
            </div>
          </div>

          {/* severity table */}
          <table className="ledger mt-8">
            <thead>
              <tr>
                <th>Severity</th><th style={{ textAlign: "right" }}>Count</th><th>CVSS band</th><th>Disposition</th>
              </tr>
            </thead>
            <tbody>
              {SEVERITIES.map((s) => (
                <tr key={s}>
                  <td><Stamp label={s} /></td>
                  <td className="num" style={{ textAlign: "right", fontWeight: 700 }}>{counts[s]}</td>
                  <td className="num" style={{ color: "var(--ink-soft)" }}>{CVSS_BY_SEVERITY[s]}</td>
                  <td style={{ fontSize: 13, color: "var(--ink-soft)" }}>
                    {s === "CRITICAL" ? "Release-blocking" : s === "HIGH" ? "Fix this cycle" : s === "MEDIUM" ? "Scheduled hardening" : "Informational"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* 2. findings index */}
        <section className="report-section">
          <h2 className="report-h2">2 — Findings index</h2>
          <table className="ledger">
            <thead>
              <tr><th>ID</th><th>Class</th><th>Title</th><th>Severity</th><th>Location</th></tr>
            </thead>
            <tbody>
              {findings.map((f, i) => (
                <tr key={i}>
                  <td className="num" style={{ color: "var(--ink-faint)" }}>{ref}-{String(i + 1).padStart(2, "0")}</td>
                  <td className="mono" style={{ fontSize: 12, color: "var(--brand)", fontWeight: 600 }}>{f.bug_class}</td>
                  <td style={{ fontSize: 13 }}>{f.title.replace(/\s*\([A-Z]{2}-\d{2}\)$/, "")}</td>
                  <td><Stamp label={f.severity} /></td>
                  <td className="mono" style={{ fontSize: 11.5, color: "var(--ink-soft)", wordBreak: "break-all" }}>
                    {f.source_file}{f.line ? `:${f.line}` : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* 3. technical detail */}
        <section className="report-section">
          <h2 className="report-h2">3 — Technical detail</h2>
          {findings.map((f, i) => {
            const meta = BUG_META[f.bug_class];
            return (
              <div key={i} className="report-finding">
                <div className="flex items-baseline justify-between gap-4 flex-wrap">
                  <h3 className="display" style={{ fontSize: 20 }}>
                    <span className="mono" style={{ fontSize: 13, color: "var(--ink-faint)" }}>{ref}-{String(i + 1).padStart(2, "0")} · </span>
                    {f.title.replace(/\s*\([A-Z]{2}-\d{2}\)$/, "")}
                  </h3>
                  <Stamp label={f.severity} />
                </div>

                <div className="report-tags mt-3">
                  <span>{f.bug_class}</span>
                  <span>{meta?.cwe}</span>
                  {meta?.swc && <span>{meta.swc}</span>}
                  <span>CVSS {CVSS_BY_SEVERITY[f.severity]}</span>
                </div>

                <p className="report-label mt-5">Description</p>
                <p style={{ fontSize: 13.5, lineHeight: 1.65 }}>{f.description}</p>

                <p className="report-label mt-4">Location</p>
                <p className="mono" style={{ fontSize: 12.5 }}>
                  {f.contract}{f.function ? `.${f.function}()` : ""} — {f.source_file}{f.line ? `:${f.line}` : ""}
                </p>

                <p className="report-label mt-4">Recommendation</p>
                <p style={{ fontSize: 13.5, lineHeight: 1.65 }}>{f.recommendation}</p>

                <p className="report-label mt-4">Proof of concept</p>
                <p className="mono" style={{ fontSize: 12.5 }}>{f.poc_ref}</p>

                {meta?.references?.length ? (
                  <>
                    <p className="report-label mt-4">References</p>
                    <ul className="mono" style={{ fontSize: 11.5, color: "var(--ink-soft)" }}>
                      {meta.references.map((r) => <li key={r}>{r}</li>)}
                    </ul>
                  </>
                ) : null}
              </div>
            );
          })}
        </section>

        {/* 4. methodology */}
        <section className="report-section">
          <h2 className="report-h2">4 — Methodology &amp; limitations</h2>
          <p style={{ fontSize: 13.5, lineHeight: 1.7 }}>
            Findings were produced by DelegateGuard&apos;s static-analysis engines (E1 delegate analyzer, E2 protocol
            scanner), built on Slither. Detectors are heuristic: they flag <em>candidate</em> issues for human review,
            not confirmed exploits. Absence of a finding is not a proof of safety. Severity reflects worst-case impact
            under an EIP-7702 threat model where any EOA may execute arbitrary delegate code. Each finding ships with a
            Foundry proof-of-concept reference that a reviewer can run to confirm or dismiss it. Detection boundaries for
            each class are documented in the DelegateGuard bug catalogue.
          </p>
        </section>

        <footer className="report-footer">
          <span className="meta">{ref}</span>
          <span className="meta">DELEGATEGUARD · CONFIDENTIAL — {project.toUpperCase()}</span>
        </footer>
      </article>
    </div>
  );
}
