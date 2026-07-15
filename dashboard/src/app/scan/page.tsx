"use client";

import { useMemo, useRef, useState } from "react";
import Stamp from "@/components/Stamp";
import { countBySeverity, grade, gradeColor, securityScore } from "@/lib/score";
import type { Finding, ScanMode, ScanResult, Severity } from "@/lib/types";

const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "INFO"];

const PROGRESS_LINES = [
  "resolving target…",
  "slither: compiling with solc 0.8.26",
  "E1 loading detectors DC-01…DC-08",
  "E2 loading detectors PA-01…PA-05",
  "walking call graph — 14 contracts, 96 functions",
  "cross-referencing CEI violations with EOA gates",
  "matching sweeper shapes against bytecode",
  "collecting findings…",
];

function harnessCmd(f: Finding) {
  return `delegateguard harness ${f.source_file ?? "."} --bug ${f.bug_class}`;
}

function toMarkdown(r: ScanResult) {
  const lines = [
    `# DelegateGuard scan — ${r.target}`,
    ``,
    `- mode: ${r.mode}`,
    `- findings: ${r.total}`,
    `- score: ${securityScore(r.findings)}/100 (${grade(securityScore(r.findings))})`,
    `- generated: ${r.timestamp}`,
    ``,
  ];
  for (const f of r.findings) {
    lines.push(
      `## [${f.severity}] ${f.title}`,
      ``,
      `- contract: \`${f.contract}\`${f.function ? ` · \`${f.function}()\`` : ""}`,
      `- location: ${f.source_file ?? "n/a"}${f.line ? `:${f.line}` : ""}`,
      `- PoC: \`${f.poc_ref}\``,
      ``,
      f.description,
      ``,
      `**Fix:** ${f.recommendation}`,
      ``,
    );
  }
  return lines.join("\n");
}

function download(name: string, body: string, type: string) {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function FindingRow({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="panel-flat" style={{ borderLeft: `3px solid var(--sev-${f.severity.toLowerCase()})` }}>
      <button
        className="w-full flex items-center gap-4 p-4 text-left cursor-pointer"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: "var(--brand)", minWidth: 48 }}>
          {f.bug_class}
        </span>
        <span className="flex-1" style={{ fontSize: 14, fontWeight: 500 }}>{f.title}</span>
        <Stamp label={f.severity} />
        <span className="mono" style={{ fontSize: 14, color: "var(--ink-faint)" }}>{open ? "−" : "+"}</span>
      </button>

      {open && (
        <div className="px-4 pb-5" style={{ borderTop: "1px solid var(--rule)" }}>
          <div className="grid gap-6 md:grid-cols-[1.2fr_1fr] pt-4">
            <div>
              <p className="meta mb-2">FINDING</p>
              <p style={{ fontSize: 13.5, color: "var(--ink-soft)" }}>{f.description}</p>
              <p className="meta mt-5 mb-2">REMEDIATION</p>
              <p style={{ fontSize: 13.5, color: "var(--ink-soft)" }}>{f.recommendation}</p>
            </div>
            <div>
              <p className="meta mb-2">EVIDENCE</p>
              <dl className="mono" style={{ fontSize: 12.5 }}>
                <div className="dotted-leader py-1.5">
                  <dt style={{ color: "var(--ink-faint)" }}>contract</dt>
                  <dd>{f.contract}</dd>
                </div>
                {f.function && (
                  <div className="dotted-leader py-1.5">
                    <dt style={{ color: "var(--ink-faint)" }}>function</dt>
                    <dd>{f.function}()</dd>
                  </div>
                )}
                <div className="dotted-leader py-1.5">
                  <dt style={{ color: "var(--ink-faint)" }}>location</dt>
                  <dd style={{ wordBreak: "break-all" }}>
                    {f.source_file}{f.line ? `:${f.line}` : ""}
                  </dd>
                </div>
                <div className="dotted-leader py-1.5">
                  <dt style={{ color: "var(--ink-faint)" }}>PoC</dt>
                  <dd style={{ wordBreak: "break-all" }}>{f.poc_ref}</dd>
                </div>
              </dl>
              <p className="meta mt-4 mb-2">REPRODUCE</p>
              <div className="term" style={{ boxShadow: "none" }}>
                <div className="term-body" style={{ padding: "8px 12px", fontSize: 11.5 }}>
                  <span className="dim">$ </span>
                  <span className="p">{harnessCmd(f)}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ScanPage() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<ScanMode>("both");
  const [sevFilter, setSevFilter] = useState<Severity[]>([]);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState<string[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  const runScan = async () => {
    setRunning(true);
    setResult(null);
    setLog([`$ delegateguard ${mode === "both" ? "analyze && delegateguard scan" : mode} ${target || "contracts/"}`]);

    timers.current.forEach(clearTimeout);
    timers.current = PROGRESS_LINES.map((line, i) =>
      setTimeout(() => setLog((l) => [...l, line]), 260 * (i + 1))
    );

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: target, mode }),
      });
      const data: ScanResult = await res.json();
      timers.current.forEach(clearTimeout);
      setLog((l) => [...l, `done — ${data.total} findings in ${(data.duration_ms / 1000).toFixed(1)}s`]);
      setResult(data);
    } catch {
      setLog((l) => [...l, "error: scan backend unreachable"]);
    } finally {
      setRunning(false);
    }
  };

  const visible = useMemo(() => {
    if (!result) return [];
    if (sevFilter.length === 0) return result.findings;
    return result.findings.filter((f) => sevFilter.includes(f.severity));
  }, [result, sevFilter]);

  const score = result ? securityScore(result.findings) : null;
  const counts = result ? countBySeverity(result.findings) : null;

  return (
    <div className="wrap py-12">
      <p className="kicker">Scanner console</p>
      <div className="mt-4 flex flex-wrap items-end justify-between gap-4">
        <h1 className="display" style={{ fontSize: "clamp(30px, 4vw, 44px)" }}>Open an investigation.</h1>
        <p className="meta max-w-sm">
          E1 + E2 AGAINST YOUR CODEBASE. DEMO DEPLOY RUNS ON THE LAB CORPUS — SELF-HOST TO SCAN PRIVATE REPOS.
        </p>
      </div>

      {/* config + console */}
      <div className="mt-10 grid gap-6 lg:grid-cols-[1fr_1.1fr]">
        <div className="panel p-0">
          <div className="panel-head"><span>Scan configuration</span><span>№ 001</span></div>
          <div className="p-6 space-y-6">
            <div>
              <label className="meta block mb-2" htmlFor="target">TARGET — REPO URL OR PATH</label>
              <input
                id="target"
                className="field"
                placeholder="https://github.com/org/protocol  ·  contracts/"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                spellCheck={false}
              />
            </div>

            <div>
              <p className="meta mb-2">ENGINE</p>
              <div className="flex flex-wrap gap-2">
                {([
                  ["analyze", "E1 · delegate"],
                  ["scan", "E2 · protocol"],
                  ["both", "E1 + E2"],
                ] as [ScanMode, string][]).map(([m, label]) => (
                  <button key={m} className={`choice ${mode === m ? "on" : ""}`} onClick={() => setMode(m)}>
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <button className="btn btn-brand w-full justify-center" onClick={runScan} disabled={running}>
              {running ? "Scanning…" : "Run scan →"}
            </button>

            <p className="meta" style={{ lineHeight: 1.8 }}>
              STRICT MODE: DC DETECTORS ONLY RUN AGAINST DELEGATES, PA ONLY AGAINST PROTOCOLS.
              MIXED CODEBASES GET BOTH, SCOPED BY CONTRACT TYPE.
            </p>
          </div>
        </div>

        <div className="term">
          <div className="term-bar">
            <span style={{ color: "var(--term-red)" }}>●</span>
            <span style={{ color: "var(--term-hot)" }}>●</span>
            <span style={{ color: "var(--term-green)" }}>●</span>
            <span className="ml-2">delegateguard — session log</span>
          </div>
          <div className="term-body" style={{ minHeight: 264 }}>
            {log.length === 0 ? (
              <>
                <p><span className="dim">$ </span><span className="p">delegateguard --help</span></p>
                <p className="dim">analyze &nbsp;· delegate contracts (DC-01…08)</p>
                <p className="dim">scan &nbsp;&nbsp;&nbsp;&nbsp;· protocol assumptions (PA-01…05)</p>
                <p className="dim">harness &nbsp;· Foundry PoC scaffolds</p>
                <p className="dim">monitor &nbsp;· live on-chain delegations</p>
                <p className="mt-3"><span className="dim">$ </span><span className="cursor" /></p>
              </>
            ) : (
              <>
                {log.map((line, i) => (
                  <p key={i} className={i === 0 ? "p" : line.startsWith("done") ? "ok" : line.startsWith("error") ? "bad" : "dim"}>
                    {i > 0 && <span className="dim">  › </span>}{line}
                  </p>
                ))}
                {running && <p><span className="cursor" /></p>}
              </>
            )}
          </div>
        </div>
      </div>

      {/* results */}
      {result && counts && score !== null && (
        <section className="mt-14">
          <hr className="rule-x" />
          <div className="mt-10 grid gap-6 lg:grid-cols-[0.9fr_1.4fr_0.9fr]">
            {/* score */}
            <div className="panel ticked p-6 text-center">
              <p className="meta">SECURITY SCORE</p>
              <p className="num mt-2" style={{ fontSize: 72, fontWeight: 700, lineHeight: 1, color: gradeColor(score) }}>
                {score}
              </p>
              <p className="display mt-1" style={{ fontSize: 26, color: gradeColor(score) }}>{grade(score)}</p>
              <p className="meta mt-3">DEDUCTIONS: −24 CRIT · −11 HIGH · −4 MED</p>
            </div>

            {/* severity bars */}
            <div className="panel p-6">
              <p className="meta mb-4">FINDINGS BY SEVERITY — {result.total} TOTAL</p>
              <div className="space-y-3">
                {SEVERITIES.map((s) => {
                  const n = counts[s];
                  const max = Math.max(1, ...SEVERITIES.map((x) => counts[x]));
                  return (
                    <div key={s} className="flex items-center gap-3">
                      <span className="mono" style={{ fontSize: 10.5, width: 68, color: `var(--sev-${s.toLowerCase()})`, fontWeight: 700 }}>
                        {s}
                      </span>
                      <div className="flex-1" style={{ background: "var(--paper-sunk)", height: 16 }}>
                        <div style={{ width: `${(n / max) * 100}%`, height: "100%", background: `var(--sev-${s.toLowerCase()})`, transition: "width 400ms ease" }} />
                      </div>
                      <span className="num" style={{ fontSize: 13, width: 20, textAlign: "right" }}>{n}</span>
                    </div>
                  );
                })}
              </div>
              <p className="meta mt-5" style={{ wordBreak: "break-all" }}>
                TARGET: {result.target} · MODE: {result.mode.toUpperCase()} · {new Date(result.timestamp).toUTCString()}
              </p>
            </div>

            {/* export */}
            <div className="panel p-6 flex flex-col justify-between gap-4">
              <div>
                <p className="meta mb-3">EXPORT</p>
                <p style={{ fontSize: 13.5, color: "var(--ink-soft)" }}>
                  Take the evidence with you — audit-ready Markdown or raw JSON, same shape as the CLI output.
                </p>
              </div>
              <div className="space-y-2.5">
                <button className="btn btn-solid w-full justify-center" onClick={() => download("delegateguard-report.md", toMarkdown(result), "text/markdown")}>
                  Report .md
                </button>
                <button className="btn btn-line w-full justify-center" onClick={() => download("delegateguard-scan.json", JSON.stringify(result, null, 2), "application/json")}>
                  Raw .json
                </button>
              </div>
            </div>
          </div>

          {/* filter + list */}
          <div className="mt-10 flex flex-wrap items-center gap-2">
            <span className="meta mr-2">FILTER:</span>
            {SEVERITIES.map((s) => (
              <button
                key={s}
                className={`choice ${sevFilter.includes(s) ? "on" : ""}`}
                onClick={() =>
                  setSevFilter((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]))
                }
              >
                {s} ({counts[s]})
              </button>
            ))}
            {sevFilter.length > 0 && (
              <button className="choice" onClick={() => setSevFilter([])}>clear</button>
            )}
          </div>

          <div className="mt-5 space-y-3">
            {visible.map((f, i) => (
              <FindingRow key={`${f.bug_class}-${i}`} f={f} />
            ))}
            {visible.length === 0 && (
              <p className="meta py-8 text-center">NO FINDINGS MATCH THE CURRENT FILTER.</p>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
