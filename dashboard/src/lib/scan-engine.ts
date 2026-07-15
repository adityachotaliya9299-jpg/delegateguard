import { MOCK_SCAN } from "./mock-findings";
import { BUG_META } from "./bug-meta";
import { securityScore, grade, countBySeverity } from "./score";
import type { Finding, ScanMode, ScanResult } from "./types";

/**
 * Single source of truth for a scan run. The demo deployment has no Python
 * backend, so this returns the lab corpus filtered by mode — the same shape the
 * real CLI (`delegateguard analyze/scan --json`) emits. When a backend is wired
 * up (Phase 7), only this function changes; every caller keeps working.
 */
export function runScan(mode: ScanMode, target: string): ScanResult {
  const findings =
    mode === "analyze"
      ? MOCK_SCAN.findings.filter((f) => f.bug_class.startsWith("DC"))
      : mode === "scan"
      ? MOCK_SCAN.findings.filter((f) => f.bug_class.startsWith("PA"))
      : MOCK_SCAN.findings;

  return {
    ...MOCK_SCAN,
    target: target || MOCK_SCAN.target,
    mode: mode === "analyze" ? "delegate-analyze" : mode === "scan" ? "protocol-scan" : "both",
    findings,
    total: findings.length,
    timestamp: new Date().toISOString(),
    duration_ms: Math.floor(2800 + Math.random() * 1200),
  };
}

/** The stable, versioned public shape. Kept separate from the internal ScanResult. */
export interface PublicFinding {
  id: string;
  bug_class: string;
  severity: string;
  cvss_range: string;
  cwe: string;
  swc: string | null;
  title: string;
  description: string;
  location: { file: string | null; contract: string; function: string | null; line: number | null };
  remediation: string;
  proof_of_concept: string;
  references: string[];
}

export interface PublicScanResponse {
  api_version: "v1";
  target: string;
  engine: string;
  summary: {
    security_score: number;
    grade: string;
    total: number;
    by_severity: Record<string, number>;
  };
  findings: PublicFinding[];
  generated_at: string;
  disclaimer: string;
}

function toPublicFinding(f: Finding, i: number): PublicFinding {
  const meta = BUG_META[f.bug_class];
  return {
    id: `${f.bug_class}-${String(i + 1).padStart(3, "0")}`,
    bug_class: f.bug_class,
    severity: f.severity,
    cvss_range: { CRITICAL: "9.0-10.0", HIGH: "7.0-8.9", MEDIUM: "4.0-6.9", INFO: "0.0-3.9" }[f.severity] ?? "n/a",
    cwe: meta?.cwe ?? "n/a",
    swc: meta?.swc ?? null,
    title: f.title,
    description: f.description,
    location: { file: f.source_file, contract: f.contract, function: f.function, line: f.line },
    remediation: f.recommendation,
    proof_of_concept: f.poc_ref,
    references: meta?.references ?? [],
  };
}

export function toPublicResponse(result: ScanResult): PublicScanResponse {
  const score = securityScore(result.findings);
  return {
    api_version: "v1",
    target: result.target,
    engine:
      result.mode === "delegate-analyze"
        ? "E1 delegate-analyzer"
        : result.mode === "protocol-scan"
        ? "E2 protocol-scanner"
        : "E1+E2",
    summary: {
      security_score: score,
      grade: grade(score),
      total: result.total,
      by_severity: countBySeverity(result.findings),
    },
    findings: result.findings.map(toPublicFinding),
    generated_at: result.timestamp,
    disclaimer:
      "Heuristic static analysis. Findings are candidates for review, not confirmed exploits. See /catalog for detection boundaries.",
  };
}
