import type { Finding, Severity } from "./types";

// Weighted deduction model. A single CRITICAL should hurt more than a pile
// of MEDIUMs — the weights are deliberately non-linear.
const DEDUCTION: Record<Severity, number> = {
  CRITICAL: 24,
  HIGH: 11,
  MEDIUM: 4,
  INFO: 1,
};

export function securityScore(findings: Finding[]): number {
  const raw = findings.reduce((acc, f) => acc + (DEDUCTION[f.severity] ?? 0), 0);
  return Math.max(0, Math.round(100 - raw));
}

export function grade(score: number): string {
  if (score >= 97) return "A+";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 55) return "D";
  return "F";
}

export function gradeColor(score: number): string {
  if (score >= 90) return "var(--safe)";
  if (score >= 70) return "var(--sev-high)";
  return "var(--sev-critical)";
}

export function countBySeverity(findings: Finding[]) {
  const out: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 };
  for (const f of findings) out[f.severity] = (out[f.severity] ?? 0) + 1;
  return out;
}
