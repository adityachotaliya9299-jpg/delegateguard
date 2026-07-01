import { NextRequest, NextResponse } from "next/server";
import { MOCK_SCAN } from "@/lib/mock-findings";

// In production this would shell out to:
//   delegateguard analyze <target> --json
//   delegateguard scan   <target> --json
// and merge the results.
//
// For the Vercel deployment we return the rich mock dataset
// which faithfully mirrors the real CLI output format.

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const { mode = "both", target_url = "" } = body;

  // Simulate scan duration
  await new Promise(r => setTimeout(r, 1200 + Math.random() * 800));

  const result = {
    ...MOCK_SCAN,
    target: target_url || MOCK_SCAN.target,
    mode,
    timestamp: new Date().toISOString(),
    duration_ms: Math.floor(2800 + Math.random() * 1200),
    findings: mode === "analyze"
      ? MOCK_SCAN.findings.filter(f => f.bug_class.startsWith("DC"))
      : mode === "scan"
      ? MOCK_SCAN.findings.filter(f => f.bug_class.startsWith("PA"))
      : MOCK_SCAN.findings,
    total: 0,
  };
  result.total = result.findings.length;

  return NextResponse.json(result);
}