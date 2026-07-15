import { NextRequest, NextResponse } from "next/server";
import { runScan, toPublicResponse } from "@/lib/scan-engine";
import type { ScanMode } from "@/lib/types";

/**
 * Public API v1 — POST /api/v1/scan
 *
 * The productized version of the CLI: submit a target, get structured findings
 * back with severity, location, remediation, CWE/SWC mapping, and references.
 * This is the contract other tools integrate against, so its shape is frozen
 * (see lib/scan-engine PublicScanResponse) independently of internal changes.
 *
 * Request:  { "target": "github.com/org/repo" | "contracts/", "engine": "analyze" | "scan" | "both" }
 * Response: PublicScanResponse (JSON)
 */

const VALID: ScanMode[] = ["analyze", "scan", "both"];

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  if (!body || typeof body !== "object") {
    return json({ error: "invalid_request", message: "Body must be JSON." }, 400);
  }

  const engine = (body.engine ?? "both") as ScanMode;
  if (!VALID.includes(engine)) {
    return json(
      { error: "invalid_engine", message: `engine must be one of ${VALID.join(", ")}.` },
      422
    );
  }

  const target = typeof body.target === "string" ? body.target : "";
  if (!target) {
    return json({ error: "missing_target", message: "A 'target' (repo URL or path) is required." }, 422);
  }

  const result = runScan(engine, target);
  return json(toPublicResponse(result), 200);
}

export async function GET() {
  return json(
    {
      api_version: "v1",
      endpoint: "POST /api/v1/scan",
      body: { target: "string (repo URL or path)", engine: "analyze | scan | both" },
      example:
        'curl -X POST /api/v1/scan -H "content-type: application/json" -d \'{"target":"contracts/","engine":"both"}\'',
    },
    200
  );
}

function json(payload: unknown, status: number) {
  return NextResponse.json(payload, {
    status,
    headers: {
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "POST, GET, OPTIONS",
      "access-control-allow-headers": "content-type",
    },
  });
}

export async function OPTIONS() {
  return json({}, 204);
}
