import { NextRequest, NextResponse } from "next/server";
import { runScan } from "@/lib/scan-engine";
import type { ScanMode } from "@/lib/types";

// Internal endpoint used by the /scan console. In production this shells out to
//   delegateguard analyze <target> --json  &&  delegateguard scan <target> --json
// and merges the results; on the demo deploy runScan() returns the lab corpus.

export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const mode: ScanMode = body.mode ?? "both";
  const target: string = body.target_url ?? "";

  // Simulate scan latency so the console progress log has time to breathe.
  await new Promise((r) => setTimeout(r, 1200 + Math.random() * 800));

  return NextResponse.json(runScan(mode, target));
}
