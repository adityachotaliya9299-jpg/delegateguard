import type { Metadata } from "next";
import Link from "next/link";
import { LEADERBOARD } from "@/lib/leaderboard";
import { grade, gradeColor } from "@/lib/score";

export const metadata: Metadata = {
  title: "Protocol Leaderboard",
  description: "Public ranking of protocols by post-Pectra security score.",
};

const TREND = { up: ["▲", "var(--safe)"], down: ["▼", "var(--sev-critical)"], flat: ["—", "var(--ink-faint)"] } as const;

export default function LeaderboardPage() {
  return (
    <div className="wrap py-12">
      <p className="kicker">Public board</p>
      <div className="mt-4 flex flex-wrap items-end justify-between gap-4">
        <h1 className="display" style={{ fontSize: "clamp(30px, 4vw, 44px)" }}>
          Who&apos;s ready for the post-Pectra world.
        </h1>
        <p className="meta max-w-sm">
          OPT-IN RANKINGS. SCORE = 100 − WEIGHTED DEDUCTIONS FROM THE LATEST FULL SCAN.
          NAMES BELOW ARE SAMPLE DATA.
        </p>
      </div>

      <div className="panel mt-10 p-0 overflow-x-auto">
        <table className="ledger">
          <thead>
            <tr>
              <th style={{ width: 56 }}>#</th>
              <th>Protocol</th>
              <th>Category</th>
              <th style={{ textAlign: "right" }}>Score</th>
              <th>Grade</th>
              <th style={{ textAlign: "center" }}>Crit</th>
              <th style={{ textAlign: "center" }}>High</th>
              <th style={{ textAlign: "center" }}>Med</th>
              <th>Trend</th>
              <th>Last scan</th>
            </tr>
          </thead>
          <tbody>
            {LEADERBOARD.map((p) => {
              const [arrow, color] = TREND[p.trend];
              return (
                <tr key={p.rank}>
                  <td className="num" style={{ color: "var(--ink-faint)", fontWeight: 600 }}>{String(p.rank).padStart(2, "0")}</td>
                  <td>
                    <p style={{ fontWeight: 600, fontSize: 14 }}>{p.name}</p>
                    <p style={{ fontSize: 12, color: "var(--ink-soft)", maxWidth: 340 }}>{p.note}</p>
                  </td>
                  <td style={{ fontSize: 13, color: "var(--ink-soft)" }}>{p.category}</td>
                  <td style={{ textAlign: "right" }}>
                    <span className="num" style={{ fontSize: 20, fontWeight: 700, color: gradeColor(p.score) }}>{p.score}</span>
                  </td>
                  <td>
                    <span className="stamp" style={{ color: gradeColor(p.score) }}>{grade(p.score)}</span>
                  </td>
                  <td className="num" style={{ textAlign: "center", color: p.criticals ? "var(--sev-critical)" : "var(--ink-faint)", fontWeight: p.criticals ? 700 : 400 }}>{p.criticals}</td>
                  <td className="num" style={{ textAlign: "center", color: p.highs ? "var(--sev-high)" : "var(--ink-faint)", fontWeight: p.highs ? 700 : 400 }}>{p.highs}</td>
                  <td className="num" style={{ textAlign: "center", color: p.mediums ? "var(--sev-medium)" : "var(--ink-faint)" }}>{p.mediums}</td>
                  <td className="mono" style={{ color, fontSize: 13 }}>{arrow}</td>
                  <td className="num" style={{ color: "var(--ink-soft)", fontSize: 12.5 }}>{p.lastScan}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="mt-8 grid gap-6 md:grid-cols-2">
        <div className="panel-flat p-6">
          <p className="meta mb-2">HOW SCORING WORKS</p>
          <p style={{ fontSize: 13.5, color: "var(--ink-soft)" }}>
            Every protocol starts at 100. Each finding deducts by severity — 24 for a CRITICAL, 11
            for a HIGH, 4 for a MEDIUM. Deliberately non-linear: one critical outweighs five
            mediums, because that&apos;s how exploits work too.
          </p>
        </div>
        <div className="panel-flat p-6 flex flex-col justify-between gap-4">
          <div>
            <p className="meta mb-2">GET ON THE BOARD</p>
            <p style={{ fontSize: 13.5, color: "var(--ink-soft)" }}>
              Run a full scan, fix what it finds, publish your score. Green rows make good
              marketing — ask the teams at the top.
            </p>
          </div>
          <Link href="/scan" className="btn btn-brand self-start">Scan your protocol →</Link>
        </div>
      </div>
    </div>
  );
}
