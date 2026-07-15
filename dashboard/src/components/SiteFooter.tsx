import Link from "next/link";
import { Mark } from "./Logo";

const COLS: { title: string; links: { label: string; href: string }[] }[] = [
  {
    title: "Product",
    links: [
      { label: "Scanner console", href: "/scan" },
      { label: "On-chain monitor", href: "/monitor" },
      { label: "Delegate registry", href: "/registry" },
      { label: "Audit report generator", href: "/report" },
      { label: "Protocol leaderboard", href: "/leaderboard" },
      { label: "Public API (v1)", href: "/api/v1/scan" },
    ],
  },
  {
    title: "Research",
    links: [
      { label: "Bug class catalog", href: "/catalog" },
      { label: "Delegate bugs DC-01…08", href: "/catalog#dc" },
      { label: "Protocol bugs PA-01…05", href: "/catalog#pa" },
      { label: "Threat model", href: "/catalog" },
    ],
  },
  {
    title: "Company",
    links: [
      { label: "Pricing & services", href: "/pricing" },
      { label: "Security assessments", href: "/pricing#services" },
      { label: "GitHub", href: "https://github.com/adityachotaliya9299-jpg" },
    ],
  },
];

export default function SiteFooter() {
  return (
    <footer style={{ borderTop: "1px solid var(--rule-strong)", background: "var(--paper-sunk)" }}>
      <div className="wrap py-14">
        <div className="grid gap-12 lg:grid-cols-[1.4fr_1fr_1fr_1fr]">
          <div>
            <div className="flex items-center gap-3" style={{ color: "var(--ink)" }}>
              <Mark size={30} />
              <span className="display" style={{ fontSize: 21, fontWeight: 640 }}>
                DelegateGuard
              </span>
            </div>
            <p className="mt-4 max-w-xs" style={{ color: "var(--ink-soft)", fontSize: 13.5 }}>
              Code-level security analysis for the EIP-7702 attack surface. Delegate contracts,
              protocol assumptions, and live on-chain delegations — one toolkit.
            </p>
            <p className="meta mt-6">
              4 ENGINES · 13 BUG CLASSES · 137 TESTS
            </p>
          </div>

          {COLS.map((col) => (
            <div key={col.title}>
              <h3 className="meta mb-4" style={{ color: "var(--ink)" }}>
                {col.title.toUpperCase()}
              </h3>
              <ul className="space-y-2.5">
                {col.links.map((l) => (
                  <li key={l.label}>
                    {l.href.startsWith("http") ? (
                      <a
                        href={l.href}
                        target="_blank"
                        rel="noreferrer"
                        style={{ fontSize: 13.5, color: "var(--ink-soft)" }}
                        className="hover:underline"
                      >
                        {l.label} ↗
                      </a>
                    ) : (
                      <Link href={l.href} style={{ fontSize: 13.5, color: "var(--ink-soft)" }} className="hover:underline">
                        {l.label}
                      </Link>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <hr className="rule-x my-10" />

        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <span className="meta">© {new Date().getFullYear()} DELEGATEGUARD — BUILT SOLO, PHASES 0–6 COMPLETE</span>
          <span className="meta">CODE SLOT: 0xEF0100 ‖ DELEGATE</span>
        </div>
      </div>
    </footer>
  );
}
