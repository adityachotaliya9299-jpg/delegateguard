import type { Metadata } from "next";
import Link from "next/link";
import Reveal from "@/components/Reveal";

export const metadata: Metadata = {
  title: "Pricing & Services",
  description: "Self-serve scanning, enterprise, and scoped EIP-7702 security assessments.",
};

const TIERS = [
  {
    name: "Open source",
    price: "Free",
    unit: "forever",
    for: "Researchers & solo devs",
    cta: "Read the docs",
    href: "/catalog",
    highlight: false,
    lines: [
      "Full CLI — analyze, scan, harness, monitor",
      "All 13 detectors, no feature gates",
      "Public-repo scanning in the console",
      "Foundry PoC harness generation",
      "MIT licensed, self-hostable",
    ],
  },
  {
    name: "Team",
    price: "$499",
    unit: "/ month",
    for: "Wallet & protocol teams",
    cta: "Start a scan",
    href: "/scan",
    highlight: true,
    lines: [
      "Private-repo scanning",
      "GitHub App — PR checks, inline comments",
      "Fail-build-on-critical in CI",
      "Historical scans & score trend",
      "On-chain monitor with alerting",
      "Email support",
    ],
  },
  {
    name: "Enterprise",
    price: "From $15k",
    unit: "/ year",
    for: "Larger protocols, exchanges, custodians",
    cta: "Talk to us",
    href: "#services",
    highlight: false,
    lines: [
      "Everything in Team",
      "SSO, RBAC, audit logs",
      "Self-hosted / private deployment",
      "Custom detectors & policy enforcement",
      "Monitoring retainer for your EOA user base",
      "Priority support & SLA",
    ],
  },
];

const SERVICES = [
  {
    tier: "Focused review",
    range: "$3k – $8k",
    desc: "A single delegate contract or a scoped protocol surface. Findings, exploit validation, and a remediation memo.",
  },
  {
    tier: "Protocol assessment",
    range: "$10k – $25k",
    desc: "A substantial codebase end to end. Full DC + PA coverage, PoC harnesses for every critical, and CI integration set up.",
  },
  {
    tier: "Engagement",
    range: "$25k – $75k+",
    desc: "Large or multi-repo protocols, ongoing. Assessment plus a monitoring retainer and re-scans across your release cycle.",
  },
];

export default function PricingPage() {
  return (
    <div className="wrap py-12">
      <p className="kicker">Pricing & services</p>
      <h1 className="display mt-4" style={{ fontSize: "clamp(30px, 4vw, 48px)" }}>
        The tool is free. The peace of mind scales.
      </h1>
      <p className="lead mt-5 max-w-2xl">
        Run the CLI forever at no cost. Pay when you need private scanning, continuous CI coverage,
        or a human in the loop reading the findings with you.
      </p>

      {/* tiers */}
      <div className="mt-12 grid gap-6 lg:grid-cols-3">
        {TIERS.map((t, i) => (
          <Reveal
            key={t.name}
            variant="up"
            delay={i * 110}
            className={`${t.highlight ? "panel" : "panel-flat"} p-0 lift`}
            style={t.highlight ? { borderColor: "var(--brand)", borderWidth: 2 } : undefined}
          >
            <div className="p-7" style={{ borderBottom: "1px solid var(--rule)" }}>
              <div className="flex items-center justify-between">
                <p className="meta">{t.name.toUpperCase()}</p>
                {t.highlight && <span className="stamp stamp-critical">POPULAR</span>}
              </div>
              <p className="mt-4">
                <span className="display" style={{ fontSize: 40, fontWeight: 640 }}>{t.price}</span>
                <span className="meta ml-2">{t.unit.toUpperCase()}</span>
              </p>
              <p className="mt-1" style={{ fontSize: 13, color: "var(--ink-soft)" }}>{t.for}</p>
            </div>
            <div className="p-7">
              <ul className="tick-list">
                {t.lines.map((l) => (
                  <li key={l} style={{ fontSize: 13.5 }}>{l}</li>
                ))}
              </ul>
              <Link
                href={t.href}
                className={`btn ${t.highlight ? "btn-brand" : "btn-line"} w-full justify-center mt-7`}
              >
                {t.cta} →
              </Link>
            </div>
          </Reveal>
        ))}
      </div>

      {/* services */}
      <section id="services" className="mt-20 scroll-mt-32">
        <div className="dotted-leader mb-3">
          <p className="kicker">Security services</p>
          <span className="meta">POWERED BY DELEGATEGUARD</span>
        </div>
        <h2 className="display mt-3 max-w-2xl" style={{ fontSize: "clamp(26px, 3.5vw, 38px)" }}>
          Or hand the whole thing to someone who&apos;s read the catalog cover to cover.
        </h2>
        <p className="lead mt-4 max-w-2xl">
          Not &quot;buy my scanner.&quot; An EIP-7702 assessment: I run the engines against your protocol,
          validate the real findings with runnable exploits, and hand back a report with
          remediation and CI integration. The tooling means every engagement doesn&apos;t start from zero.
        </p>

        <div className="mt-10 grid gap-6 md:grid-cols-3">
          {SERVICES.map((s) => (
            <div key={s.tier} className="panel-flat p-6">
              <p className="meta">{s.tier.toUpperCase()}</p>
              <p className="display mt-2" style={{ fontSize: 28, color: "var(--brand)" }}>{s.range}</p>
              <p className="mt-3" style={{ fontSize: 13.5, color: "var(--ink-soft)" }}>{s.desc}</p>
            </div>
          ))}
        </div>

        <div className="panel mt-10 p-8 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div>
            <h3 className="display" style={{ fontSize: 24 }}>Start with a sanitized findings summary.</h3>
            <p className="lead mt-2 max-w-xl" style={{ fontSize: 15 }}>
              I&apos;ll scan a public codebase, surface the post-Pectra assumptions worth reviewing, and
              send a short write-up. Full assessment optional from there.
            </p>
          </div>
          <a className="btn btn-brand shrink-0" href="https://github.com/adityachotaliya9299-jpg" target="_blank" rel="noreferrer">
            Get in touch →
          </a>
        </div>
      </section>
    </div>
  );
}
