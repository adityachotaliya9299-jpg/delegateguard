import type { Metadata } from "next";
import Link from "next/link";
import Stamp from "@/components/Stamp";
import Reveal from "@/components/Reveal";
import { CATALOG, DC_ENTRIES, PA_ENTRIES, type BugEntry } from "@/lib/catalog";

export const metadata: Metadata = {
  title: "Bug Class Catalog",
  description: "Root cause, exploit path, and fix for all 13 EIP-7702 bug classes DelegateGuard detects.",
};

function Entry({ b }: { b: BugEntry }) {
  return (
    <Reveal as="article" variant="up" id={b.id.toLowerCase()} className="panel p-0 scroll-mt-32">
      <div className="panel-head">
        <span><span style={{ color: "var(--brand)" }}>{b.id}</span> · {b.name}</span>
        <Stamp label={b.severity} />
      </div>
      <div className="p-7">
        <p className="lead" style={{ fontSize: 16 }}>{b.oneLiner}</p>

        {b.seenInWild && (
          <p className="mt-4 mono p-3" style={{ fontSize: 12.5, background: "var(--brand-wash)", borderLeft: "3px solid var(--brand)", color: "var(--brand-deep)" }}>
            SEEN IN THE WILD — {b.seenInWild}
          </p>
        )}

        <div className="grid gap-8 md:grid-cols-2 mt-7">
          <div>
            <p className="meta mb-2">ROOT CAUSE</p>
            <p style={{ fontSize: 13.5, color: "var(--ink-soft)" }}>{b.rootCause}</p>

            <p className="meta mt-6 mb-2">HOW DELEGATEGUARD DETECTS IT</p>
            <p style={{ fontSize: 13.5, color: "var(--ink-soft)" }}>{b.detector}</p>
          </div>

          <div>
            <p className="meta mb-3">EXPLOIT PATH</p>
            <ol className="space-y-2.5">
              {b.exploitPath.map((step, i) => (
                <li key={i} className="flex gap-3" style={{ fontSize: 13, color: "var(--ink-soft)" }}>
                  <span className="mono" style={{ color: "var(--brand)", fontWeight: 700 }}>{i + 1}.</span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </div>
        </div>

        <div className="mt-7 p-5" style={{ background: "var(--paper-sunk)", borderLeft: "3px solid var(--safe)" }}>
          <p className="meta mb-1.5" style={{ color: "var(--safe)" }}>THE FIX</p>
          <p style={{ fontSize: 13.5 }}>{b.fix}</p>
        </div>

        <p className="meta mt-5">
          POC: <span style={{ color: "var(--ink)" }}>{b.poc}</span> · RED PROVES THE EXPLOIT, GREEN PROVES THE FIX
        </p>
      </div>
    </Reveal>
  );
}

export default function CatalogPage() {
  return (
    <div className="wrap py-12">
      <p className="kicker">The catalog</p>
      <h1 className="display mt-4" style={{ fontSize: "clamp(30px, 4vw, 48px)" }}>
        Thirteen ways EIP-7702 breaks your assumptions.
      </h1>
      <p className="lead mt-5 max-w-2xl">
        Eight in the delegate contracts themselves, five in the protocols that talk to them. Each
        one: root cause, the exploit as it actually runs, the fix, and a Foundry proof that both
        exist. This is the reference the analyzer and scanner are built from.
      </p>

      {/* quick index */}
      <nav className="mt-10 grid gap-px sm:grid-cols-2 lg:grid-cols-3" style={{ background: "var(--rule-strong)", border: "1px solid var(--rule-strong)" }}>
        {CATALOG.map((b) => (
          <a key={b.id} href={`#${b.id.toLowerCase()}`} className="dotted-leader px-4 py-3 hover:opacity-70" style={{ background: "var(--paper)", transition: "opacity 100ms" }}>
            <span className="mono" style={{ fontSize: 11.5, color: "var(--brand)", fontWeight: 600 }}>{b.id}</span>
            <span style={{ fontSize: 12.5 }}>{b.name}</span>
          </a>
        ))}
      </nav>

      <section id="dc" className="mt-16 scroll-mt-32">
        <div className="dotted-leader mb-6">
          <h2 className="display" style={{ fontSize: 28 }}>Delegate contract bugs</h2>
          <span className="meta">DC-01 … DC-08</span>
        </div>
        <div className="space-y-6">
          {DC_ENTRIES.map((b) => <Entry key={b.id} b={b} />)}
        </div>
      </section>

      <section id="pa" className="mt-16 scroll-mt-32">
        <div className="dotted-leader mb-6">
          <h2 className="display" style={{ fontSize: 28 }}>Protocol assumption bugs</h2>
          <span className="meta">PA-01 … PA-05</span>
        </div>
        <div className="space-y-6">
          {PA_ENTRIES.map((b) => <Entry key={b.id} b={b} />)}
        </div>
      </section>

      <div className="panel mt-14 p-8 text-center">
        <h2 className="display" style={{ fontSize: 26 }}>Found your codebase in here?</h2>
        <p className="lead mt-3 mx-auto max-w-lg">Run the scanner and get the exact file:line, or book an assessment and get the PoC harnesses too.</p>
        <div className="mt-6 flex flex-wrap justify-center gap-3">
          <Link href="/scan" className="btn btn-brand">Run a scan →</Link>
          <Link href="/pricing" className="btn btn-line">Book an assessment</Link>
        </div>
      </div>
    </div>
  );
}
