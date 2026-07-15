import Link from "next/link";
import Stamp from "@/components/Stamp";
import Reveal from "@/components/Reveal";
import CountUp from "@/components/CountUp";
import { DC_ENTRIES, PA_ENTRIES } from "@/lib/catalog";

const TICKER = [
  "AUG 2025 — SWEEPER DELEGATES DRAIN $2.5M IN ONE MONTH",
  "SINGLE LARGEST LOSS: $1.54M IN ONE TRANSACTION",
  "EXTCODESIZE == 0 NO LONGER MEANS EOA",
  "CHAIN_ID = 0 AUTHORIZATIONS REPLAY ON EVERY EVM CHAIN",
  "MSG.SENDER == TX.ORIGIN GATES ARE OPEN",
  "PECTRA SHIPPED MAY 2025 — YOUR ASSUMPTIONS DIDN'T",
];

const ENGINES = [
  {
    no: "E1",
    name: "Delegate Analyzer",
    cmd: "delegateguard analyze contracts/",
    desc: "Eight Slither-based detectors, one per DC bug class. Storage collisions, sweeper shapes, missing auth, cross-chain replay — with exact file:line locations.",
    href: "/scan",
    proof: "41 findings on the lab corpus",
  },
  {
    no: "E2",
    name: "Protocol Scanner",
    cmd: "delegateguard scan protocol/",
    desc: "Sweeps any Solidity codebase for EOA assumptions that stopped being true after Pectra: tx.origin auth, extcodesize gates, EOA-only reentrancy paths.",
    href: "/scan",
    proof: "17 findings incl. cross-fire detection",
  },
  {
    no: "E3",
    name: "Harness Generator",
    cmd: "delegateguard harness contracts/ --out harnesses/",
    desc: "Every finding becomes a compile-ready Foundry scaffold: a RED test that proves the exploit and a GREEN test that proves your fix. Thirteen templates.",
    href: "/catalog",
    proof: "13 templates, red/green pairs",
  },
  {
    no: "E4",
    name: "On-chain Monitor",
    cmd: "delegateguard monitor --rpc $RPC_URL",
    desc: "Watches live type-4 transactions, parses authorization lists, classifies delegates against the registry, and fires six alert rules on the bad ones.",
    href: "/monitor",
    proof: "6 alert rules, campaign detection",
  },
];

const AUDIENCES = [
  {
    who: "Wallet teams",
    need: "shipping delegate contracts",
    pitch: "DC-01…08 coverage before your delegator holds a million accounts. Analyzer in CI, harness scaffolds for the audit.",
  },
  {
    who: "DeFi protocols",
    need: "holding pre-Pectra assumptions",
    pitch: "PA-01…05 tells you where your codebase still believes an EOA is a human with no code. It probably does.",
  },
  {
    who: "Audit firms",
    need: "selling 7702 reviews",
    pitch: "The engagement toolkit: scan, triage, generate PoC harnesses, hand the client a report with runnable evidence.",
  },
];

function LedgerRows({ entries }: { entries: typeof DC_ENTRIES }) {
  return (
    <ul>
      {entries.map((b) => (
        <li key={b.id} style={{ borderBottom: "1px solid var(--rule)" }}>
          <Link
            href={`/catalog#${b.id.toLowerCase()}`}
            className="dotted-leader py-3 hover:opacity-70"
            style={{ transition: "opacity 100ms" }}
          >
            <span className="mono" style={{ fontSize: 12, color: "var(--brand)", fontWeight: 600 }}>
              {b.id}
            </span>
            <span style={{ fontSize: 14 }}>{b.name}</span>
            <Stamp label={b.severity} />
          </Link>
        </li>
      ))}
    </ul>
  );
}

export default function Home() {
  return (
    <>
      {/* ------------------------------------------------ hero */}
      <section className="gridfield wrap grid gap-14 lg:grid-cols-[1.05fr_0.95fr] items-center pt-16 pb-20">
        <div>
          <p className="kicker reveal">Case file Nº 7702 · opened May 2025</p>
          <h1 className="display reveal d1 mt-5" style={{ fontSize: "clamp(40px, 6vw, 72px)" }}>
            The EOA you trusted has <em style={{ color: "var(--brand)", fontStyle: "italic" }}>code</em> now.
          </h1>
          <p className="lead reveal d2 mt-6 max-w-xl">
            EIP-7702 lets any externally owned account execute contract logic. Phishing crews
            industrialized it within weeks. DelegateGuard is the toolkit that inspects delegate
            contracts, audits protocol assumptions, and watches delegations land on-chain — before
            the funds leave.
          </p>
          <div className="reveal d3 mt-9 flex flex-wrap gap-4">
            <Link href="/scan" className="btn btn-brand">
              Run a scan →
            </Link>
            <Link href="/catalog" className="btn btn-line">
              Read the bug catalog
            </Link>
          </div>
          <div className="reveal d4 mt-10 flex flex-wrap gap-x-10 gap-y-3">
            {[
              [13, "bug classes"],
              [4, "engines"],
              [137, "tests passing"],
              [51, "Foundry PoCs"],
            ].map(([n, l]) => (
              <div key={l as string}>
                <CountUp to={n as number} className="num" style={{ fontSize: 26, fontWeight: 600 }} />
                <span className="meta ml-2">{(l as string).toUpperCase()}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Exhibit A — the delegation designator, annotated like evidence */}
        <figure className="panel ticked p-0 reveal d2" style={{ position: "relative" }}>
          <div className="panel-head">
            <span>Exhibit A — delegation designator</span>
            <span style={{ color: "var(--ink-faint)" }}>TYPE-4 TX</span>
          </div>
          <div className="p-6 mono" style={{ fontSize: 13 }}>
            <p className="meta mb-1.5">EOA · victim account</p>
            <p style={{ wordBreak: "break-all" }}>0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063</p>

            <div className="my-5 flex items-center gap-3" aria-hidden>
              <span style={{ color: "var(--brand)", fontSize: 18 }}>↓</span>
              <span className="meta">CODE SLOT AFTER AUTHORIZATION</span>
            </div>

            <div
              className="p-4"
              style={{ background: "var(--paper-sunk)", border: "1px dashed var(--rule-strong)" }}
            >
              <span style={{ color: "var(--brand)", fontWeight: 600 }}>0xef0100</span>
              <span style={{ color: "var(--ink-faint)" }}> ‖ </span>
              <span style={{ wordBreak: "break-all" }}>930fCc37d6042C79211eE18a02857cb1fd7f0d0b</span>
              <p className="meta mt-2">23 BYTES · EXTCODESIZE ≠ 0 · STILL &quot;AN EOA&quot;</p>
            </div>

            <div className="my-5 flex items-center gap-3" aria-hidden>
              <span style={{ color: "var(--brand)", fontSize: 18 }}>↓</span>
              <span className="meta">EXECUTES AS</span>
            </div>

            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="meta mb-1.5">DELEGATE · resolved</p>
                <p>CrimeEnjoyor sweeper</p>
                <p className="meta mt-1">EXECUTE() · NO AUTH · NO ALLOWLIST</p>
              </div>
              <Stamp label="CRITICAL" />
            </div>
          </div>
          <figcaption
            className="rubber stamp-in"
            style={{ position: "absolute", right: 18, bottom: 54, fontSize: 13, animationDelay: "0.7s" }}
          >
            DC-07 · Flagged
          </figcaption>
          <div className="panel-head" style={{ borderTop: "1px solid var(--rule)", borderBottom: 0 }}>
            <span style={{ color: "var(--brand)" }}>VERDICT: DO NOT SIGN</span>
            <Link href="/registry" className="hover:underline" style={{ color: "var(--ink-soft)" }}>
              CHECK THE REGISTRY →
            </Link>
          </div>
        </figure>
      </section>

      {/* ------------------------------------------------ incident ticker */}
      <div
        className="overflow-hidden py-3"
        style={{ background: "var(--term-bg)", borderTop: "1px solid var(--rule-strong)", borderBottom: "1px solid var(--rule-strong)" }}
      >
        <div className="marquee-track">
          {[...TICKER, ...TICKER].map((t, i) => (
            <span key={i} className="mono px-8 whitespace-nowrap" style={{ fontSize: 11.5, letterSpacing: "0.12em", color: "var(--term-hot)" }}>
              {t} <span style={{ color: "var(--term-dim)" }}>·</span>
            </span>
          ))}
        </div>
      </div>

      {/* ------------------------------------------------ the collapse */}
      <section className="wrap py-20">
        <Reveal as="p" className="kicker">The problem</Reveal>
        <Reveal as="h2" delay={80} className="display mt-4 max-w-3xl" style={{ fontSize: "clamp(28px, 4vw, 44px)" }}>
          Three security domains collapsed into one attack surface overnight.
        </Reveal>
        <div className="mt-12 grid gap-px md:grid-cols-3" style={{ background: "var(--rule-strong)", border: "1px solid var(--rule-strong)" }}>
          {[
            {
              n: "01",
              t: "Wallet code",
              d: "Delegates run in the EOA's storage with the EOA's balance. A bug in the delegate is a bug in every account that trusts it — at once.",
            },
            {
              n: "02",
              t: "Delegate contracts",
              d: "A new contract class with its own failure modes: storage collisions across re-delegations, initializer races, replayable authorizations.",
            },
            {
              n: "03",
              t: "Protocol assumptions",
              d: "Every 'callers with no code are humans' check in DeFi silently stopped being true. Most teams haven't gone looking for theirs yet.",
            },
          ].map((c, i) => (
            <Reveal key={c.n} variant="up" delay={i * 110} className="p-8" style={{ background: "var(--paper)" }}>
              <span className="mono" style={{ fontSize: 12, color: "var(--brand)", fontWeight: 700 }}>{c.n}</span>
              <h3 className="display mt-3" style={{ fontSize: 22 }}>{c.t}</h3>
              <p className="mt-3" style={{ color: "var(--ink-soft)", fontSize: 14 }}>{c.d}</p>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ------------------------------------------------ engines */}
      <section style={{ background: "var(--paper-sunk)", borderTop: "1px solid var(--rule-strong)", borderBottom: "1px solid var(--rule-strong)" }}>
        <div className="wrap py-20">
          <div className="flex flex-wrap items-end justify-between gap-6">
            <Reveal>
              <p className="kicker">The toolkit</p>
              <h2 className="display mt-4" style={{ fontSize: "clamp(28px, 4vw, 44px)" }}>
                Four engines. <span className="uline">One case.</span>
              </h2>
            </Reveal>
            <p className="meta max-w-xs">
              SOLIDITY FOR PROOFS · PYTHON FOR ANALYSIS · EVERYTHING SHIPS WITH TESTS
            </p>
          </div>

          <div className="mt-12 grid gap-6 md:grid-cols-2">
            {ENGINES.map((e, i) => (
              <Reveal key={e.no} variant={i % 2 === 0 ? "left" : "right"} delay={(i % 2) * 90}>
              <Link href={e.href} className="panel p-0 block group lift">
                <div className="panel-head">
                  <span>
                    <span style={{ color: "var(--brand)" }}>{e.no}</span> · {e.name}
                  </span>
                  <span className="group-hover:translate-x-1 transition-transform" aria-hidden>→</span>
                </div>
                <div className="p-6">
                  <p style={{ color: "var(--ink-soft)", fontSize: 14, minHeight: 84 }}>{e.desc}</p>
                  <div className="term mt-5" style={{ boxShadow: "none" }}>
                    <div className="term-body" style={{ padding: "10px 14px" }}>
                      <span className="dim">$ </span>
                      <span className="p">{e.cmd}</span>
                    </div>
                  </div>
                  <p className="meta mt-4">{e.proof.toUpperCase()}</p>
                </div>
              </Link>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ------------------------------------------------ bug ledger */}
      <section className="wrap py-20">
        <div className="flex flex-wrap items-end justify-between gap-6">
          <Reveal>
            <p className="kicker">Known bug classes</p>
            <h2 className="display mt-4" style={{ fontSize: "clamp(28px, 4vw, 44px)" }}>
              The <span className="uline">ledger</span>, so far.
            </h2>
          </Reveal>
          <Link href="/catalog" className="btn btn-line">Full catalog →</Link>
        </div>

        <div className="mt-10 grid gap-10 lg:grid-cols-2">
          <Reveal variant="left">
            <h3 className="panel-head" style={{ border: "none", borderBottom: "2px solid var(--ink)", padding: "0 0 8px" }}>
              <span>Delegate contract bugs</span>
              <span style={{ color: "var(--ink-faint)" }}>DC-01…08</span>
            </h3>
            <LedgerRows entries={DC_ENTRIES} />
          </Reveal>
          <Reveal variant="right" delay={90}>
            <h3 className="panel-head" style={{ border: "none", borderBottom: "2px solid var(--ink)", padding: "0 0 8px" }}>
              <span>Protocol assumption bugs</span>
              <span style={{ color: "var(--ink-faint)" }}>PA-01…05</span>
            </h3>
            <LedgerRows entries={PA_ENTRIES} />
            <div className="panel-flat mt-8 p-5">
              <p className="meta">EVERY ENTRY SHIPS WITH</p>
              <p className="mt-2" style={{ fontSize: 14, color: "var(--ink-soft)" }}>
                Root cause → exploit path → fix → a Foundry PoC that runs. RED proves the exploit,
                GREEN proves the patch. No hand-waving.
              </p>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ------------------------------------------------ audiences */}
      <section style={{ background: "var(--term-bg)" }}>
        <div className="wrap py-20">
          <p className="kicker" style={{ color: "var(--term-hot)" }}>Who runs it</p>
          <h2 className="display mt-4" style={{ fontSize: "clamp(28px, 4vw, 44px)", color: "var(--term-ink)" }}>
            Built for the teams holding the bag.
          </h2>
          <div className="mt-12 grid gap-px md:grid-cols-3" style={{ background: "var(--term-edge)", border: "1px solid var(--term-edge)" }}>
            {AUDIENCES.map((a, i) => (
              <Reveal key={a.who} variant="up" delay={i * 120} className="p-8" style={{ background: "var(--term-bg)" }}>
                <h3 className="display" style={{ fontSize: 21, color: "var(--term-ink)" }}>{a.who}</h3>
                <p className="mono mt-1" style={{ fontSize: 11, letterSpacing: "0.1em", textTransform: "uppercase", color: "var(--term-hot)" }}>
                  {a.need}
                </p>
                <p className="mt-4" style={{ fontSize: 14, color: "var(--term-dim)" }}>{a.pitch}</p>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      {/* ------------------------------------------------ closing CTA */}
      <Reveal as="section" variant="scale" className="wrap py-24 text-center">
        <p className="kicker justify-center flex">Open the file</p>
        <h2 className="display mt-5 mx-auto max-w-3xl" style={{ fontSize: "clamp(32px, 5vw, 56px)" }}>
          Your protocol was audited <em style={{ fontStyle: "italic", color: "var(--brand)" }}>before</em> Pectra.
        </h2>
        <p className="lead mt-5 mx-auto max-w-xl">
          A scan takes minutes. The findings come with proofs. Start with the free tier, or book a
          scoped assessment for the whole codebase.
        </p>
        <div className="mt-9 flex flex-wrap justify-center gap-4">
          <Link href="/scan" className="btn btn-brand">Scan your contracts →</Link>
          <Link href="/pricing" className="btn btn-line">See pricing</Link>
        </div>
      </Reveal>
    </>
  );
}
