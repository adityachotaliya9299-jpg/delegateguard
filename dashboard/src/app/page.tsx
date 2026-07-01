import Link from "next/link";
import Nav from "@/components/Nav";
import DelegationDesignator from "@/components/DelegationDesignator";
import GithubIcon from "@/components/GithubIcon";
import { Shield, Terminal, Search, FileCode, ArrowRight, CheckCircle, Zap, Lock } from "lucide-react";

const STATS = [
  { value: "13", label: "Bug classes covered" },
  { value: "51", label: "Foundry PoC tests" },
  { value: "8",  label: "DC detectors (E1)" },
  { value: "5",  label: "PA detectors (E2)" },
];

const FEATURES = [
  {
    icon: <Search size={18} color="var(--cyan)" />,
    id: "E1",
    title: "Delegate analyzer",
    desc: "Static analysis of EIP-7702 delegate contracts. Detects storage collisions, sweeper patterns, missing auth, cross-chain replay, and 5 more bug classes.",
    cmd: "delegateguard analyze contracts/",
  },
  {
    icon: <Shield size={18} color="var(--cyan)" />,
    id: "E2",
    title: "Protocol scanner",
    desc: "Scans any Solidity codebase for post-Pectra EOA assumptions. Flags tx.origin auth, extcodesize gates, EOA-only reentrancy paths, and Sybil vulnerabilities.",
    cmd: "delegateguard scan protocol/",
  },
  {
    icon: <FileCode size={18} color="var(--cyan)" />,
    id: "E3",
    title: "Harness generator",
    desc: "Turns any finding into a runnable Foundry test scaffold. Pre-stubbed red/green test pairs with exact source location. One command, compile-ready output.",
    cmd: "delegateguard harness contracts/ --out harnesses/",
  },
];

const DC_BUGS = [
  { id: "DC-01", name: "Storage collision on re-delegation",  sev: "HIGH" },
  { id: "DC-02", name: "Unprotected initializer",            sev: "HIGH" },
  { id: "DC-03", name: "Cross-chain replay (chain_id=0)",    sev: "CRITICAL" },
  { id: "DC-04", name: "Missing per-call authentication",    sev: "HIGH" },
  { id: "DC-05", name: "Unsafe inner DELEGATECALL",          sev: "CRITICAL" },
  { id: "DC-06", name: "Batch replay / nonce gaps",          sev: "HIGH" },
  { id: "DC-07", name: "Sweeper pattern",                    sev: "CRITICAL" },
  { id: "DC-08", name: "Signature malleability",             sev: "MEDIUM" },
];

const PA_BUGS = [
  { id: "PA-01", name: "tx.origin authentication",           sev: "HIGH" },
  { id: "PA-02", name: "msg.sender == tx.origin EOA gate",   sev: "HIGH" },
  { id: "PA-03", name: "extcodesize == 0 EOA check",         sev: "HIGH" },
  { id: "PA-04", name: "EOA-only reentrancy paths",          sev: "CRITICAL" },
  { id: "PA-05", name: "EOA = unique human assumption",      sev: "MEDIUM" },
];

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "var(--red)",
  HIGH:     "var(--yellow)",
  MEDIUM:   "#818CF8",
};

export default function Home() {
  return (
    <main style={{ minHeight: "100vh" }}>
      <Nav />

      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <section style={{
        paddingTop: 140, paddingBottom: 100,
        paddingLeft: 24, paddingRight: 24,
        maxWidth: 1100, margin: "0 auto",
        position: "relative",
      }}>
        <div style={{
          position: "absolute", inset: 0, zIndex: 0, pointerEvents: "none",
          backgroundImage: "radial-gradient(ellipse 60% 40% at 50% 0%, rgba(0,229,255,0.055), transparent)",
        }} />

        <div style={{ position: "relative", zIndex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 24 }}>
            <span className="section-label">Post-Pectra security</span>
            <span style={{ width: 40, height: 1, background: "var(--cyan)", opacity: 0.4 }} />
            <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>EIP-7702</span>
          </div>

          <h1 className="mono" style={{
            fontSize: "clamp(30px, 5vw, 56px)",
            fontWeight: 700, lineHeight: 1.1,
            letterSpacing: "-0.03em",
            marginBottom: 24, color: "var(--text)",
          }}>
            Security analysis for<br />
            <span style={{ color: "var(--cyan)" }}>delegate contracts</span>
          </h1>

          <p style={{ fontSize: 17, color: "var(--text-secondary)", lineHeight: 1.7, maxWidth: 540, marginBottom: 36 }}>
            EIP-7702 lets any EOA delegate execution to a contract. DelegateGuard is the specialist toolkit that finds the 13 bug classes this creates before attackers do.
          </p>

          <div style={{ marginBottom: 48 }}>
            <DelegationDesignator />
          </div>

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <Link href="/dashboard">
              <button className="btn-primary" style={{ fontSize: 14 }}>
                Open dashboard <ArrowRight size={15} />
              </button>
            </Link>
            <a href="https://github.com/adityachotaliya9299-jpg/delegateguard" target="_blank" rel="noopener noreferrer">
              <button className="btn-ghost" style={{ fontSize: 14 }}>
                <GithubIcon size={15} /> View on GitHub
              </button>
            </a>
          </div>
        </div>
      </section>

      {/* ── Stats bar ────────────────────────────────────────────────────── */}
      <div style={{ borderTop: "1px solid var(--border)", borderBottom: "1px solid var(--border)", padding: "24px", background: "var(--bg-card)" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 24 }}>
          {STATS.map(s => (
            <div key={s.label} style={{ textAlign: "center" }}>
              <div className="mono" style={{ fontSize: 28, fontWeight: 700, color: "var(--cyan)", letterSpacing: "-0.03em" }}>{s.value}</div>
              <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Features ─────────────────────────────────────────────────────── */}
      <section id="features" style={{ padding: "80px 24px", maxWidth: 1100, margin: "0 auto" }}>
        <div style={{ marginBottom: 40 }}>
          <span className="section-label">Three engines</span>
          <h2 className="mono" style={{ fontSize: 28, fontWeight: 600, marginTop: 8, letterSpacing: "-0.02em" }}>
            Built for the full audit workflow
          </h2>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 16 }}>
          {FEATURES.map(f => (
            <div key={f.id} className="card" style={{ padding: "22px 24px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
                <div style={{
                  width: 34, height: 34, borderRadius: 8,
                  background: "var(--cyan-glow)", border: "1px solid rgba(0,229,255,0.18)",
                  display: "flex", alignItems: "center", justifyContent: "center",
                }}>
                  {f.icon}
                </div>
                <div>
                  <span className="mono" style={{ fontSize: 11, color: "var(--cyan)", display: "block" }}>{f.id}</span>
                  <span style={{ fontSize: 15, fontWeight: 500 }}>{f.title}</span>
                </div>
              </div>

              <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.65, marginBottom: 16 }}>{f.desc}</p>

              <div style={{ background: "var(--bg-elevated)", borderRadius: 6, padding: "8px 12px", border: "1px solid var(--border)" }}>
                <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)" }}>$ </span>
                <span className="mono" style={{ fontSize: 12, color: "var(--cyan-dim)" }}>{f.cmd}</span>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ── Coverage ─────────────────────────────────────────────────────── */}
      <section id="coverage" style={{ padding: "0 24px 80px", maxWidth: 1100, margin: "0 auto" }}>
        <div className="glow-line" style={{ marginBottom: 48 }} />

        <div style={{ marginBottom: 40 }}>
          <span className="section-label">Complete coverage</span>
          <h2 className="mono" style={{ fontSize: 28, fontWeight: 600, marginTop: 8, letterSpacing: "-0.02em" }}>
            13 bug classes, all reproduced in Foundry
          </h2>
          <p style={{ fontSize: 14, color: "var(--text-secondary)", marginTop: 8, maxWidth: 500 }}>
            Every class has a runnable PoC, a fixed version, and a detector. Not described, proven.
          </p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
          {/* DC bugs */}
          <div>
            <p style={{ fontSize: 11, fontFamily: "monospace", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 12 }}>
              Delegate-contract bugs (E1)
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {DC_BUGS.map(b => (
                <div key={b.id} className="card" style={{ padding: "10px 14px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <CheckCircle size={13} color="var(--green)" />
                    <span className="mono" style={{ fontSize: 12, color: "var(--cyan)", minWidth: 44 }}>{b.id}</span>
                    <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{b.name}</span>
                  </div>
                  <span style={{ fontSize: 10, fontFamily: "monospace", color: SEV_COLOR[b.sev], background: `${SEV_COLOR[b.sev]}18`, padding: "1px 7px", borderRadius: 3 }}>
                    {b.sev}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* PA bugs + CTA */}
          <div>
            <p style={{ fontSize: 11, fontFamily: "monospace", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: 12 }}>
              Protocol-assumption bugs (E2)
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {PA_BUGS.map(b => (
                <div key={b.id} className="card" style={{ padding: "10px 14px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <CheckCircle size={13} color="var(--green)" />
                    <span className="mono" style={{ fontSize: 12, color: "var(--cyan)", minWidth: 44 }}>{b.id}</span>
                    <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>{b.name}</span>
                  </div>
                  <span style={{ fontSize: 10, fontFamily: "monospace", color: SEV_COLOR[b.sev], background: `${SEV_COLOR[b.sev]}18`, padding: "1px 7px", borderRadius: 3 }}>
                    {b.sev}
                  </span>
                </div>
              ))}
            </div>

            <div style={{
              marginTop: 16, padding: "20px 22px",
              border: "1px solid rgba(0,229,255,0.18)", borderRadius: 10,
              background: "var(--cyan-glow)",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <Lock size={15} color="var(--cyan)" />
                <span style={{ fontSize: 14, fontWeight: 500 }}>Request a 7702 audit</span>
              </div>
              <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 14 }}>
                Scoped delegate-contract and protocol-assumption reviews. Written contract, 50% upfront.
              </p>
              <a href="mailto:audit@delegateguard.io" style={{ textDecoration: "none" }}>
                <button className="btn-primary" style={{ fontSize: 13, padding: "8px 16px" }}>
                  Get in touch <ArrowRight size={13} />
                </button>
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* ── CLI section ──────────────────────────────────────────────────── */}
      <section style={{ borderTop: "1px solid var(--border)", padding: "72px 24px", background: "var(--bg-card)" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto", display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 40, flexWrap: "wrap" }}>
          <div style={{ maxWidth: 420 }}>
            <span className="section-label">CLI-first</span>
            <h2 className="mono" style={{ fontSize: 26, fontWeight: 600, marginTop: 8, letterSpacing: "-0.02em" }}>
              Runs anywhere.<br />Integrates everywhere.
            </h2>
            <p style={{ fontSize: 14, color: "var(--text-secondary)", lineHeight: 1.7, marginTop: 12 }}>
              Install once, scan any Solidity repo. JSON output pipes into your existing CI. GitHub Action wrapper in roadmap.
            </p>
            <div style={{ display: "flex", gap: 20, marginTop: 24, flexWrap: "wrap" }}>
              {[
                { icon: <Zap size={14} />, text: "Slither-based" },
                { icon: <Terminal size={14} />, text: "CI-ready JSON" },
                { icon: <Shield size={14} />, text: "Open source core" },
              ].map(item => (
                <div key={item.text} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-secondary)" }}>
                  <span style={{ color: "var(--cyan)" }}>{item.icon}</span>
                  {item.text}
                </div>
              ))}
            </div>
          </div>

          <div className="card-elevated" style={{ flex: 1, minWidth: 300, maxWidth: 560, padding: "20px 24px" }}>
            <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
              {["#FF5F57", "#FEBC2E", "#28C840"].map(c => (
                <div key={c} style={{ width: 10, height: 10, borderRadius: "50%", background: c }} />
              ))}
              <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)", marginLeft: 8 }}>terminal</span>
            </div>
            {[
              { prompt: true,  text: "pip install delegateguard" },
              { prompt: true,  text: "delegateguard analyze contracts/" },
              { prompt: false, text: "Analyzer: 8 detectors  Running Slither..." },
              { prompt: false, text: "Found 3 issue(s): 2 CRITICAL  1 HIGH" },
              { prompt: false, text: "" },
              { prompt: true,  text: "delegateguard harness contracts/ --out harnesses/" },
              { prompt: false, text: "Generated 3 harness(es) in harnesses/" },
            ].map((line, i) => (
              <div key={i} className="mono" style={{ fontSize: 12, lineHeight: 1.9 }}>
                {line.prompt
                  ? <><span style={{ color: "var(--cyan)" }}>$ </span><span style={{ color: "var(--text)" }}>{line.text}</span></>
                  : <span style={{ color: "var(--text-muted)" }}>{line.text}</span>
                }
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Footer ───────────────────────────────────────────────────────── */}
      <footer style={{ borderTop: "1px solid var(--border)", padding: "28px 24px" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Shield size={15} color="var(--cyan)" />
            <span className="mono" style={{ fontSize: 13, color: "var(--text-muted)" }}>DelegateGuard</span>
            <span style={{ fontSize: 12, color: "var(--text-muted)" }}>MIT License</span>
          </div>
          <div style={{ display: "flex", gap: 20 }}>
            {[
              { href: "https://github.com/adityachotaliya9299-jpg/delegateguard", label: "GitHub" },
              { href: "/docs/THREAT_MODEL.md", label: "Threat model" },
              { href: "mailto:audit@delegateguard.io", label: "Request audit" },
            ].map(l => (
              <a key={l.label} href={l.href} target={l.href.startsWith("http") ? "_blank" : undefined}
                rel="noopener noreferrer"
                style={{ fontSize: 12, color: "var(--text-muted)", textDecoration: "none" }}
                className="hover:text-white transition-colors">{l.label}</a>
            ))}
          </div>
        </div>
      </footer>
    </main>
  );
}