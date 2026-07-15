"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import Logo from "./Logo";
import ScrollProgress from "./ScrollProgress";

const NAV = [
  { href: "/scan", label: "Scanner" },
  { href: "/monitor", label: "Monitor" },
  { href: "/registry", label: "Registry" },
  { href: "/report", label: "Report" },
  { href: "/catalog", label: "Bug Classes" },
  { href: "/pricing", label: "Pricing" },
];

export default function SiteHeader() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  return (
    <header className="sticky top-0 z-50" style={{ background: "var(--paper)" }}>
      {/* meta strip */}
      <div style={{ borderBottom: "1px solid var(--rule)" }}>
        <div className="wrap flex items-center justify-between py-1.5">
          <span className="meta">EIP-7702 SECURITY TOOLKIT · POST-PECTRA</span>
          <span className="meta hidden sm:flex items-center gap-2">
            <span className="blip" style={{ background: "var(--safe)" }} />
            137 TESTS PASSING
          </span>
        </div>
      </div>

      {/* masthead */}
      <div style={{ borderBottom: "1px solid var(--rule-strong)" }}>
        <div className="wrap flex items-center justify-between gap-6 py-3.5">
          <Link href="/" aria-label="DelegateGuard home" onClick={() => setOpen(false)}>
            <Logo compact />
          </Link>

          <nav className="hidden lg:flex items-center gap-7">
            {NAV.map((item) => {
              const active = pathname.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className="mono"
                  style={{
                    fontSize: 12,
                    letterSpacing: "0.09em",
                    textTransform: "uppercase",
                    color: active ? "var(--brand)" : "var(--ink-soft)",
                    borderBottom: active ? "2px solid var(--brand)" : "2px solid transparent",
                    paddingBottom: 2,
                  }}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="hidden lg:flex items-center gap-3">
            <a
              className="btn btn-line"
              style={{ padding: "8px 14px", fontSize: 11.5 }}
              href="https://github.com/adityachotaliya9299-jpg"
              target="_blank"
              rel="noreferrer"
            >
              GitHub
            </a>
            <Link className="btn btn-brand" style={{ padding: "8px 16px", fontSize: 11.5 }} href="/scan">
              Run a scan
            </Link>
          </div>

          {/* wrapped in a bare div: Tailwind's `lg:hidden` on the button itself is
              overridden by our unlayered .btn display, so gate visibility here */}
          <div className="lg:hidden">
            <button
              className="btn btn-line"
              style={{ padding: "7px 13px", fontSize: 11 }}
              onClick={() => setOpen((v) => !v)}
              aria-expanded={open}
              aria-label="Toggle menu"
            >
              {open ? "Close" : "Menu"}
            </button>
          </div>
        </div>
      </div>

      <ScrollProgress />

      {open && (
        <div className="lg:hidden" style={{ borderBottom: "1px solid var(--rule-strong)", background: "var(--paper-raised)" }}>
          <nav className="wrap flex flex-col py-3">
            {NAV.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setOpen(false)}
                className="mono py-3"
                style={{
                  fontSize: 13,
                  letterSpacing: "0.09em",
                  textTransform: "uppercase",
                  color: pathname.startsWith(item.href) ? "var(--brand)" : "var(--ink)",
                  borderBottom: "1px solid var(--rule)",
                }}
              >
                {item.label}
              </Link>
            ))}
            <Link href="/scan" onClick={() => setOpen(false)} className="btn btn-brand mt-4 justify-center">
              Run a scan
            </Link>
          </nav>
        </div>
      )}
    </header>
  );
}
