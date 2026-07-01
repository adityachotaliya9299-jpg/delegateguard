"use client";
import { useState, useEffect } from "react";
import Link from "next/link";
import { Shield, ExternalLink } from "lucide-react";
import GithubIcon from "./GithubIcon";

export default function Nav() {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", onScroll);
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <nav style={{
      position: "fixed", top: 0, left: 0, right: 0, zIndex: 50,
      borderBottom: scrolled ? "1px solid var(--border)" : "1px solid transparent",
      background: scrolled ? "rgba(10,10,15,0.92)" : "transparent",
      backdropFilter: scrolled ? "blur(12px)" : "none",
      transition: "all 0.2s ease",
      padding: "0 24px",
    }}>
      <div style={{ maxWidth: 1100, margin: "0 auto", height: 60, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <Link href="/" style={{ display: "flex", alignItems: "center", gap: 8, textDecoration: "none" }}>
          <Shield size={20} color="var(--cyan)" />
          <span className="mono" style={{ fontSize: 15, fontWeight: 600, color: "var(--text)", letterSpacing: "-0.02em" }}>
            DelegateGuard
          </span>
        </Link>

        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {[
            { href: "/#features", label: "Features" },
            { href: "/#coverage", label: "Coverage" },
            { href: "/dashboard", label: "Dashboard" },
          ].map(l => (
            <Link key={l.href} href={l.href} style={{ color: "var(--text-secondary)", fontSize: 13, textDecoration: "none", padding: "6px 12px" }}
              className="hover:text-white transition-colors">{l.label}</Link>
          ))}

          <div style={{ width: 1, height: 20, background: "var(--border-strong)", margin: "0 6px" }} />

          <a href="https://github.com/adityachotaliya9299-jpg/delegateguard"
            target="_blank" rel="noopener noreferrer"
            style={{ color: "var(--text-secondary)", padding: "6px 8px", display: "flex", alignItems: "center" }}
            className="hover:text-white transition-colors">
            <GithubIcon size={17} />
          </a>

          <Link href="/dashboard">
            <button className="btn-primary" style={{ fontSize: 13, padding: "7px 16px" }}>
              Run scan <ExternalLink size={13} />
            </button>
          </Link>
        </div>
      </div>
    </nav>
  );
}