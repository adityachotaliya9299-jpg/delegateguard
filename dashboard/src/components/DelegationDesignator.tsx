"use client";
import { useEffect, useState } from "react";

const ADDRESSES = [
  "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488",
  "0xBF...malicious_sweeper",
  "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
  "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
];

export default function DelegationDesignator() {
  const [addrIndex, setAddrIndex] = useState(0);
  const [chars, setChars] = useState(0);
  const [phase, setPhase] = useState<"typing" | "hold" | "clearing">("typing");

  const currentAddr = ADDRESSES[addrIndex];

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;

    if (phase === "typing") {
      if (chars < currentAddr.length) {
        timer = setTimeout(() => setChars(c => c + 1), 28);
      } else {
        timer = setTimeout(() => setPhase("hold"), 1800);
      }
    } else if (phase === "hold") {
      timer = setTimeout(() => setPhase("clearing"), 200);
    } else {
      if (chars > 0) {
        timer = setTimeout(() => setChars(c => c - 1), 12);
      } else {
        setAddrIndex(i => (i + 1) % ADDRESSES.length);
        setPhase("typing");
      }
    }

    return () => clearTimeout(timer);
  }, [phase, chars, currentAddr]);

  const isMalicious = currentAddr.includes("malicious");

  return (
    <div className="mono" style={{
      fontSize: "clamp(13px, 2vw, 17px)",
      letterSpacing: "0.04em",
      display: "flex", alignItems: "center", flexWrap: "wrap", gap: 4,
      padding: "16px 20px",
      background: "var(--bg-elevated)",
      border: "1px solid var(--border-strong)",
      borderRadius: 8,
      maxWidth: 680,
    }}>
      <span style={{ color: "var(--text-muted)" }}>EOA code slot:</span>
      <span style={{ color: "var(--cyan)", marginLeft: 8 }}>0xef0100</span>
      <span style={{ color: "var(--text-muted)" }}> || </span>
      <span style={{
        color: isMalicious ? "var(--red)" : "var(--text)",
        transition: "color 0.2s",
      }}>
        {currentAddr.slice(0, chars)}
      </span>
      <span className="animate-blink" style={{ color: "var(--cyan)", marginLeft: 1 }}>█</span>
      {isMalicious && chars > 8 && (
        <span style={{
          marginLeft: 10, fontSize: 11,
          background: "var(--red-dim)", color: "var(--red)",
          border: "1px solid rgba(255,59,59,0.3)",
          padding: "1px 7px", borderRadius: 4,
        }}>
          ⚠ sweeper detected
        </span>
      )}
    </div>
  );
}