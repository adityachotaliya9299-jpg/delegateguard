import type { Severity } from "@/lib/types";

const CLASS: Record<string, string> = {
  CRITICAL: "stamp stamp-critical",
  HIGH: "stamp stamp-high",
  MEDIUM: "stamp stamp-medium",
  INFO: "stamp stamp-info",
  SAFE: "stamp stamp-safe",
  MALICIOUS: "stamp stamp-critical",
  SUSPICIOUS: "stamp stamp-high",
  UNKNOWN: "stamp stamp-info",
};

export default function Stamp({ label }: { label: Severity | string }) {
  return <span className={CLASS[label] ?? "stamp stamp-info"}>{label}</span>;
}
