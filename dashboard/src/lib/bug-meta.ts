import type { BugClass } from "./types";

/**
 * Standards mapping for each bug class. CWE is the MITRE weakness id; SWC is the
 * (now-archived but still widely referenced) Smart Contract Weakness Classification.
 * Consumers: the public API response and the audit report generator.
 */
export interface BugMeta {
  cwe: string;
  cweTitle: string;
  swc: string | null;
  swcTitle: string | null;
  references: string[];
}

export const BUG_META: Record<BugClass, BugMeta> = {
  "DC-01": {
    cwe: "CWE-668",
    cweTitle: "Exposure of Resource to Wrong Sphere",
    swc: "SWC-124",
    swcTitle: "Write to Arbitrary Storage Location",
    references: ["https://eips.ethereum.org/EIPS/eip-7201", "https://eips.ethereum.org/EIPS/eip-7702"],
  },
  "DC-02": {
    cwe: "CWE-665",
    cweTitle: "Improper Initialization",
    swc: "SWC-118",
    swcTitle: "Incorrect Constructor Name",
    references: ["https://eips.ethereum.org/EIPS/eip-7702"],
  },
  "DC-03": {
    cwe: "CWE-294",
    cweTitle: "Authentication Bypass by Capture-replay",
    swc: "SWC-121",
    swcTitle: "Missing Protection against Signature Replay Attacks",
    references: ["https://eips.ethereum.org/EIPS/eip-712", "https://eips.ethereum.org/EIPS/eip-7702"],
  },
  "DC-04": {
    cwe: "CWE-306",
    cweTitle: "Missing Authentication for Critical Function",
    swc: "SWC-105",
    swcTitle: "Unprotected Ether Withdrawal",
    references: ["https://eips.ethereum.org/EIPS/eip-7702"],
  },
  "DC-05": {
    cwe: "CWE-829",
    cweTitle: "Inclusion of Functionality from Untrusted Control Sphere",
    swc: "SWC-112",
    swcTitle: "Delegatecall to Untrusted Callee",
    references: ["https://swcregistry.io/docs/SWC-112"],
  },
  "DC-06": {
    cwe: "CWE-294",
    cweTitle: "Authentication Bypass by Capture-replay",
    swc: "SWC-121",
    swcTitle: "Missing Protection against Signature Replay Attacks",
    references: ["https://swcregistry.io/docs/SWC-121"],
  },
  "DC-07": {
    cwe: "CWE-284",
    cweTitle: "Improper Access Control",
    swc: "SWC-105",
    swcTitle: "Unprotected Ether Withdrawal",
    references: ["https://eips.ethereum.org/EIPS/eip-7702"],
  },
  "DC-08": {
    cwe: "CWE-347",
    cweTitle: "Improper Verification of Cryptographic Signature",
    swc: "SWC-117",
    swcTitle: "Signature Malleability",
    references: ["https://swcregistry.io/docs/SWC-117"],
  },
  "PA-01": {
    cwe: "CWE-290",
    cweTitle: "Authentication Bypass by Spoofing",
    swc: "SWC-115",
    swcTitle: "Authorization through tx.origin",
    references: ["https://swcregistry.io/docs/SWC-115"],
  },
  "PA-02": {
    cwe: "CWE-287",
    cweTitle: "Improper Authentication",
    swc: "SWC-115",
    swcTitle: "Authorization through tx.origin",
    references: ["https://swcregistry.io/docs/SWC-115"],
  },
  "PA-03": {
    cwe: "CWE-697",
    cweTitle: "Incorrect Comparison",
    swc: null,
    swcTitle: null,
    references: ["https://eips.ethereum.org/EIPS/eip-7702"],
  },
  "PA-04": {
    cwe: "CWE-841",
    cweTitle: "Improper Enforcement of Behavioral Workflow",
    swc: "SWC-107",
    swcTitle: "Reentrancy",
    references: ["https://swcregistry.io/docs/SWC-107"],
  },
  "PA-05": {
    cwe: "CWE-799",
    cweTitle: "Improper Control of Interaction Frequency",
    swc: null,
    swcTitle: null,
    references: ["https://eips.ethereum.org/EIPS/eip-7702"],
  },
};

export const CVSS_BY_SEVERITY: Record<string, string> = {
  CRITICAL: "9.0–10.0",
  HIGH: "7.0–8.9",
  MEDIUM: "4.0–6.9",
  INFO: "0.0–3.9",
};
