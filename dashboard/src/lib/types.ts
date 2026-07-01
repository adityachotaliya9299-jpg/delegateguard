export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "INFO";

export type BugClass =
  | "DC-01" | "DC-02" | "DC-03" | "DC-04"
  | "DC-05" | "DC-06" | "DC-07" | "DC-08"
  | "PA-01" | "PA-02" | "PA-03" | "PA-04" | "PA-05";

export interface Finding {
  bug_class: BugClass;
  severity: Severity;
  title: string;
  description: string;
  contract: string;
  function: string | null;
  line: number | null;
  source_file: string | null;
  recommendation: string;
  poc_ref: string;
}

export interface ScanResult {
  target: string;
  mode: "delegate-analyze" | "protocol-scan" | "both";
  total: number;
  findings: Finding[];
  duration_ms: number;
  timestamp: string;
}

export type ScanMode = "analyze" | "scan" | "both";

export interface ScanRequest {
  target_url?: string;   // GitHub repo URL
  mode: ScanMode;
  severity_filter?: Severity[];
}