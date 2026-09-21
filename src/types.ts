export interface FindingItem {
  id: string;
  title: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  confidence?: string;
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  references?: string[];
}

export interface ScanRecord {
  scan_id: string;
  target: string;
  modules: string[];
  started_at: string;
  completed_at?: string;
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  risk_assessment: {
    score: number;
    level: string;
    status: string;
    counts: {
      CRITICAL: number;
      HIGH: number;
      MEDIUM: number;
      LOW: number;
      INFO: number;
    };
  };
  findings: FindingItem[];
  module_results?: Record<string, any>;
}

export interface LabStatus {
  running: boolean;
  url: string | null;
  canary: string | null;
  raw?: string;
}
