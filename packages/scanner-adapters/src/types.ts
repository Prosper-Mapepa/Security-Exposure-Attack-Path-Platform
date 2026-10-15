export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type ScannerName = 'SEMGREP' | 'TRIVY' | 'ZAP' | 'GITLEAKS';

export interface ScanRequest {
  scanId: string;
  targetType: 'PATH' | 'GIT' | 'URL' | 'IMAGE';
  location: string;
  workdir: string;
  signal?: AbortSignal;
}

export interface RawScanOutput {
  scanner: ScannerName;
  format: string;
  payload: unknown;
  logs: string[];
}

export interface NormalizedFinding {
  source: ScannerName;
  ruleId?: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  cve?: string;
  cwe?: string;
  cvss?: number;
  affectedComponent?: string;
  location?: string;
  evidence: string;
  remediation?: string;
  references: string[];
  fingerprint: string;
  dedupKey: string;
}

export interface ScannerStatus {
  scanner: ScannerName;
  available: boolean;
  detail: string;
}

export interface ScannerAdapter {
  readonly name: ScannerName;
  scan(request: ScanRequest): Promise<RawScanOutput>;
  getStatus(): Promise<ScannerStatus>;
  parseResults(raw: RawScanOutput): NormalizedFinding[];
  normalizeFinding(rawFinding: unknown): NormalizedFinding;
}
