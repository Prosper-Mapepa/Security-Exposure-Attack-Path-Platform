import { commandAvailable, runCommand } from './command';
import { buildFinding, cweFromMetadata } from './normalize';
import { normalizeSeverity } from './severity-map';
import type { NormalizedFinding, RawScanOutput, ScanRequest, ScannerAdapter, ScannerStatus } from './types';

interface TrivyVuln {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
  References?: string[];
  CweIDs?: string[];
  CVSS?: Record<string, { V3Score?: number }>;
}

interface TrivyResult {
  Target?: string;
  Vulnerabilities?: TrivyVuln[];
}

function resultsOf(payload: unknown): TrivyResult[] {
  if (!payload || typeof payload !== 'object') return [];
  const results = (payload as { Results?: unknown }).Results;
  return Array.isArray(results) ? (results as TrivyResult[]) : [];
}

function cvssOf(vuln: TrivyVuln): number | undefined {
  const scores = Object.values(vuln.CVSS ?? {})
    .map((entry) => entry.V3Score)
    .filter((score): score is number => typeof score === 'number');
  if (scores.length === 0) return undefined;
  return Math.max(...scores);
}

export class TrivyAdapter implements ScannerAdapter {
  readonly name = 'TRIVY' as const;

  constructor(
    private readonly binary = process.env.TRIVY_BIN ?? 'trivy',
    private readonly timeoutMs = Number(process.env.SCAN_COMMAND_TIMEOUT_MS ?? 600_000),
  ) {}

  async getStatus(): Promise<ScannerStatus> {
    const available = await commandAvailable(this.binary);
    return {
      scanner: this.name,
      available,
      detail: available ? `${this.binary} is installed` : `${this.binary} is not installed`,
    };
  }

  async scan(request: ScanRequest): Promise<RawScanOutput> {
    const mode = request.targetType === 'IMAGE' ? 'image' : 'fs';
    const args = [
      mode,
      '--format',
      'json',
      '--quiet',
      '--scanners',
      'vuln',
      request.location,
    ];
    const result = await runCommand(this.binary, args, {
      cwd: request.workdir,
      timeoutMs: this.timeoutMs,
      signal: request.signal,
    });
    if (!result.stdout.trim()) {
      throw new Error(result.stderr.trim() || 'Trivy produced no output');
    }
    return {
      scanner: this.name,
      format: 'trivy-json',
      payload: JSON.parse(result.stdout) as unknown,
      logs: [result.stderr].filter(Boolean),
    };
  }

  parseResults(raw: RawScanOutput): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];
    for (const result of resultsOf(raw.payload)) {
      for (const vuln of result.Vulnerabilities ?? []) {
        findings.push(this.normalizeFinding({ ...vuln, Target: result.Target }));
      }
    }
    return findings;
  }

  normalizeFinding(rawFinding: unknown): NormalizedFinding {
    const vuln = (rawFinding ?? {}) as TrivyVuln & { Target?: string };
    const component = [vuln.PkgName, vuln.InstalledVersion].filter(Boolean).join('@');
    return buildFinding({
      source: 'TRIVY',
      assetKey: 'target',
      ruleId: vuln.VulnerabilityID,
      title: vuln.Title || vuln.VulnerabilityID || 'Vulnerable package',
      description: vuln.Description || `${component} is affected by ${vuln.VulnerabilityID ?? 'a known vulnerability'}`,
      severity: normalizeSeverity(vuln.Severity),
      confidence: 0.9,
      cve: vuln.VulnerabilityID,
      cwe: cweFromMetadata(vuln.CweIDs),
      cvss: cvssOf(vuln),
      affectedComponent: component || vuln.Target,
      location: vuln.Target,
      evidence: `Installed ${vuln.InstalledVersion ?? 'unknown'}; fixed ${vuln.FixedVersion || 'unavailable'}`,
      remediation: vuln.FixedVersion
        ? `Upgrade ${vuln.PkgName ?? 'the package'} to ${vuln.FixedVersion} or later.`
        : 'Review the advisory and remove or replace the affected package if no fix is available.',
      references: [vuln.PrimaryURL, ...(vuln.References ?? [])].filter((item): item is string => Boolean(item)),
    });
  }
}
