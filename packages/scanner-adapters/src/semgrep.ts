import path from 'node:path';
import { commandAvailable, runCommand } from './command';
import { buildFinding, cweFromMetadata } from './normalize';
import { normalizeSeverity } from './severity-map';
import type { NormalizedFinding, RawScanOutput, ScanRequest, ScannerAdapter, ScannerStatus } from './types';

interface SemgrepFinding {
  check_id?: string;
  path?: string;
  start?: { line?: number };
  extra?: {
    message?: string;
    severity?: string;
    metadata?: { cwe?: unknown; references?: string[]; likelihood?: string };
    lines?: string;
  };
}

function asFindings(payload: unknown): SemgrepFinding[] {
  if (!payload || typeof payload !== 'object') return [];
  const results = (payload as { results?: unknown }).results;
  return Array.isArray(results) ? (results as SemgrepFinding[]) : [];
}

export class SemgrepAdapter implements ScannerAdapter {
  readonly name = 'SEMGREP' as const;

  constructor(
    private readonly binary = process.env.SEMGREP_BIN ?? 'semgrep',
    private readonly config = process.env.SEMGREP_CONFIG ?? 'auto',
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
    const rules = process.env.SEMGREP_RULES_PATH
      ? path.resolve(process.env.SEMGREP_RULES_PATH)
      : path.resolve(process.cwd(), 'packages/scanner-adapters/rules');
    const args = ['scan', '--json', '--quiet', '--metrics=off', '--config', rules];
    if (this.config && this.config !== 'bundled') {
      args.push('--config', this.config);
    }
    args.push(request.location);
    const result = await runCommand(this.binary, args, {
      cwd: request.workdir,
      timeoutMs: this.timeoutMs,
      signal: request.signal,
    });
    if (!result.stdout.trim()) {
      throw new Error(result.stderr.trim() || 'Semgrep produced no output');
    }
    let payload: unknown;
    try {
      payload = JSON.parse(result.stdout) as unknown;
    } catch {
      throw new Error('Semgrep output was not valid JSON');
    }
    return {
      scanner: this.name,
      format: 'semgrep-json',
      payload,
      logs: [result.stderr].filter(Boolean),
    };
  }

  parseResults(raw: RawScanOutput): NormalizedFinding[] {
    return asFindings(raw.payload).map((finding) => this.normalizeFinding(finding));
  }

  normalizeFinding(rawFinding: unknown): NormalizedFinding {
    const finding = (rawFinding ?? {}) as SemgrepFinding;
    const cwe = cweFromMetadata(finding.extra?.metadata?.cwe);
    const location = finding.path
      ? `${finding.path}:${finding.start?.line ?? 1}`
      : undefined;
    return buildFinding({
      source: 'SEMGREP',
      assetKey: 'target',
      ruleId: finding.check_id,
      title: finding.extra?.message ?? finding.check_id?.split('.').pop() ?? 'Semgrep finding',
      description: finding.extra?.message ?? 'Semgrep reported a code finding',
      severity: normalizeSeverity(finding.extra?.severity),
      confidence: finding.extra?.metadata?.likelihood === 'HIGH' ? 0.8 : 0.6,
      cwe,
      affectedComponent: finding.path,
      location,
      evidence: finding.extra?.lines ?? finding.extra?.message ?? '',
      remediation: 'Review the matched code and apply the secure pattern for the referenced CWE.',
      references: finding.extra?.metadata?.references ?? [],
    });
  }
}
