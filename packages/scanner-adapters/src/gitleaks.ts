import { access } from 'node:fs/promises';
import path from 'node:path';
import { commandAvailable, runCommand } from './command';
import { buildFinding } from './normalize';
import type { NormalizedFinding, RawScanOutput, ScanRequest, ScannerAdapter, ScannerStatus } from './types';

interface GitleaksFinding {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  Commit?: string;
  Fingerprint?: string;
  Secret?: string;
}

function asArray(payload: unknown): GitleaksFinding[] {
  return Array.isArray(payload) ? (payload as GitleaksFinding[]) : [];
}

export class GitleaksAdapter implements ScannerAdapter {
  readonly name = 'GITLEAKS' as const;

  constructor(
    private readonly binary = process.env.GITLEAKS_BIN ?? 'gitleaks',
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
    const report = `${request.workdir}/gitleaks-${request.scanId}.json`;
    const args = ['detect', '--source', request.location, '--report-format', 'json', '--report-path', report, '--no-banner', '--exit-code', '0'];
    if (!(await isGitCheckout(request.location))) args.push('--no-git');
    const result = await runCommand(this.binary, args, {
      cwd: request.workdir,
      timeoutMs: this.timeoutMs,
      signal: request.signal,
    });
    const fs = await import('node:fs/promises');
    const text = await fs.readFile(report, 'utf8').catch(() => '[]');
    await fs.unlink(report).catch(() => undefined);
    const payload = JSON.parse(text || '[]') as unknown;
    if (Array.isArray(payload)) {
      for (const item of payload) {
        if (item && typeof item === 'object') {
          const record = item as Record<string, unknown>;
          delete record.Secret;
          delete record.Match;
        }
      }
    }
    return {
      scanner: this.name,
      format: 'gitleaks-json',
      payload,
      logs: [result.stderr].filter(Boolean),
    };
  }

  parseResults(raw: RawScanOutput): NormalizedFinding[] {
    return asArray(raw.payload).map((finding) => this.normalizeFinding(finding));
  }

  normalizeFinding(rawFinding: unknown): NormalizedFinding {
    const finding = (rawFinding ?? {}) as GitleaksFinding;
    const location = finding.File ? `${finding.File}:${finding.StartLine ?? 1}` : undefined;
    return buildFinding({
      source: 'GITLEAKS',
      assetKey: 'target',
      ruleId: finding.RuleID,
      title: `Secret detected: ${finding.RuleID ?? 'credential'}`,
      description: finding.Description || 'A secret pattern was detected in source. The secret value is not stored.',
      severity: 'HIGH',
      confidence: 0.85,
      cwe: 'CWE-798',
      affectedComponent: finding.File,
      location,
      evidence: `type=${finding.RuleID ?? 'unknown'}; file=${finding.File ?? 'unknown'}; commit=${finding.Commit ?? 'unknown'}; fingerprint=${finding.Fingerprint ?? 'n/a'}; secret=[REDACTED]`,
      remediation: 'Remove the secret from source, rotate it, and load it from a secret manager.',
      references: ['https://cwe.mitre.org/data/definitions/798.html'],
    });
  }
}

async function isGitCheckout(location: string): Promise<boolean> {
  try {
    await access(path.join(location, '.git'));
    return true;
  } catch {
    return false;
  }
}
