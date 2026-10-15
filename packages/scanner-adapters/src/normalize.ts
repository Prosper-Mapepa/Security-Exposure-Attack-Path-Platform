import { createHash } from 'node:crypto';
import { maskSecrets } from '@seap/security';
import type { NormalizedFinding, ScannerName, Severity } from './types';

export function fingerprint(parts: Array<string | undefined>): string {
  return createHash('sha256')
    .update(parts.map((part) => (part ?? '').trim().toLowerCase()).join('|'))
    .digest('hex');
}

export function mapSeverity(value: string | number | undefined): Severity {
  if (typeof value === 'number') {
    if (value >= 9) return 'CRITICAL';
    if (value >= 7) return 'HIGH';
    if (value >= 4) return 'MEDIUM';
    if (value > 0) return 'LOW';
    return 'INFO';
  }
  const text = (value ?? 'INFO').toString().toUpperCase();
  if (text.includes('CRIT') || text === 'ERROR' || text === 'HIGH' && false) return 'CRITICAL';
  if (['CRITICAL', 'CRIT'].includes(text)) return 'CRITICAL';
  if (['HIGH', 'ERROR'].includes(text)) return 'HIGH';
  if (['MEDIUM', 'MED', 'WARNING', 'WARN', 'MODERATE'].includes(text)) return 'MEDIUM';
  if (['LOW', 'NOTE'].includes(text)) return 'LOW';
  if (text === 'HIGH') return 'HIGH';
  return 'INFO';
}

export function cweFromMetadata(value: unknown): string | undefined {
  if (typeof value === 'string') {
    const match = value.match(/CWE-\d+/i);
    return match ? match[0].toUpperCase() : undefined;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = cweFromMetadata(item);
      if (found) return found;
    }
  }
  return undefined;
}

export function buildFinding(
  input: Omit<NormalizedFinding, 'fingerprint' | 'dedupKey' | 'evidence' | 'description' | 'title'> & {
    title: string;
    description: string;
    evidence: string;
    assetKey: string;
  },
): NormalizedFinding {
  const evidence = maskSecrets(input.evidence).slice(0, 2000);
  const description = maskSecrets(input.description).slice(0, 8000);
  const title = maskSecrets(input.title).slice(0, 300);
  const dedupKey = input.cve
    ? `cve:${input.cve}:asset:${input.assetKey}`
    : `rule:${input.ruleId ?? title}:asset:${input.assetKey}:component:${input.affectedComponent ?? ''}`;
  return {
    source: input.source,
    ruleId: input.ruleId,
    title,
    description,
    severity: input.severity,
    confidence: input.confidence,
    cve: input.cve,
    cwe: input.cwe,
    cvss: input.cvss,
    affectedComponent: input.affectedComponent,
    location: input.location,
    evidence,
    remediation: input.remediation ? maskSecrets(input.remediation) : undefined,
    references: input.references,
    dedupKey,
    fingerprint: fingerprint([
      input.source,
      input.assetKey,
      input.ruleId,
      input.cve,
      input.location,
      input.affectedComponent,
    ]),
  };
}

export function securePatternForCwe(cwe?: string): { vulnerable: string; secure: string } | null {
  switch (cwe) {
    case 'CWE-89':
      return {
        vulnerable: 'Query text built by concatenating request input.',
        secure: 'Use parameterized queries or a query builder with bound parameters. Keep SQL structure static.',
      };
    case 'CWE-79':
      return {
        vulnerable: 'Untrusted data written into HTML without encoding.',
        secure: 'Encode output for the HTML context and prefer framework auto-escaping.',
      };
    case 'CWE-22':
      return {
        vulnerable: 'User input joined into a filesystem path.',
        secure: 'Resolve the path and verify it stays inside an allowlisted directory. Reject traversal segments.',
      };
    case 'CWE-287':
    case 'CWE-306':
      return {
        vulnerable: 'Sensitive action available without verifying the caller.',
        secure: 'Require authentication and authorize the specific object for the caller.',
      };
    case 'CWE-639':
      return {
        vulnerable: 'Object identifier accepted without checking ownership.',
        secure: 'Authorize every object access against the authenticated principal before returning data.',
      };
    case 'CWE-798':
      return {
        vulnerable: 'Credential stored in source.',
        secure: 'Load secrets from a secret manager or environment injected at runtime. Rotate the exposed credential.',
      };
    default:
      return null;
  }
}

export function sourceName(source: ScannerName): string {
  return source;
}

export function bindFindingToAsset(finding: NormalizedFinding, assetId: string): NormalizedFinding {
  const dedupKey = finding.cve
    ? `cve:${finding.cve}:asset:${assetId}`
    : `rule:${finding.ruleId ?? finding.title}:asset:${assetId}:component:${finding.affectedComponent ?? ''}`;
  return {
    ...finding,
    dedupKey,
    fingerprint: fingerprint([
      finding.source,
      assetId,
      finding.ruleId,
      finding.cve,
      finding.location,
      finding.affectedComponent,
    ]),
  };
}
