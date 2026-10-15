export interface PolicyAssetContext {
  type: string;
  exposure: string;
  environment: string;
  ownerId?: string | null;
  riskScore?: number | null;
}

export interface PolicyFindingContext {
  severity: string;
  status: string;
}

const SEVERITY_RANK: Record<string, number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const OPEN = new Set(['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'REOPENED']);

export function explainPolicyViolation(
  rule: unknown,
  asset: PolicyAssetContext,
  finding?: PolicyFindingContext,
): string | null {
  if (!rule || typeof rule !== 'object') return null;
  const candidate = rule as {
    type?: string;
    severity?: string;
    exposure?: string;
    environment?: string;
    assetTypes?: string[];
    max?: number;
  };
  if (candidate.type === 'MAX_OPEN_SEVERITY') {
    if (!finding || !OPEN.has(finding.status)) return null;
    if (candidate.exposure && candidate.exposure !== asset.exposure) return null;
    if (candidate.environment && candidate.environment !== asset.environment) return null;
    const limit = SEVERITY_RANK[candidate.severity ?? 'HIGH'] ?? 3;
    if ((SEVERITY_RANK[finding.severity] ?? 0) >= limit) {
      return `Open ${finding.severity} finding exceeds the ${candidate.severity} policy`;
    }
  }
  if (candidate.type === 'REQUIRE_OWNER') {
    if (candidate.assetTypes?.includes(asset.type) && !asset.ownerId) {
      return `${asset.type} assets require an owner`;
    }
  }
  if (candidate.type === 'MAX_RISK_SCORE') {
    if (typeof asset.riskScore === 'number' && typeof candidate.max === 'number' && asset.riskScore > candidate.max) {
      return `Risk score ${asset.riskScore} exceeds the policy maximum of ${candidate.max}`;
    }
  }
  return null;
}
