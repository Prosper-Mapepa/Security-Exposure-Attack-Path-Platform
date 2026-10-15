import { DEFAULT_RISK_WEIGHTS, RISK_FORMULA_VERSION, type RiskWeights } from '@seap/shared';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Criticality = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type Exposure = 'PUBLIC' | 'INTERNAL' | 'PRIVATE' | 'UNKNOWN';
export type DataSensitivity = 'RESTRICTED' | 'CONFIDENTIAL' | 'INTERNAL' | 'PUBLIC' | 'UNKNOWN';
export type Privilege = 'NONE' | 'LOW' | 'HIGH' | 'UNKNOWN';

export interface RiskInput {
  cvss?: number | null;
  severity: Severity;
  knownExploited?: boolean;
  publicExploit?: boolean;
  exploitIntelAvailable?: boolean;
  criticality: Criticality;
  exposure: Exposure;
  internetFacing?: boolean;
  authRequired?: boolean | null;
  privilegeRequired?: Privilege | null;
  dataSensitivity: DataSensitivity;
  firstSeen: Date;
  now?: Date;
  onAttackPath?: boolean;
  onSensitiveAttackPath?: boolean;
  compensatingControlScore?: number;
  weights?: Partial<RiskWeights>;
}

export interface RiskFactor {
  key: string;
  label: string;
  normalized: number;
  weight: number;
  contribution: number;
  reason: string;
}

export interface RiskResult {
  formulaVersion: string;
  score: number;
  rating: Severity;
  factors: RiskFactor[];
  summary: string;
}

const SEVERITY_SCORE: Record<Severity, number> = {
  CRITICAL: 9.5,
  HIGH: 7.5,
  MEDIUM: 5,
  LOW: 2.5,
  INFO: 0,
};

const CRITICALITY_SCORE: Record<Criticality, number> = {
  CRITICAL: 10,
  HIGH: 7,
  MEDIUM: 4,
  LOW: 1,
};

const EXPOSURE_SCORE: Record<Exposure, number> = {
  PUBLIC: 10,
  INTERNAL: 5,
  PRIVATE: 2,
  UNKNOWN: 4,
};

const DATA_SCORE: Record<DataSensitivity, number> = {
  RESTRICTED: 10,
  CONFIDENTIAL: 7,
  INTERNAL: 4,
  PUBLIC: 1,
  UNKNOWN: 3,
};

const PRIVILEGE_SCORE: Record<Privilege, number> = {
  NONE: 10,
  LOW: 6,
  HIGH: 2,
  UNKNOWN: 5,
};

function clamp(value: number, min = 0, max = 10): number {
  return Math.min(max, Math.max(min, value));
}

function ratingFor(score: number): Severity {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  if (score >= 15) return 'LOW';
  return 'INFO';
}

function mergeWeights(partial?: Partial<RiskWeights>): RiskWeights {
  return { ...DEFAULT_RISK_WEIGHTS, ...partial };
}

export function calculateRisk(input: RiskInput): RiskResult {
  const weights = mergeWeights(input.weights);
  const now = input.now ?? new Date();
  const technical = input.cvss != null ? clamp(input.cvss) : SEVERITY_SCORE[input.severity];

  let exploitability = 2;
  const exploitReasons: string[] = [];
  if (input.exploitIntelAvailable) {
    exploitability = 2;
    if (input.knownExploited) {
      exploitability += 4;
      exploitReasons.push('Known exploited vulnerability');
    }
    if (input.publicExploit) {
      exploitability += 2;
      exploitReasons.push('Public exploit reference');
    }
    if ((input.cvss ?? 0) >= 9) {
      exploitability += 2;
      exploitReasons.push('CVSS at or above 9');
    }
  } else {
    exploitability = { CRITICAL: 7, HIGH: 5, MEDIUM: 3, LOW: 1, INFO: 0 }[input.severity];
    exploitReasons.push('Estimated from severity because no threat-intel feed is connected');
  }
  exploitability = clamp(exploitability);

  const business = CRITICALITY_SCORE[input.criticality];
  const exposure = input.internetFacing ? 10 : EXPOSURE_SCORE[input.exposure];
  const authentication = input.authRequired === false ? 10 : input.authRequired === true ? 3 : 6;
  const privilege = PRIVILEGE_SCORE[input.privilegeRequired ?? 'UNKNOWN'];
  const data = DATA_SCORE[input.dataSensitivity];
  const ageDays = Math.max(0, (now.getTime() - input.firstSeen.getTime()) / 86_400_000);
  const age = clamp(ageDays / 18);
  const attackPath = input.onSensitiveAttackPath ? 10 : input.onAttackPath ? 6 : 0;
  const controls = clamp(input.compensatingControlScore ?? 0);

  const positive: Array<Omit<RiskFactor, 'contribution'> & { points: number }> = [
    {
      key: 'technical',
      label: 'Technical severity',
      normalized: technical,
      weight: weights.technical,
      points: technical,
      reason: input.cvss != null ? `CVSS ${input.cvss}` : `Severity ${input.severity} mapped to ${technical}`,
    },
    {
      key: 'exploitability',
      label: 'Exploitability',
      normalized: exploitability,
      weight: weights.exploitability,
      points: exploitability,
      reason: exploitReasons.join('; '),
    },
    {
      key: 'business',
      label: 'Business impact',
      normalized: business,
      weight: weights.business,
      points: business,
      reason: `Asset criticality ${input.criticality}`,
    },
    {
      key: 'exposure',
      label: 'Exposure',
      normalized: exposure,
      weight: weights.exposure,
      points: exposure,
      reason: input.internetFacing ? 'Internet-facing asset' : `Exposure ${input.exposure}`,
    },
    {
      key: 'authentication',
      label: 'Authentication requirement',
      normalized: authentication,
      weight: weights.authentication,
      points: authentication,
      reason:
        input.authRequired === false
          ? 'No authentication required'
          : input.authRequired === true
            ? 'Authentication required'
            : 'Authentication requirement unknown',
    },
    {
      key: 'privilege',
      label: 'Privilege required',
      normalized: privilege,
      weight: weights.privilege,
      points: privilege,
      reason: `Privilege required ${input.privilegeRequired ?? 'UNKNOWN'}`,
    },
    {
      key: 'data',
      label: 'Data sensitivity',
      normalized: data,
      weight: weights.data,
      points: data,
      reason: `Data sensitivity ${input.dataSensitivity}`,
    },
    {
      key: 'age',
      label: 'Vulnerability age',
      normalized: Number(age.toFixed(2)),
      weight: weights.age,
      points: age,
      reason: `${Math.floor(ageDays)} days open`,
    },
    {
      key: 'attackPath',
      label: 'Attack-path context',
      normalized: attackPath,
      weight: weights.attackPath,
      points: attackPath,
      reason: input.onSensitiveAttackPath
        ? 'Part of an attack path to a sensitive asset'
        : input.onAttackPath
          ? 'Part of an attack path'
          : 'Not currently on an attack path',
    },
  ];

  const factors: RiskFactor[] = positive.map((factor) => ({
    key: factor.key,
    label: factor.label,
    normalized: Number(factor.normalized.toFixed(2)),
    weight: factor.weight,
    contribution: Number(((factor.points / 10) * factor.weight * 100).toFixed(2)),
    reason: factor.reason,
  }));

  const controlContribution = controls === 0 ? 0 : Number(((controls / 10) * weights.controls * 100).toFixed(2));
  factors.push({
    key: 'controls',
    label: 'Compensating controls',
    normalized: controls,
    weight: weights.controls,
    contribution: controlContribution === 0 ? 0 : -controlContribution,
    reason:
      controls > 0
        ? 'Enabled compensating controls reduced the score'
        : 'No compensating controls recorded',
  });

  const raw = factors.reduce((sum, factor) => sum + factor.contribution, 0);
  const score = Math.round(clamp(raw, 0, 100));
  const rating = ratingFor(score);
  const drivers = factors
    .filter((factor) => factor.contribution >= 8)
    .map((factor) => factor.reason);

  return {
    formulaVersion: RISK_FORMULA_VERSION,
    score,
    rating,
    factors,
    summary: drivers.length > 0 ? drivers.join(' · ') : 'Score is driven by the weighted factor set',
  };
}
