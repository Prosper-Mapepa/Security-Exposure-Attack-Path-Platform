export * from './permissions';
export * from './schemas';
export * from './policies';

export const RISK_FORMULA_VERSION = '1.0.0';

export const DEFAULT_RISK_WEIGHTS = {
  technical: 0.22,
  exploitability: 0.14,
  business: 0.16,
  exposure: 0.14,
  authentication: 0.08,
  privilege: 0.06,
  data: 0.08,
  age: 0.04,
  attackPath: 0.08,
  controls: 0.15,
} as const;

export interface Page<T> {
  data: T[];
  page: number;
  pageSize: number;
  total: number;
}

export interface AuthPrincipal {
  id: string;
  email: string;
  name: string;
  organizationId: string | null;
  role: import('./permissions').RoleName;
  isPlatformAdmin: boolean;
}
