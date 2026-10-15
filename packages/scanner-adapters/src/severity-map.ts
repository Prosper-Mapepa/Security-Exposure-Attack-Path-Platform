import type { Severity } from './types';

export function normalizeSeverity(value: string | undefined): Severity {
  const text = (value ?? '').toUpperCase();
  if (text === 'CRITICAL' || text === 'CRIT') return 'CRITICAL';
  if (text === 'HIGH' || text === 'ERROR') return 'HIGH';
  if (text === 'MEDIUM' || text === 'MODERATE' || text === 'WARNING' || text === 'WARN') return 'MEDIUM';
  if (text === 'LOW' || text === 'NOTE') return 'LOW';
  return 'INFO';
}
