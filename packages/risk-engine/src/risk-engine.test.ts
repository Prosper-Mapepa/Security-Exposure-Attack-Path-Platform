import { calculateRisk } from './index';

describe('risk engine', () => {
  const now = new Date('2026-09-28T00:00:00.000Z');

  it('scores an internet-facing production issue above an internal low issue', () => {
    const high = calculateRisk({
      cvss: 9.8,
      severity: 'CRITICAL',
      knownExploited: true,
      publicExploit: true,
      exploitIntelAvailable: true,
      criticality: 'CRITICAL',
      exposure: 'PUBLIC',
      internetFacing: true,
      authRequired: false,
      privilegeRequired: 'NONE',
      dataSensitivity: 'RESTRICTED',
      firstSeen: new Date('2026-01-01T00:00:00.000Z'),
      now,
      onSensitiveAttackPath: true,
    });
    const low = calculateRisk({
      cvss: 3.1,
      severity: 'LOW',
      exploitIntelAvailable: true,
      criticality: 'LOW',
      exposure: 'PRIVATE',
      authRequired: true,
      privilegeRequired: 'HIGH',
      dataSensitivity: 'PUBLIC',
      firstSeen: now,
      now,
    });
    expect(high.score).toBeGreaterThan(low.score);
    expect(high.rating === 'CRITICAL' || high.rating === 'HIGH').toBe(true);
    expect(high.factors.find((factor) => factor.key === 'exposure')?.reason).toContain('Internet-facing');
    expect(high.formulaVersion).toBe('1.0.0');
  });

  it('does not hide a zero control reduction', () => {
    const result = calculateRisk({
      severity: 'MEDIUM',
      criticality: 'MEDIUM',
      exposure: 'INTERNAL',
      dataSensitivity: 'INTERNAL',
      firstSeen: now,
      now,
      compensatingControlScore: 0,
    });
    expect(result.factors.find((factor) => factor.key === 'controls')?.contribution).toBe(0);
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
  });
});
