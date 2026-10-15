import { discoverAttackPaths } from './index';

describe('attack path engine', () => {
  it('finds a path from the internet through a vulnerability to a database', () => {
    const paths = discoverAttackPaths(
      [
        { id: 'net', kind: 'INTERNET', label: 'Internet', exposure: 'PUBLIC' },
        { id: 'api', kind: 'API', label: 'Customer API', exposure: 'PUBLIC', criticality: 'CRITICAL' },
        {
          id: 'vuln',
          kind: 'VULNERABILITY',
          label: 'BOLA',
          severity: 'HIGH',
          riskScore: 70,
          explanation: 'Broken object level authorization on the public API',
        },
        { id: 'role', kind: 'IAM_ROLE', label: 'App role', privileged: true },
        {
          id: 'db',
          kind: 'DATABASE',
          label: 'Customer database',
          criticality: 'CRITICAL',
          dataSensitivity: 'RESTRICTED',
        },
      ],
      [
        { id: 'e1', source: 'net', target: 'api', type: 'CONNECTS_TO' },
        { id: 'e2', source: 'api', target: 'vuln', type: 'EXPOSES' },
        { id: 'e3', source: 'vuln', target: 'role', type: 'CAN_ACCESS' },
        { id: 'e4', source: 'role', target: 'db', type: 'CAN_ACCESS' },
      ],
    );
    const fullPath = paths.find((path) => path.nodeIds[0] === 'net');
    expect(fullPath?.nodeIds).toEqual(['net', 'api', 'vuln', 'role', 'db']);
    expect(fullPath?.score).toBeGreaterThan(40);
    expect(fullPath?.explanations[2]).toContain('Broken object level authorization');
  });

  it('does not emit a path that never touches a vulnerability', () => {
    const paths = discoverAttackPaths(
      [
        { id: 'net', kind: 'INTERNET', label: 'Internet' },
        { id: 'api', kind: 'API', label: 'API', exposure: 'PUBLIC' },
        { id: 'db', kind: 'DATABASE', label: 'DB', dataSensitivity: 'RESTRICTED' },
      ],
      [
        { id: 'e1', source: 'net', target: 'api', type: 'CONNECTS_TO' },
        { id: 'e2', source: 'api', target: 'db', type: 'CAN_ACCESS' },
      ],
    );
    expect(paths).toHaveLength(0);
  });
});
