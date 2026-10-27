import { GitleaksAdapter } from './gitleaks';
import { SemgrepAdapter } from './semgrep';
import { TrivyAdapter } from './trivy';
import { ZapAdapter } from './zap';

describe('scanner parsers', () => {
  it('normalizes Semgrep JSON and masks matched secrets', () => {
    const findings = new SemgrepAdapter().parseResults({
      scanner: 'SEMGREP',
      format: 'semgrep-json',
      logs: [],
      payload: {
        results: [
          {
            check_id: 'seap-sql-string-concat',
            path: 'src/users.js',
            start: { line: 12 },
            extra: {
              message: 'SQL query is built by concatenating untrusted input.',
              severity: 'ERROR',
              lines: 'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
              metadata: { cwe: ['CWE-89: SQL Injection'], likelihood: 'HIGH' },
            },
          },
        ],
      },
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('HIGH');
    expect(findings[0]?.cwe).toBe('CWE-89');
    expect(findings[0]?.location).toBe('src/users.js:12');
    expect(findings[0]?.dedupKey).toContain('seap-sql-string-concat');
  });

  it('normalizes Trivy package vulnerabilities', () => {
    const findings = new TrivyAdapter().parseResults({
      scanner: 'TRIVY',
      format: 'trivy-json',
      logs: [],
      payload: {
        Results: [
          {
            Target: 'package-lock.json',
            Vulnerabilities: [
              {
                VulnerabilityID: 'CVE-2021-23337',
                PkgName: 'lodash',
                InstalledVersion: '4.17.20',
                FixedVersion: '4.17.21',
                Severity: 'HIGH',
                Title: 'Command Injection in lodash',
                Description: 'lodash versions prior to 4.17.21 are vulnerable.',
                CweIDs: ['CWE-94'],
                CVSS: { nvd: { V3Score: 7.2 } },
                PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2021-23337',
              },
            ],
          },
        ],
      },
    });
    expect(findings[0]?.cve).toBe('CVE-2021-23337');
    expect(findings[0]?.cvss).toBe(7.2);
    expect(findings[0]?.affectedComponent).toBe('lodash@4.17.20');
    expect(findings[0]?.remediation).toContain('4.17.21');
    expect(findings[0]?.dedupKey).toBe('cve:CVE-2021-23337:asset:target');
  });

  it('never keeps a gitleaks secret in evidence', () => {
    const findings = new GitleaksAdapter().parseResults({
      scanner: 'GITLEAKS',
      format: 'gitleaks-json',
      logs: [],
      payload: [
        {
          RuleID: 'aws-access-token',
          Description: 'AWS access key',
          File: 'config',
          StartLine: 4,
          Commit: 'abc123',
          Fingerprint: 'config.js:aws-access-token:4',
          Secret: 'AKIAIOSFODNN7EXAMPLE',
        },
      ],
    });
    expect(findings[0]?.evidence).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(findings[0]?.evidence).toContain('[REDACTED]');
    expect(findings[0]?.cwe).toBe('CWE-798');
    expect(findings[0]?.cvss).toBe(7.5);
  });

  it('normalizes ZAP alerts', () => {
    const findings = new ZapAdapter().parseResults({
      scanner: 'ZAP',
      format: 'zap-json',
      logs: [],
      payload: {
        alerts: [
          {
            name: 'SQL Injection',
            riskdesc: 'High (Medium)',
            confidence: 'Medium',
            desc: '<p>SQL injection may be possible.</p>',
            url: 'http://127.0.0.1:8090/users',
            param: 'id',
            evidence: 'syntax error',
            solution: '<p>Use parameterized queries.</p>',
            cweid: '89',
            reference: 'https://owasp.org/www-community/attacks/SQL_Injection',
          },
        ],
      },
    });
    expect(findings[0]?.severity).toBe('HIGH');
    expect(findings[0]?.cwe).toBe('CWE-89');
    expect(findings[0]?.description).not.toContain('<p>');
    expect(findings[0]?.location).toContain('/users');
  });
});
