import { maskSecrets, maskUnknown } from './mask';

describe('secret masking', () => {
  it('masks AWS access key ids and tokens', () => {
    const input = 'key AKIAIOSFODNN7EXAMPLE and bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const masked = maskSecrets(input);
    expect(masked).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(masked).toContain('[REDACTED]');
  });

  it('redacts sensitive object keys', () => {
    const masked = maskUnknown({ password: 'Hunter-Secret-1', note: 'ok' }) as {
      password: string;
      note: string;
    };
    expect(masked.password).toBe('[REDACTED]');
    expect(masked.note).toBe('ok');
  });
});
