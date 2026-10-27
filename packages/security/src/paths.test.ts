import path from 'node:path';
import { isPathInsideAllowlist, repositoryRoot, resolveScanAllowlist } from './paths';

describe('scan path allowlist', () => {
  it('keeps a path inside an allowed directory', () => {
    expect(isPathInsideAllowlist('/repo/lab/src', ['/repo/lab'])).toBe(true);
    expect(isPathInsideAllowlist('/repo/apps/api', ['/repo/lab'])).toBe(false);
  });

  it('resolves relative allowlist entries from the repository root', () => {
    const root = repositoryRoot();
    const resolved = resolveScanAllowlist('./lab,./tests/fixtures/vulnerable-repo', path.join(root, 'apps/api'));
    expect(resolved[0]).toBe(path.join(root, 'lab'));
    expect(resolved[1]).toBe(path.join(root, 'tests/fixtures/vulnerable-repo'));
  });
});
