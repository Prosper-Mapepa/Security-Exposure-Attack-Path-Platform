import { existsSync } from 'node:fs';
import path from 'node:path';

export function repositoryRoot(start = process.cwd()): string {
  let dir = path.resolve(start);
  for (let i = 0; i < 8; i += 1) {
    if (
      existsSync(path.join(dir, 'package.json')) &&
      existsSync(path.join(dir, 'apps')) &&
      existsSync(path.join(dir, 'packages'))
    ) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return path.resolve(start);
}

export function resolveScanAllowlist(raw: string | undefined, start = process.cwd()): string[] {
  const root = repositoryRoot(start);
  return (raw ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .map((entry) => (path.isAbsolute(entry) ? entry : path.resolve(root, entry)));
}

export function isPathInsideAllowlist(candidate: string, allowlist: string[]): boolean {
  const resolved = path.resolve(candidate);
  return allowlist.some((entry) => {
    const root = path.resolve(entry);
    return resolved === root || resolved.startsWith(root + path.sep);
  });
}

export function slugify(value: string): string {
  const slug = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
  return slug || 'org';
}
