import path from 'node:path';

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
