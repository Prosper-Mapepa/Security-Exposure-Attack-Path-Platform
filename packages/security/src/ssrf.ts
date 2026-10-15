import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

const BLOCKED_HOSTS = new Set(['localhost', 'metadata.google.internal', 'instance-data']);

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
}

function parseCidr(cidr: string): { base: number; mask: number } | null {
  const [addr, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  const base = ipv4ToInt(addr ?? '');
  if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { base: base & mask, mask };
}

export function isBlockedIp(ip: string): boolean {
  if (isIP(ip) === 6) {
    const normalized = ip.toLowerCase();
    if (normalized === '::1' || normalized.startsWith('fe80:') || normalized.startsWith('fc') || normalized.startsWith('fd')) {
      return true;
    }
    if (normalized.startsWith('::ffff:')) {
      return isBlockedIp(normalized.slice(7));
    }
    return false;
  }
  const value = ipv4ToInt(ip);
  if (value === null) return true;
  const ranges = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '255.255.255.255/32'];
  return ranges.some((cidr) => {
    const parsed = parseCidr(cidr);
    if (!parsed) return false;
    return (value & parsed.mask) === parsed.base;
  });
}

export function ipInCidrs(ip: string, cidrs: string[]): boolean {
  const value = ipv4ToInt(ip);
  if (value === null) return false;
  return cidrs.some((cidr) => {
    const parsed = parseCidr(cidr.trim());
    if (!parsed) return false;
    return (value & parsed.mask) === parsed.base;
  });
}

export interface UrlSafetyOptions {
  allowPrivate: boolean;
  labCidrs: string[];
}

export async function assertSafeScanUrl(raw: string, options: UrlSafetyOptions): Promise<URL> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('Scan target URL is invalid');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Scan target URL must use http or https');
  }
  if (url.username || url.password) {
    throw new Error('Scan target URL must not include credentials');
  }
  const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (BLOCKED_HOSTS.has(host) || host.endsWith('.local') || host === '0.0.0.0') {
    if (!options.allowPrivate) {
      throw new Error('Scan target host is not allowed');
    }
  }
  const addresses = isIP(host) ? [host] : (await lookup(host, { all: true })).map((entry) => entry.address);
  if (addresses.length === 0) {
    throw new Error('Scan target host did not resolve');
  }
  for (const address of addresses) {
    if (!isBlockedIp(address)) continue;
    const labAllowed = options.allowPrivate && ipInCidrs(address, options.labCidrs);
    const loopback = address.startsWith('127.') && options.allowPrivate;
    if (!labAllowed && !loopback) {
      throw new Error('Scan target resolves to a blocked address');
    }
  }
  return url;
}
