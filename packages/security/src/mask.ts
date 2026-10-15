const SECRET_PATTERNS: RegExp[] = [
  /AKIA[0-9A-Z]{16}/g,
  /ASIA[0-9A-Z]{16}/g,
  /-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/g,
  /ghp_[A-Za-z0-9]{20,}/g,
  /github_pat_[A-Za-z0-9_]{20,}/g,
  /xox[baprs]-[A-Za-z0-9-]{10,}/g,
  /sk_live_[A-Za-z0-9]{16,}/g,
  /(?<=password\s*[:=]\s*['"]?)[^\s'"]{6,}/gi,
  /(?<=secret\s*[:=]\s*['"]?)[^\s'"]{6,}/gi,
  /(?<=api[_-]?key\s*[:=]\s*['"]?)[^\s'"]{6,}/gi,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
];

export function maskSecrets(value: string): string {
  let masked = value;
  for (const pattern of SECRET_PATTERNS) {
    masked = masked.replace(pattern, '[REDACTED]');
  }
  return masked;
}

export function maskUnknown(value: unknown): unknown {
  if (typeof value === 'string') return maskSecrets(value);
  if (Array.isArray(value)) return value.map((item) => maskUnknown(item));
  if (value && typeof value === 'object') {
    const output: Record<string, unknown> = {};
    for (const [key, inner] of Object.entries(value)) {
      if (/password|secret|token|authorization|api[_-]?key|cookie/i.test(key)) {
        output[key] = '[REDACTED]';
      } else {
        output[key] = maskUnknown(inner);
      }
    }
    return output;
  }
  return value;
}
