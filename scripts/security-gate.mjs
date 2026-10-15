import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

const failOn = (process.env.FAIL_ON ?? 'HIGH').toUpperCase();
const rank = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const threshold = rank[failOn] ?? 3;
const root = process.argv[2] ?? 'security-artifacts';

function walk(dir) {
  if (!statSafe(dir)) return [];
  return readdirSync(dir).flatMap((entry) => {
    const full = path.join(dir, entry);
    return statSync(full).isDirectory() ? walk(full) : full.endsWith('.json') ? [full] : [];
  });
}

function statSafe(dir) {
  try {
    return statSync(dir).isDirectory();
  } catch {
    return false;
  }
}

const failures = [];
for (const file of walk(root)) {
  const payload = JSON.parse(readFileSync(file, 'utf8'));
  const findings = [];
  if (Array.isArray(payload.results)) {
    for (const result of payload.results) findings.push(String(result.extra?.severity ?? 'INFO').toUpperCase());
  }
  if (Array.isArray(payload.Results)) {
    for (const result of payload.Results) {
      for (const vuln of result.Vulnerabilities ?? []) findings.push(String(vuln.Severity ?? 'INFO').toUpperCase());
    }
  }
  if (Array.isArray(payload)) {
    for (const item of payload) if (item?.RuleID) findings.push('HIGH');
  }
  findings.forEach((severity, index) => {
    const normalized = severity === 'ERROR' ? 'HIGH' : severity === 'WARNING' ? 'MEDIUM' : severity;
    if ((rank[normalized] ?? 0) >= threshold) failures.push(`${file}#${index} ${normalized}`);
  });
}

if (failures.length > 0) {
  console.error(`Security gate failed for FAIL_ON=${failOn}`);
  failures.slice(0, 50).forEach((line) => console.error(line));
  process.exit(1);
}
console.log(`Security gate passed for FAIL_ON=${failOn}`);
