const counters = new Map<string, number>();

export function incrementMetric(name: string, labels: Record<string, string> = {}): void {
  const key = `${name}{${Object.entries(labels)
    .map(([label, value]) => `${label}="${value.replace(/"/g, '')}"`)
    .join(',')}}`;
  counters.set(key, (counters.get(key) ?? 0) + 1);
}

export function renderMetrics(): string {
  const lines = [
    '# HELP seap_http_requests_total HTTP requests',
    '# TYPE seap_http_requests_total counter',
  ];
  for (const [key, value] of counters) {
    lines.push(`seap_${key} ${value}`);
  }
  return `${lines.join('\n')}\n`;
}
