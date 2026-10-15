import { buildFinding, cweFromMetadata } from './normalize';
import { normalizeSeverity } from './severity-map';
import type { NormalizedFinding, RawScanOutput, ScanRequest, ScannerAdapter, ScannerStatus } from './types';

interface ZapAlert {
  name?: string;
  riskdesc?: string;
  riskcode?: string;
  confidence?: string;
  desc?: string;
  url?: string;
  param?: string;
  evidence?: string;
  solution?: string;
  cweid?: string;
  reference?: string;
  alert?: string;
}

interface ZapSite {
  alerts?: ZapAlert[];
}

function alertsOf(payload: unknown): ZapAlert[] {
  if (!payload || typeof payload !== 'object') return [];
  const site = (payload as { site?: unknown }).site;
  if (Array.isArray(site)) {
    return site.flatMap((item) => ((item as ZapSite).alerts ?? []));
  }
  const alerts = (payload as { alerts?: unknown }).alerts;
  return Array.isArray(alerts) ? (alerts as ZapAlert[]) : [];
}

function confidenceOf(value?: string): number {
  const text = (value ?? '').toLowerCase();
  if (text.includes('high') || text.startsWith('3')) return 0.9;
  if (text.includes('medium') || text.startsWith('2')) return 0.6;
  if (text.includes('low') || text.startsWith('1')) return 0.4;
  return 0.5;
}

export class ZapAdapter implements ScannerAdapter {
  readonly name = 'ZAP' as const;

  constructor(
    private readonly baseUrl = process.env.ZAP_BASE_URL ?? '',
    private readonly apiKey = process.env.ZAP_API_KEY ?? '',
    private readonly timeoutMs = Number(process.env.SCAN_COMMAND_TIMEOUT_MS ?? 600_000),
  ) {}

  async getStatus(): Promise<ScannerStatus> {
    if (!this.baseUrl) {
      return { scanner: this.name, available: false, detail: 'ZAP_BASE_URL is not configured' };
    }
    try {
      const response = await fetch(`${this.baseUrl.replace(/\/$/, '')}/JSON/core/view/version/?apikey=${encodeURIComponent(this.apiKey)}`);
      if (!response.ok) {
        return { scanner: this.name, available: false, detail: `ZAP returned ${response.status}` };
      }
      return { scanner: this.name, available: true, detail: 'ZAP API is reachable' };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'ZAP API unreachable';
      return { scanner: this.name, available: false, detail: message };
    }
  }

  async scan(request: ScanRequest): Promise<RawScanOutput> {
    if (request.targetType !== 'URL') {
      throw new Error('OWASP ZAP scans require a URL target');
    }
    if (!this.baseUrl) {
      throw new Error('ZAP_BASE_URL is not configured. Start the zap compose profile or set the API address.');
    }
    const root = this.baseUrl.replace(/\/$/, '');
    const key = encodeURIComponent(this.apiKey);
    const target = encodeURIComponent(request.location);
    const logs: string[] = [];
    await this.call(`${root}/JSON/core/action/accessUrl/?apikey=${key}&url=${target}&followRedirects=true`);
    logs.push('Spider started');
    const spider = await this.call(`${root}/JSON/spider/action/scan/?apikey=${key}&url=${target}&recurse=true`);
    const spiderId = String((spider as { scan?: string }).scan ?? '');
    await this.wait(`${root}/JSON/spider/view/status/?apikey=${key}&scanId=${spiderId}`, request.signal);
    logs.push('Active scan started');
    const active = await this.call(`${root}/JSON/ascan/action/scan/?apikey=${key}&url=${target}&recurse=true`);
    const scanId = String((active as { scan?: string }).scan ?? '');
    await this.wait(`${root}/JSON/ascan/view/status/?apikey=${key}&scanId=${scanId}`, request.signal);
    const alerts = await this.call(`${root}/JSON/core/view/alerts/?apikey=${key}&baseurl=${target}&start=0&count=500`);
    return { scanner: this.name, format: 'zap-json', payload: alerts, logs };
  }

  parseResults(raw: RawScanOutput): NormalizedFinding[] {
    return alertsOf(raw.payload).map((alert) => this.normalizeFinding(alert));
  }

  normalizeFinding(rawFinding: unknown): NormalizedFinding {
    const alert = (rawFinding ?? {}) as ZapAlert;
    const risk = (alert.riskdesc ?? '').split(' ')[0] || alert.riskcode;
    const cwe = alert.cweid && alert.cweid !== '-1' ? `CWE-${alert.cweid}` : cweFromMetadata(alert.reference);
    return buildFinding({
      source: 'ZAP',
      assetKey: 'target',
      ruleId: alert.alert || alert.name,
      title: alert.name || alert.alert || 'ZAP alert',
      description: stripHtml(alert.desc || 'OWASP ZAP reported an alert'),
      severity: normalizeSeverity(risk),
      confidence: confidenceOf(alert.confidence),
      cwe,
      affectedComponent: alert.param || alert.url,
      location: alert.url,
      evidence: [alert.url, alert.param ? `param=${alert.param}` : '', alert.evidence ? `evidence=${alert.evidence}` : '']
        .filter(Boolean)
        .join(' '),
      remediation: stripHtml(alert.solution || 'Apply the ZAP remediation guidance for this alert.'),
      references: (alert.reference ?? '')
        .split(/\s+/)
        .map((item) => item.trim())
        .filter((item) => item.startsWith('http')),
    });
  }

  private async call(url: string): Promise<unknown> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(url, { signal: controller.signal });
      if (!response.ok) {
        throw new Error(`ZAP API request failed with ${response.status}`);
      }
      return (await response.json()) as unknown;
    } finally {
      clearTimeout(timer);
    }
  }

  private async wait(statusUrl: string, signal?: AbortSignal): Promise<void> {
    const started = Date.now();
    while (Date.now() - started < this.timeoutMs) {
      if (signal?.aborted) throw new Error('Scan cancelled');
      const body = (await this.call(statusUrl)) as { status?: string };
      if (Number(body.status) >= 100) return;
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
    throw new Error('ZAP scan timed out');
  }
}

function stripHtml(value: string): string {
  return value.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}
