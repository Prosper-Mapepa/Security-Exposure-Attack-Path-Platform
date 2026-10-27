import { useQuery } from '@tanstack/react-query';
import { Bar, BarChart, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts';
import { Empty, Hint, PageHeader, PageLoading, Panel, Tooltip } from '../components/ui';
import { api } from '../lib/api';

interface Summary {
  empty: boolean;
  message?: string;
  securityRiskScore?: number | null;
  openCritical?: number;
  openHigh?: number;
  internetFacingAssets?: number;
  assetsWithVulnerabilities?: number;
  attackPaths?: number;
  activeIncidents?: number;
  overdueRemediation?: number;
  meanTimeToRemediateHours?: number | null;
  findingsBySeverity?: Array<{ severity: string; count: number }>;
  findingsBySource?: Array<{ source: string; count: number }>;
  findingsByAsset?: Array<{ name: string; count: number }>;
  riskTrend?: Array<{ date: string; averageRisk: number }>;
}

const METRIC_TIPS: Record<string, string> = {
  'Risk score': 'Average risk of open findings, 0–100. Higher means more urgent exposure.',
  'Open critical': 'Open findings scored Critical that still need triage or a fix.',
  'Open high': 'Open findings scored High that still need triage or a fix.',
  'Internet-facing assets': 'Assets marked public or internet-facing in inventory.',
  'Assets with vulnerabilities': 'Distinct assets that currently have at least one open finding.',
  'Attack paths': 'Stored routes from exposure through a vulnerability to a sensitive sink.',
  'Active incidents': 'Incidents that are not yet resolved or closed.',
  'Overdue remediation': 'Remediation work past its due date that is not validated or closed.',
  'Mean time to remediate (hours)': 'Average hours from first seen to mitigated or resolved. Shows n/a until findings are closed.',
};

function CountBars({ rows }: { rows: Array<{ source: string; count: number }> }) {
  const max = Math.max(...rows.map((row) => row.count), 1);
  return (
    <ul className="space-y-3 text-sm">
      {rows.map((row) => (
        <li key={row.source}>
          <div className="mb-1 flex justify-between gap-3">
            <Tooltip content={row.source}>
              <span className="truncate">{row.source}</span>
            </Tooltip>
            <span className="font-mono">{row.count}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-ink">
            <div className="h-full rounded-full bg-accent" style={{ width: `${(row.count / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

export function DashboardPage() {
  const query = useQuery({ queryKey: ['dashboard'], queryFn: () => api.get<Summary>('/api/dashboard') });
  if (query.isLoading) return <PageLoading label="Loading security posture" />;
  if (query.isError) return <p className="text-rose-500">Dashboard could not be loaded.</p>;
  const data = query.data;
  if (!data || data.empty) {
    return (
      <div className="space-y-6">
        <PageHeader title="Security posture" description="Open risk, exposure, and the work still in front of the team." />
        <Empty title="No security data available" body="Add assets and run a scanner. Metrics are calculated from stored findings." />
      </div>
    );
  }
  const cards = [
    ['Risk score', data.securityRiskScore ?? 'n/a'],
    ['Open critical', data.openCritical ?? 0],
    ['Open high', data.openHigh ?? 0],
    ['Internet-facing assets', data.internetFacingAssets ?? 0],
    ['Assets with vulnerabilities', data.assetsWithVulnerabilities ?? 0],
    ['Attack paths', data.attackPaths ?? 0],
    ['Active incidents', data.activeIncidents ?? 0],
    ['Overdue remediation', data.overdueRemediation ?? 0],
    ['Mean time to remediate (hours)', data.meanTimeToRemediateHours == null ? 'n/a' : data.meanTimeToRemediateHours],
  ] as const;
  return (
    <div className="space-y-6">
      <PageHeader title="Security posture" description="Open risk, exposure, and the work still in front of the team." />
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {cards.map(([label, value]) => (
          <Tooltip key={label} content={METRIC_TIPS[label]} placement="top" className="w-full">
            <div className="w-full rounded-lg border border-line bg-panel px-4 py-3">
              <p className="text-xs text-mute">{label}</p>
              <p className="mt-1 font-mono text-2xl font-medium">{value}</p>
            </div>
          </Tooltip>
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Findings by severity" tip="Open findings grouped by severity. Hover a bar for the exact count.">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.findingsBySeverity ?? []}>
                <XAxis dataKey="severity" />
                <YAxis allowDecimals={false} />
                <ChartTooltip />
                <Bar dataKey="count" fill="#0f766e" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Findings by source" tip="Which scanners reported the open findings currently in scope.">
          {(data.findingsBySource ?? []).length === 0 ? <Empty title="No source data" body="Completed scans will appear here." /> : (
            <CountBars rows={data.findingsBySource ?? []} />
          )}
        </Panel>
      </div>
      <Panel
        title="Findings by asset"
        tip="Assets with the most open findings. Use this to decide where to start remediation."
        action={<Hint label={<span className="text-xs text-mute">Why this matters</span>} tip="Concentrated findings on one asset often share a fix or an attack path." />}
      >
        {(data.findingsByAsset ?? []).length === 0 ? <Empty title="No asset findings" body="Findings are grouped by the affected asset." /> : (
          <CountBars rows={(data.findingsByAsset ?? []).map((row) => ({ source: row.name, count: row.count }))} />
        )}
      </Panel>
    </div>
  );
}
