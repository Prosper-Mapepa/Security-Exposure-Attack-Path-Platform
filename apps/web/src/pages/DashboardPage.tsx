import { useQuery } from '@tanstack/react-query';
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Empty, PageHeader, PageLoading, Panel } from '../components/ui';
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

function CountBars({ rows }: { rows: Array<{ source: string; count: number }> }) {
  const max = Math.max(...rows.map((row) => row.count), 1);
  return (
    <ul className="space-y-3 text-sm">
      {rows.map((row) => (
        <li key={row.source}>
          <div className="mb-1 flex justify-between gap-3">
            <span className="truncate">{row.source}</span>
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
    ['Mean time to remediate (hours)', data.meanTimeToRemediateHours ?? 'n/a'],
  ];
  return (
    <div className="space-y-6">
      <PageHeader title="Security posture" description="Open risk, exposure, and the work still in front of the team." />
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {cards.map(([label, value]) => (
          <div key={String(label)} className="rounded-lg border border-line bg-panel px-4 py-3">
            <p className="text-xs text-mute">{label}</p>
            <p className="mt-1 font-mono text-2xl font-medium">{value}</p>
          </div>
        ))}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Findings by severity">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.findingsBySeverity ?? []}>
                <XAxis dataKey="severity" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#0f766e" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Findings by source">
          {(data.findingsBySource ?? []).length === 0 ? <Empty title="No source data" body="Completed scans will appear here." /> : (
            <CountBars rows={data.findingsBySource ?? []} />
          )}
        </Panel>
      </div>
      <Panel title="Findings by asset">
        {(data.findingsByAsset ?? []).length === 0 ? <Empty title="No asset findings" body="Findings are grouped by the affected asset." /> : (
          <CountBars rows={(data.findingsByAsset ?? []).map((row) => ({ source: row.name, count: row.count }))} />
        )}
      </Panel>
    </div>
  );
}
