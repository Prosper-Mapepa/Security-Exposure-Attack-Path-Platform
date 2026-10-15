import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Button, Empty, Field, PageHeader, PageLoading, Panel, Severity, Table, inputClass } from '../components/ui';
import { api } from '../lib/api';

interface Asset {
  id: string;
  name: string;
  type: string;
  environment: string;
  criticality: string;
  exposure: string;
  internetFacing: boolean;
  businessService?: string | null;
  technology?: string | null;
}

export function AssetsPage() {
  const client = useQueryClient();
  const [q, setQ] = useState('');
  const [form, setForm] = useState({ name: '', type: 'APPLICATION', environment: 'PRODUCTION', criticality: 'HIGH', exposure: 'INTERNAL', technology: '', businessService: '' });
  const query = useQuery({
    queryKey: ['assets', q],
    queryFn: () => api.get<{ data: Asset[]; total: number }>(`/api/assets?page=1&pageSize=50${q ? `&q=${encodeURIComponent(q)}` : ''}`),
  });
  const create = useMutation({
    mutationFn: () => api.post('/api/assets', { ...form, internetFacing: form.exposure === 'PUBLIC', detail: {} }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['assets'] }),
  });
  return (
    <div className="space-y-6">
      <PageHeader
        title="Asset inventory"
        description="Applications, repositories, cloud resources, and anything else a scan can target."
        actions={<input aria-label="Search assets" className={`${inputClass} w-64`} placeholder="Search assets" value={q} onChange={(event) => setQ(event.target.value)} />}
      />
      <Panel title="Add asset">
        <form className="grid gap-3 md:grid-cols-3" onSubmit={(event) => { event.preventDefault(); create.mutate(); }}>
          <Field label="Name"><input className={inputClass} value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} required /></Field>
          <Field label="Type">
            <select className={inputClass} value={form.type} onChange={(event) => setForm({ ...form, type: event.target.value })}>
              {['APPLICATION','API','DOMAIN','IP_ADDRESS','REPOSITORY','CLOUD_ACCOUNT','CLOUD_RESOURCE','CONTAINER','CONTAINER_IMAGE','KUBERNETES_CLUSTER','KUBERNETES_WORKLOAD','DATABASE','SERVER','IDENTITY','SERVICE_ACCOUNT','IAM_ROLE'].map((type) => <option key={type}>{type}</option>)}
            </select>
          </Field>
          <Field label="Environment">
            <select className={inputClass} value={form.environment} onChange={(event) => setForm({ ...form, environment: event.target.value })}>
              {['PRODUCTION','STAGING','DEVELOPMENT','TEST'].map((item) => <option key={item}>{item}</option>)}
            </select>
          </Field>
          <Field label="Criticality">
            <select className={inputClass} value={form.criticality} onChange={(event) => setForm({ ...form, criticality: event.target.value })}>
              {['CRITICAL','HIGH','MEDIUM','LOW'].map((item) => <option key={item}>{item}</option>)}
            </select>
          </Field>
          <Field label="Exposure">
            <select className={inputClass} value={form.exposure} onChange={(event) => setForm({ ...form, exposure: event.target.value })}>
              {['PUBLIC','INTERNAL','PRIVATE'].map((item) => <option key={item}>{item}</option>)}
            </select>
          </Field>
          <Field label="Technology"><input className={inputClass} value={form.technology} onChange={(event) => setForm({ ...form, technology: event.target.value })} /></Field>
          <div className="flex justify-end md:col-span-3"><Button type="submit" loading={create.isPending}>Save asset</Button></div>
        </form>
        {create.isError && <p className="mt-2 text-sm text-rose-500">{(create.error as Error).message}</p>}
      </Panel>
      {query.isLoading ? <PageLoading label="Loading assets" /> : (query.data?.data.length ?? 0) === 0 ? <Empty title="No assets" body="Add an application, repository, cloud resource, or the local security lab." /> : (
        <Panel>
          <Table headers={['Name', 'Type', 'Environment', 'Criticality', 'Exposure']}>
            {query.data?.data.map((asset) => (
              <tr key={asset.id} className="border-t border-line hover:bg-ink/70">
                <td className="px-3 py-2.5"><Link className="font-medium text-accent" to={`/assets/${asset.id}`}>{asset.name}</Link></td>
                <td className="px-3 py-2.5">{asset.type}</td>
                <td className="px-3 py-2.5">{asset.environment}</td>
                <td className="px-3 py-2.5"><Severity value={asset.criticality} /></td>
                <td className="px-3 py-2.5">{asset.internetFacing ? 'Public' : asset.exposure}</td>
              </tr>
            ))}
          </Table>
        </Panel>
      )}
    </div>
  );
}

export function AssetDetailPage() {
  const { id = '' } = useParams();
  const query = useQuery({
    queryKey: ['asset', id],
    queryFn: () => api.get<{
      asset: Asset & { description?: string | null; dataSensitivity: string };
      severity: Record<string, number>;
      findings: Array<{ id: string; title: string; severity: string; status: string; riskScore: number }>;
      scans: Array<{ id: string; name: string; scanner: string; status: string }>;
      attackPaths: Array<{ id: string; title: string; score: number }>;
    }>(`/api/assets/${id}/posture`),
  });
  if (query.isLoading) return <PageLoading label="Loading asset" />;
  if (query.isError || !query.data) return <p className="text-rose-500">Asset was not found.</p>;
  const { asset, severity, findings, scans, attackPaths } = query.data;
  return (
    <div className="space-y-6">
      <PageHeader title={asset.name} description={`${asset.type} · ${asset.environment}`} />
      <Panel title="Details">
        <dl className="grid gap-2 text-sm md:grid-cols-3">
          <div>Environment<div className="font-medium">{asset.environment}</div></div>
          <div>Criticality<div className="mt-1"><Severity value={asset.criticality} /></div></div>
          <div>Internet exposure<div className="font-medium">{asset.internetFacing ? 'Public' : asset.exposure}</div></div>
        </dl>
      </Panel>
      <Panel title="Security posture">
        <div className="flex flex-wrap gap-3">{Object.entries(severity).map(([level, count]) => <div key={level}><Severity value={level} /> <span className="font-mono">{count}</span></div>)}</div>
      </Panel>
      <Panel title="Related findings">
        {findings.length === 0 ? <Empty title="No findings" body="Run a scan against this asset." /> : findings.map((finding) => (
          <div key={finding.id} className="flex items-center justify-between border-t border-line py-2 text-sm">
            <Link className="text-accent" to={`/findings/${finding.id}`}>{finding.title}</Link>
            <span className="flex items-center gap-2"><Severity value={finding.severity} />{finding.riskScore}</span>
          </div>
        ))}
      </Panel>
      <Panel title="Attack paths">
        {attackPaths.length === 0 ? <Empty title="No attack paths" body="Model relationships and rebuild the graph." /> : attackPaths.map((path) => <p key={path.id} className="border-t border-line py-2 text-sm">{path.title}</p>)}
      </Panel>
      <Panel title="Recent scans">
        {scans.length === 0 ? <Empty title="No scans" body="Start a Semgrep, Trivy, Gitleaks, or ZAP scan." /> : scans.map((scan) => <p key={scan.id} className="text-sm">{scan.scanner} · {scan.name} · {scan.status}</p>)}
      </Panel>
    </div>
  );
}
