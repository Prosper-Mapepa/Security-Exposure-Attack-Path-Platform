import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Button, Empty, Field, PageHeader, PageLoading, Panel, Severity, Spinner, Table, Tooltip, inputClass } from '../components/ui';
import { api } from '../lib/api';

const ASSET_TYPES = ['APPLICATION','API','DOMAIN','IP_ADDRESS','REPOSITORY','CLOUD_ACCOUNT','CLOUD_RESOURCE','CONTAINER','CONTAINER_IMAGE','KUBERNETES_CLUSTER','KUBERNETES_WORKLOAD','DATABASE','SERVER','IDENTITY','SERVICE_ACCOUNT','IAM_ROLE'];
const ENVIRONMENTS = ['PRODUCTION', 'STAGING', 'DEVELOPMENT', 'TEST'];
const CRITICALITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const EXPOSURES = ['PUBLIC', 'INTERNAL', 'PRIVATE'];

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

interface AssetFormValues {
  name: string;
  type: string;
  environment: string;
  criticality: string;
  exposure: string;
  technology: string;
}

function emptyAssetForm(): AssetFormValues {
  return { name: '', type: 'APPLICATION', environment: 'PRODUCTION', criticality: 'HIGH', exposure: 'INTERNAL', technology: '' };
}

function assetToForm(asset: Asset): AssetFormValues {
  return {
    name: asset.name,
    type: asset.type,
    environment: ENVIRONMENTS.includes(asset.environment) ? asset.environment : 'PRODUCTION',
    criticality: asset.criticality,
    exposure: EXPOSURES.includes(asset.exposure) ? asset.exposure : asset.internetFacing ? 'PUBLIC' : 'INTERNAL',
    technology: asset.technology ?? '',
  };
}

function assetPayload(form: AssetFormValues) {
  return {
    name: form.name.trim(),
    type: form.type,
    environment: form.environment,
    criticality: form.criticality,
    exposure: form.exposure,
    technology: form.technology.trim(),
    internetFacing: form.exposure === 'PUBLIC',
  };
}

function AssetForm({
  form,
  setForm,
  editing,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  form: AssetFormValues;
  setForm: (form: AssetFormValues) => void;
  editing: boolean;
  pending: boolean;
  error?: string;
  onSubmit: () => void;
  onCancel: () => void;
}) {
  return (
    <Panel title={editing ? 'Update asset' : 'Add asset'}>
      <form className="grid gap-3 md:grid-cols-3" onSubmit={(event) => { event.preventDefault(); onSubmit(); }}>
        <Field label="Name"><input className={inputClass} value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} required /></Field>
        <Field label="Type">
          <select className={inputClass} value={form.type} onChange={(event) => setForm({ ...form, type: event.target.value })}>
            {ASSET_TYPES.map((type) => <option key={type}>{type}</option>)}
          </select>
        </Field>
        <Field label="Environment">
          <select className={inputClass} value={form.environment} onChange={(event) => setForm({ ...form, environment: event.target.value })}>
            {ENVIRONMENTS.map((item) => <option key={item}>{item}</option>)}
          </select>
        </Field>
        <Field label="Criticality">
          <select className={inputClass} value={form.criticality} onChange={(event) => setForm({ ...form, criticality: event.target.value })}>
            {CRITICALITIES.map((item) => <option key={item}>{item}</option>)}
          </select>
        </Field>
        <Field label="Exposure">
          <select className={inputClass} value={form.exposure} onChange={(event) => setForm({ ...form, exposure: event.target.value })}>
            {EXPOSURES.map((item) => <option key={item}>{item}</option>)}
          </select>
        </Field>
        <Field label="Technology"><input className={inputClass} value={form.technology} onChange={(event) => setForm({ ...form, technology: event.target.value })} /></Field>
        <div className="flex justify-end gap-2 md:col-span-3">
          {editing ? <Button variant="secondary" onClick={onCancel}>Cancel</Button> : null}
          <Button type="submit" loading={pending}>{editing ? 'Save changes' : 'Save asset'}</Button>
        </div>
      </form>
      {error ? <p className="mt-2 text-sm text-rose-500">{error}</p> : null}
    </Panel>
  );
}

export function AssetsPage() {
  const client = useQueryClient();
  const [q, setQ] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<AssetFormValues>(emptyAssetForm);
  const query = useQuery({
    queryKey: ['assets', q],
    queryFn: () => api.get<{ data: Asset[]; total: number }>(`/api/assets?page=1&pageSize=50${q ? `&q=${encodeURIComponent(q)}` : ''}`),
  });
  const save = useMutation({
    mutationFn: () => editingId
      ? api.patch(`/api/assets/${editingId}`, assetPayload(form))
      : api.post('/api/assets', { ...assetPayload(form), detail: {} }),
    onSuccess: () => {
      setEditingId(null);
      setForm(emptyAssetForm());
      void client.invalidateQueries({ queryKey: ['assets'] });
    },
  });
  function beginEdit(asset: Asset) {
    setEditingId(asset.id);
    setForm(assetToForm(asset));
    save.reset();
  }
  function cancelEdit() {
    setEditingId(null);
    setForm(emptyAssetForm());
    save.reset();
  }
  return (
    <div className="space-y-6">
      <PageHeader
        title="Asset inventory"
        description="Applications, repositories, cloud resources, and anything else a scan can target."
        actions={<input aria-label="Search assets" className={`${inputClass} w-64`} placeholder="Search assets" value={q} onChange={(event) => setQ(event.target.value)} />}
      />
      <AssetForm
        form={form}
        setForm={setForm}
        editing={Boolean(editingId)}
        pending={save.isPending}
        error={save.isError ? (save.error as Error).message : undefined}
        onSubmit={() => save.mutate()}
        onCancel={cancelEdit}
      />
      {query.isLoading ? <PageLoading label="Loading assets" /> : (query.data?.data.length ?? 0) === 0 ? <Empty title="No assets" body="Add an application, repository, cloud resource, or the local security lab." /> : (
        <Panel>
          <Table headers={['Name', 'Type', 'Environment', 'Criticality', 'Exposure', 'Actions']}>
            {query.data?.data.map((asset) => (
              <tr key={asset.id} className={`border-t border-line hover:bg-ink/70 ${editingId === asset.id ? 'bg-accent/10' : ''}`}>
                <td className="px-3 py-2.5"><Link className="font-medium text-accent" to={`/assets/${asset.id}`}>{asset.name}</Link></td>
                <td className="px-3 py-2.5">{asset.type}</td>
                <td className="px-3 py-2.5">{asset.environment}</td>
                <td className="px-3 py-2.5"><Severity value={asset.criticality} /></td>
                <td className="px-3 py-2.5">{asset.internetFacing ? 'Public' : asset.exposure}</td>
                <td className="px-3 py-2.5 text-right">
                  <Tooltip content="Update type, exposure, criticality, or ownership">
                    <Button variant="secondary" onClick={() => beginEdit(asset)}>Edit</Button>
                  </Tooltip>
                </td>
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
  const client = useQueryClient();
  const [rescanningId, setRescanningId] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState<AssetFormValues>(emptyAssetForm);
  const save = useMutation({
    mutationFn: () => api.patch(`/api/assets/${id}`, assetPayload(form)),
    onSuccess: () => {
      setEditing(false);
      void client.invalidateQueries({ queryKey: ['asset', id] });
      void client.invalidateQueries({ queryKey: ['assets'] });
    },
  });
  const query = useQuery({
    queryKey: ['asset', id],
    queryFn: () => api.get<{
      asset: Asset & { description?: string | null; dataSensitivity: string };
      severity: Record<string, number>;
      findings: Array<{ id: string; title: string; severity: string; status: string; riskScore: number }>;
      scans: Array<{ id: string; name: string; scanner: string; status: string; progress: number }>;
      attackPaths: Array<{ id: string; title: string; score: number }>;
    }>(`/api/assets/${id}/posture`),
    refetchInterval: (current) => (current.state.data?.scans.some((scan) => scan.status === 'QUEUED' || scan.status === 'RUNNING') ? 2000 : false),
  });
  async function rescan(scanId: string) {
    setRescanningId(scanId);
    setScanError(null);
    try {
      await api.post(`/api/scans/${scanId}/rescan`);
      await client.invalidateQueries({ queryKey: ['asset', id] });
      await client.invalidateQueries({ queryKey: ['scans'] });
    } catch (error) {
      setScanError(error instanceof Error ? error.message : 'Rescan failed');
    } finally {
      setRescanningId(null);
    }
  }

  if (query.isLoading) return <PageLoading label="Loading asset" />;
  if (query.isError || !query.data) return <p className="text-rose-500">Asset was not found.</p>;
  const { asset, severity, findings, scans, attackPaths } = query.data;
  return (
    <div className="space-y-6">
      <PageHeader
        title={asset.name}
        description={`${asset.type} · ${asset.environment}`}
        actions={editing ? undefined : <Button variant="secondary" onClick={() => { setForm(assetToForm(asset)); save.reset(); setEditing(true); }}>Edit</Button>}
      />
      {editing ? (
        <AssetForm
          form={form}
          setForm={setForm}
          editing
          pending={save.isPending}
          error={save.isError ? (save.error as Error).message : undefined}
          onSubmit={() => save.mutate()}
          onCancel={() => { setEditing(false); save.reset(); }}
        />
      ) : (
        <Panel title="Details">
          <dl className="grid gap-2 text-sm md:grid-cols-3">
            <div>Environment<div className="font-medium">{asset.environment}</div></div>
            <div>Criticality<div className="mt-1"><Severity value={asset.criticality} /></div></div>
            <div>Internet exposure<div className="font-medium">{asset.internetFacing ? 'Public' : asset.exposure}</div></div>
            {asset.technology ? <div>Technology<div className="font-medium">{asset.technology}</div></div> : null}
          </dl>
        </Panel>
      )}
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
        {scanError ? <p className="mb-2 text-sm text-rose-500" role="alert">{scanError}</p> : null}
        {scans.length === 0 ? <Empty title="No scans" body="Start a Semgrep, Trivy, Gitleaks, or ZAP scan." /> : scans.map((scan) => {
          const running = scan.status === 'QUEUED' || scan.status === 'RUNNING';
          return (
            <div key={scan.id} className="flex flex-wrap items-center justify-between gap-3 border-t border-line py-2 text-sm">
              <p className="flex items-center gap-2">
                {running ? <Spinner /> : null}
                <span>{scan.scanner} · {scan.name} · {running ? `Scanning ${scan.progress}%` : scan.status}</span>
              </p>
              <Button variant="secondary" loading={rescanningId === scan.id} onClick={() => void rescan(scan.id)}>Rescan</Button>
            </div>
          );
        })}
      </Panel>
    </div>
  );
}
