import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Button, Empty, Field, PageHeader, PageLoading, Panel, Severity, inputClass } from '../components/ui';
import { api } from '../lib/api';

function scanRequestError(form: { name: string; scanner: string; assetId: string; targetType: string; location: string }): string | null {
  const problems: string[] = [];
  if (!form.name.trim()) problems.push('Enter a scan name.');
  if (!form.assetId) problems.push('Select an asset.');
  const location = form.location.trim();
  if (!location) problems.push('Enter a scan location.');
  const isHttp = /^https?:\/\//i.test(location);
  if (location && form.targetType === 'PATH' && isHttp) {
    problems.push('A PATH target is a local directory. For a website, choose the ZAP scanner and target type URL. For a repository, choose target type GIT.');
  }
  if (form.scanner === 'ZAP' && form.targetType !== 'URL') problems.push('ZAP scans a website or API URL. Set the target type to URL.');
  if (form.targetType === 'URL' && form.scanner !== 'ZAP') problems.push('URL targets are scanned with ZAP.');
  if ((form.scanner === 'SEMGREP' || form.scanner === 'GITLEAKS') && form.targetType !== 'PATH' && form.targetType !== 'GIT') {
    problems.push('Semgrep and Gitleaks scan a local directory or a git repository.');
  }
  if (form.scanner === 'TRIVY' && form.targetType !== 'PATH' && form.targetType !== 'IMAGE') {
    problems.push('Trivy scans a local filesystem path or a container image reference.');
  }
  if (location && form.targetType === 'GIT' && !isHttp) problems.push('A GIT target must be an http or https repository URL.');
  if (location && form.targetType === 'URL' && !isHttp) problems.push('A URL target must start with http:// or https://.');
  return problems.length ? problems.join(' ') : null;
}

export function ScansPage() {
  const client = useQueryClient();
  const scans = useQuery({ queryKey: ['scans'], queryFn: () => api.get<{ data: Array<{ id: string; name: string; scanner: string; status: string; progress: number; asset: { name: string } }> }>('/api/scans') });
  const assets = useQuery({ queryKey: ['assets', 'scan'], queryFn: () => api.get<{ data: Array<{ id: string; name: string }> }>('/api/assets?pageSize=100') });
  const [form, setForm] = useState({ name: 'Lab source scan', scanner: 'SEMGREP', assetId: '', targetType: 'PATH', location: '' });
  const [formError, setFormError] = useState<string | null>(null);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => api.post('/api/scans', form),
    onSuccess: () => {
      setFormError(null);
      void client.invalidateQueries({ queryKey: ['scans'] });
    },
  });
  const locationHint =
    form.scanner === 'ZAP'
      ? 'Website or API base URL, for example https://app.example.com'
      : form.targetType === 'GIT'
        ? 'HTTPS repository URL'
        : form.targetType === 'IMAGE'
          ? 'Container image reference, for example nginx:1.27'
          : 'Absolute local directory on the worker allowlist';

  async function cancelScan(id: string) {
    setCancellingId(id);
    try {
      await api.post(`/api/scans/${id}/cancel`);
      await client.invalidateQueries({ queryKey: ['scans'] });
    } finally {
      setCancellingId(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Scans" description="Queue Semgrep, Trivy, Gitleaks, or ZAP. The worker runs them outside the request." />
      <Panel title="Queue scan">
        <form
          className="grid gap-3 md:grid-cols-2"
          onSubmit={(event) => {
            event.preventDefault();
            const message = scanRequestError(form);
            setFormError(message);
            if (!message) create.mutate();
          }}
        >
          <Field label="Name"><input className={inputClass} value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></Field>
          <Field label="Scanner">
            <select
              className={inputClass}
              value={form.scanner}
              onChange={(event) => {
                const scanner = event.target.value;
                const targetType = scanner === 'ZAP' ? 'URL' : scanner === 'TRIVY' && form.targetType === 'URL' ? 'PATH' : form.targetType === 'URL' ? 'PATH' : form.targetType;
                setForm({ ...form, scanner, targetType });
              }}
            >
              {['SEMGREP','TRIVY','GITLEAKS','ZAP'].map((item) => <option key={item}>{item}</option>)}
            </select>
          </Field>
          <Field label="Asset">
            <select className={inputClass} value={form.assetId} onChange={(event) => setForm({ ...form, assetId: event.target.value })}>
              <option value="">Select asset</option>
              {assets.data?.data.map((asset) => <option key={asset.id} value={asset.id}>{asset.name}</option>)}
            </select>
          </Field>
          <Field label="Target type">
            <select className={inputClass} value={form.targetType} onChange={(event) => setForm({ ...form, targetType: event.target.value })}>
              {['PATH','GIT','URL','IMAGE'].map((item) => <option key={item}>{item}</option>)}
            </select>
          </Field>
          <Field label="Location"><input className={inputClass} value={form.location} onChange={(event) => setForm({ ...form, location: event.target.value })} placeholder={locationHint} /></Field>
          <div className="flex items-end justify-end md:col-span-2"><Button type="submit" loading={create.isPending}>Start scan</Button></div>
        </form>
        <p className="mt-2 text-sm text-mute">{locationHint}</p>
        {assets.isError && <p className="mt-2 text-sm text-rose-500">Assets could not be loaded. {(assets.error as Error).message}</p>}
        {(assets.data?.data.length ?? 0) === 0 && !assets.isLoading && !assets.isError ? <p className="mt-2 text-sm text-mute">Add an asset before queueing a scan.</p> : null}
        {(formError || create.isError) && <p className="mt-2 text-sm text-rose-500">{formError || (create.error as Error).message}</p>}
      </Panel>
      {scans.isLoading ? <PageLoading label="Loading scans" /> : (scans.data?.data.length ?? 0) === 0 ? <Empty title="No scans" body="Queued scans run in the worker and stream progress here." /> : scans.data?.data.map((scan) => (
        <Panel key={scan.id}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="min-w-0 flex-1">
              <p className="font-medium">{scan.name}</p>
              <p className="text-sm text-mute">{scan.scanner} · {scan.asset.name} · {scan.status}</p>
              <div className="mt-2 h-1.5 max-w-sm overflow-hidden rounded-full bg-ink">
                <div className="h-full rounded-full bg-accent" style={{ width: `${scan.progress}%` }} />
              </div>
            </div>
            {scan.status === 'QUEUED' || scan.status === 'RUNNING' ? <Button variant="secondary" loading={cancellingId === scan.id} onClick={() => void cancelScan(scan.id)}>Cancel</Button> : null}
          </div>
        </Panel>
      ))}
    </div>
  );
}

export function AttackPathsPage() {
  const client = useQueryClient();
  const query = useQuery({ queryKey: ['paths'], queryFn: () => api.get<Array<{ id: string; title: string; score: number; summary: string; nodes: Array<{ explanation: string; networkNode: { label: string; kind: string } }> }>>('/api/attack-paths') });
  const rebuild = useMutation({
    mutationFn: () => api.post('/api/attack-paths/rebuild'),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['paths'] }),
  });
  const [selected, setSelected] = useState<string | null>(null);
  const current = query.data?.find((path) => path.id === selected) ?? query.data?.[0];
  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack paths"
        description="Paths from an exposed entry to a sensitive system, scored from stored relationships."
        actions={<Button loading={rebuild.isPending} onClick={() => rebuild.mutate()}>Rebuild graph</Button>}
      />
      {query.isLoading ? <PageLoading label="Loading attack paths" /> : (query.data?.length ?? 0) === 0 ? <Empty title="No attack paths" body="Connect exposed assets to sensitive systems, ingest a vulnerability, then rebuild the graph." /> : (
        <div className="grid gap-4 lg:grid-cols-[280px_minmax(0,1fr)]">
          <Panel title="Paths">
            <div className="space-y-1">
              {query.data?.map((path) => (
                <button key={path.id} type="button" className={`block w-full rounded-md px-3 py-2 text-left text-sm ${path.id === current?.id ? 'bg-accent/15 text-accent' : 'hover:bg-ink'}`} onClick={() => setSelected(path.id)}>
                  <span className="font-mono">{path.score}</span> · {path.title}
                </button>
              ))}
            </div>
          </Panel>
          {current && (
            <Panel title="Path">
              <p className="text-sm text-mute">{current.summary}</p>
              <ol className="mt-4">
                {current.nodes.map((node, index) => (
                  <li key={`${node.networkNode.label}-${index}`} className="relative border-l border-line pb-4 pl-4 last:pb-0">
                    <span className="absolute -left-1.5 top-1 h-3 w-3 rounded-full border-2 border-accent bg-panel" />
                    <p className="font-medium">{node.networkNode.label}</p>
                    <p className="text-xs uppercase tracking-wide text-mute">{node.networkNode.kind}</p>
                    <p className="mt-1 text-sm">{node.explanation}</p>
                  </li>
                ))}
              </ol>
            </Panel>
          )}
        </div>
      )}
      {rebuild.isError && <p className="text-sm text-rose-500">{(rebuild.error as Error).message}</p>}
    </div>
  );
}

export function IncidentsPage() {
  const client = useQueryClient();
  const query = useQuery({ queryKey: ['incidents'], queryFn: () => api.get<Array<{ id: string; title: string; severity: string; status: string }>>('/api/incidents') });
  const [title, setTitle] = useState('');
  const create = useMutation({
    mutationFn: () => api.post('/api/incidents', { title, severity: 'HIGH' }),
    onSuccess: () => {
      setTitle('');
      void client.invalidateQueries({ queryKey: ['incidents'] });
    },
  });
  return (
    <div className="space-y-6">
      <PageHeader title="Incidents" description="Track an active security event and the assets tied to it." />
      <Panel title="Open incident">
        <form className="flex flex-wrap gap-2" onSubmit={(event) => { event.preventDefault(); create.mutate(); }}>
          <input className={inputClass + ' min-w-[16rem] flex-1'} value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Incident title" required />
          <Button type="submit" loading={create.isPending}>Create</Button>
        </form>
        {create.isError && <p className="mt-2 text-sm text-rose-500">{(create.error as Error).message}</p>}
      </Panel>
      {query.isLoading ? <PageLoading label="Loading incidents" /> : (query.data?.length ?? 0) === 0 ? <Empty title="No incidents" body="Create an incident from a finding, event, or attack path." /> : query.data?.map((incident) => (
        <Panel key={incident.id}><div className="flex items-center gap-2"><Severity value={incident.severity} /><span>{incident.title}</span><span className="text-mute">{incident.status}</span></div></Panel>
      ))}
    </div>
  );
}

export function RemediationsPage() {
  const client = useQueryClient();
  const query = useQuery({ queryKey: ['remediations'], queryFn: () => api.get<Array<{ id: string; status: string; vulnerability: { title: string }; assignee?: { name: string } | null }>>('/api/remediations') });
  const [validatingId, setValidatingId] = useState<string | null>(null);
  async function validate(id: string) {
    setValidatingId(id);
    try {
      await api.post(`/api/remediations/${id}/validate`);
      await client.invalidateQueries({ queryKey: ['remediations'] });
    } finally {
      setValidatingId(null);
    }
  }
  return (
    <div className="space-y-6">
      <PageHeader title="Remediation" description="Work assigned to an engineer. A fix is confirmed only by a validation scan." />
      {query.isLoading ? <PageLoading label="Loading remediation" /> : (query.data?.length ?? 0) === 0 ? <Empty title="No remediation work" body="Assign a finding to an engineer from the vulnerability page." /> : query.data?.map((item) => (
        <Panel key={item.id}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="font-medium">{item.vulnerability.title}</p>
              <p className="text-sm text-mute">{item.status} {item.assignee ? `· ${item.assignee.name}` : ''}</p>
            </div>
            <Button loading={validatingId === item.id} onClick={() => void validate(item.id)}>Validate fix</Button>
          </div>
        </Panel>
      ))}
    </div>
  );
}

export function EventsPage() {
  const client = useQueryClient();
  const query = useQuery({ queryKey: ['events'], queryFn: () => api.get<{ data: Array<{ id: string; timestamp: string; severity: string; eventType: string; source: string; actor?: string | null }> }>('/api/events') });
  const [eventType, setEventType] = useState('auth.failure');
  const ingest = useMutation({
    mutationFn: () => api.post('/api/events', { timestamp: new Date().toISOString(), source: 'manual', eventType, severity: 'MEDIUM', rawEvent: { note: 'analyst submitted event' } }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['events'] }),
  });
  return (
    <div className="space-y-6">
      <PageHeader title="Security events" description="Normalized events from analysts today, and from a SIEM adapter later." />
      <Panel title="Ingest event">
        <form className="flex flex-wrap gap-2" onSubmit={(event) => { event.preventDefault(); ingest.mutate(); }}>
          <input className={inputClass + ' min-w-[16rem] flex-1'} value={eventType} onChange={(event) => setEventType(event.target.value)} />
          <Button type="submit" loading={ingest.isPending}>Ingest</Button>
        </form>
        {ingest.isError && <p className="mt-2 text-sm text-rose-500">{(ingest.error as Error).message}</p>}
      </Panel>
      {query.isLoading ? <PageLoading label="Loading events" /> : (query.data?.data.length ?? 0) === 0 ? <Empty title="No events" body="Ingest a normalized event or connect a future SIEM adapter." /> : query.data?.data.map((item) => (
        <p key={item.id} className="text-sm">{new Date(item.timestamp).toLocaleString()} · <Severity value={item.severity} /> {item.source} · {item.eventType} · {item.actor ?? 'unknown actor'}</p>
      ))}
    </div>
  );
}

export function ReportsPage() {
  const [downloading, setDownloading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function download(format: 'json' | 'csv' | 'pdf') {
    setDownloading(format);
    setError(null);
    try {
      const response = await fetch(`/api/reports/export?format=${format}`, { credentials: 'include' });
      if (!response.ok) throw new Error(`Report failed (${response.status})`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `security-report.${format}`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Report failed');
    } finally {
      setDownloading(null);
    }
  }
  return (
    <div className="space-y-6">
      <PageHeader title="Reports" description="Generated from the database at request time. Secret values are masked." />
      <Panel title="Generate">
        <div className="flex flex-wrap gap-2">
          {(['json', 'csv', 'pdf'] as const).map((format) => (
            <Button key={format} variant={format === 'pdf' ? 'primary' : 'secondary'} loading={downloading === format} disabled={downloading !== null && downloading !== format} onClick={() => void download(format)}>
              Download {format.toUpperCase()}
            </Button>
          ))}
        </div>
        {error && <p className="mt-3 text-sm text-rose-500">{error}</p>}
      </Panel>
    </div>
  );
}

export function AuditPage() {
  const query = useQuery({ queryKey: ['audit'], queryFn: () => api.get<{ data: Array<{ id: string; createdAt: string; action: string; resource: string; userId?: string | null }> }>('/api/audit') });
  return (
    <div className="space-y-6">
      <PageHeader title="Audit log" description="Authentication, scans, and workflow changes. Rows cannot be edited." />
      {query.isLoading ? <PageLoading label="Loading audit log" /> : (query.data?.data.length ?? 0) === 0 ? <Empty title="No audit events" body="Authentication, scans, and workflow changes are appended here." /> : (
        <Panel>
          <ul className="divide-y divide-line font-mono text-xs">
            {query.data?.data.map((entry) => (
              <li key={entry.id} className="py-2">{new Date(entry.createdAt).toISOString()} {entry.action} {entry.resource}</li>
            ))}
          </ul>
        </Panel>
      )}
      </div>
  );
}

export function SettingsPage() {
  const client = useQueryClient();
  const users = useQuery({ queryKey: ['users'], queryFn: () => api.get<Array<{ id: string; name: string; email: string; role: string }>>('/api/users') });
  const [form, setForm] = useState({ name: '', email: '', password: 'ChangeThis-Analyst-1!', role: 'SECURITY_ANALYST' });
  const create = useMutation({
    mutationFn: () => api.post('/api/users', form),
    onSuccess: () => {
      setForm((current) => ({ ...current, name: '', email: '' }));
      void client.invalidateQueries({ queryKey: ['users'] });
    },
  });
  return (
    <div className="space-y-6">
      <PageHeader title="Organization settings" description="Members, roles, and the relationships the attack-path graph walks." />
      <Panel title="Provision user">
        <form className="grid gap-3 md:grid-cols-2" onSubmit={(event) => { event.preventDefault(); create.mutate(); }}>
          <Field label="Name"><input className={inputClass} value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></Field>
          <Field label="Email"><input className={inputClass} value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} /></Field>
          <Field label="Temporary password"><input className={inputClass} value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} /></Field>
          <Field label="Role">
            <select className={inputClass} value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })}>
              {['SECURITY_ADMIN','SECURITY_ANALYST','ENGINEER','VIEWER'].map((role) => <option key={role}>{role}</option>)}
            </select>
          </Field>
          <div className="flex items-end justify-end md:col-span-2"><Button type="submit" loading={create.isPending}>Add user</Button></div>
        </form>
        {create.isError && <p className="mt-2 text-sm text-rose-500">{(create.error as Error).message}</p>}
      </Panel>
      <Panel title="Members">
        {users.isLoading ? <PageLoading label="Loading members" /> : users.data?.map((user) => (
          <p key={user.id} className="border-t border-line py-2 text-sm first:border-t-0">{user.name} · {user.email} · {user.role}</p>
        ))}
        <p className="mt-3 text-xs text-mute">Engineer ids can be copied from the API response when assigning remediation.</p>
      </Panel>
      <Panel title="Relationship">
        <RelationshipForm />
      </Panel>
    </div>
  );
}

function RelationshipForm() {
  const assets = useQuery({ queryKey: ['assets', 'rel'], queryFn: () => api.get<{ data: Array<{ id: string; name: string }> }>('/api/assets?pageSize=100') });
  const [source, setSource] = useState('');
  const [target, setTarget] = useState('');
  const [type, setType] = useState('CAN_ACCESS');
  const connect = useMutation({
    mutationFn: () => api.post('/api/assets/relationships', { sourceAssetId: source, targetAssetId: target, type }),
  });
  return (
    <form className="grid gap-3 md:grid-cols-3" onSubmit={(event) => { event.preventDefault(); connect.mutate(); }}>
      <Field label="From">
        <select className={inputClass} value={source} onChange={(event) => setSource(event.target.value)}>
          <option value="">Select asset</option>
          {assets.data?.data.map((asset) => <option key={asset.id} value={asset.id}>{asset.name}</option>)}
        </select>
      </Field>
      <Field label="Relationship">
        <select className={inputClass} value={type} onChange={(event) => setType(event.target.value)}>{['CONNECTS_TO','CAN_ACCESS','RUNS_ON','AUTHENTICATES_TO','ASSUMES_ROLE','CONTAINS','DEPENDS_ON'].map((item) => <option key={item}>{item}</option>)}</select>
      </Field>
      <Field label="To">
        <select className={inputClass} value={target} onChange={(event) => setTarget(event.target.value)}>
          <option value="">Select asset</option>
          {assets.data?.data.map((asset) => <option key={asset.id} value={asset.id}>{asset.name}</option>)}
        </select>
      </Field>
      <div className="flex justify-end md:col-span-3">
        <Button type="submit" loading={connect.isPending}>Connect assets</Button>
      </div>
      {connect.isError && <p className="text-sm text-rose-500 md:col-span-3">{(connect.error as Error).message}</p>}
      {connect.isSuccess && <p className="text-sm text-mute md:col-span-3">Relationship saved.</p>}
    </form>
  );
}

export function HomeLink() {
  return <Link to="/dashboard">Dashboard</Link>;
}
