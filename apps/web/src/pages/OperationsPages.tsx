import { PERMISSIONS } from '@seap/shared';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronRight } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Button, Empty, Field, PageHeader, PageLoading, Panel, Severity, Spinner, Table, Tooltip, inputClass } from '../components/ui';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';

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

type ScanRow = { id: string; name: string; scanner: string; status: string; progress: number; asset: { name: string } };
type ScanAsset = { id: string; name: string; type: string };

const SCANNER_OPTIONS: Record<string, { targets: string[]; assets: Record<string, string[]> }> = {
  SEMGREP: { targets: ['PATH', 'GIT'], assets: { PATH: ['APPLICATION', 'REPOSITORY', 'API'], GIT: ['REPOSITORY'] } },
  GITLEAKS: { targets: ['PATH', 'GIT'], assets: { PATH: ['REPOSITORY', 'APPLICATION'], GIT: ['REPOSITORY'] } },
  TRIVY: { targets: ['PATH', 'IMAGE'], assets: { PATH: ['APPLICATION', 'REPOSITORY', 'API'], IMAGE: ['CONTAINER_IMAGE'] } },
  ZAP: { targets: ['URL'], assets: { URL: ['API', 'APPLICATION', 'DOMAIN'] } },
};

function scannerOptions(scanner: string) {
  return SCANNER_OPTIONS[scanner] ?? SCANNER_OPTIONS.SEMGREP;
}

function assetsForScan(scanner: string, targetType: string, assets: ScanAsset[]) {
  const allowed = new Set(scannerOptions(scanner).assets[targetType] ?? []);
  return assets.filter((asset) => allowed.has(asset.type));
}

function selectionForScanner(scanner: string, targetType: string, assetId: string, assets: ScanAsset[]) {
  const targets = scannerOptions(scanner).targets;
  const nextTarget = targets.includes(targetType) ? targetType : targets[0];
  const matching = assetsForScan(scanner, nextTarget, assets);
  const assetIdStillValid = matching.some((asset) => asset.id === assetId);
  return {
    targetType: nextTarget,
    assetId: assetIdStillValid ? assetId : matching.length === 1 ? matching[0].id : '',
    targets,
    matching,
  };
}

function scanInProgress(status: string) {
  return status === 'QUEUED' || status === 'RUNNING';
}

export function ScansPage() {
  const client = useQueryClient();
  const scans = useQuery({
    queryKey: ['scans'],
    queryFn: () => api.get<{ data: ScanRow[] }>('/api/scans'),
    refetchInterval: (query) => (query.state.data?.data.some((scan) => scanInProgress(scan.status)) ? 2000 : false),
  });
  const assets = useQuery({ queryKey: ['assets', 'scan'], queryFn: () => api.get<{ data: ScanAsset[] }>('/api/assets?pageSize=100') });
  const [form, setForm] = useState({ name: 'Lab source scan', scanner: 'SEMGREP', assetId: '', targetType: 'PATH', location: '' });
  const [formError, setFormError] = useState<string | null>(null);
  const [cancellingId, setCancellingId] = useState<string | null>(null);
  const [rescanningId, setRescanningId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => api.post('/api/scans', form),
    onSuccess: () => {
      setFormError(null);
      void client.invalidateQueries({ queryKey: ['scans'] });
    },
  });
  const catalog = assets.data?.data ?? [];
  const selection = selectionForScanner(form.scanner, form.targetType, form.assetId, catalog);
  useEffect(() => {
    if (!assets.data) return;
    if (selection.targetType === form.targetType && selection.assetId === form.assetId) return;
    setForm((current) => ({ ...current, targetType: selection.targetType, assetId: selection.assetId }));
  }, [assets.data, form.assetId, form.scanner, form.targetType, selection.assetId, selection.targetType]);
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
    setActionError(null);
    try {
      await api.post(`/api/scans/${id}/cancel`);
      await client.invalidateQueries({ queryKey: ['scans'] });
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Cancel failed');
    } finally {
      setCancellingId(null);
    }
  }

  async function rescan(id: string) {
    setRescanningId(id);
    setActionError(null);
    try {
      await api.post(`/api/scans/${id}/rescan`);
      await client.invalidateQueries({ queryKey: ['scans'] });
    } catch (error) {
      setActionError(error instanceof Error ? error.message : 'Rescan failed');
    } finally {
      setRescanningId(null);
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Scans" description="Queue Semgrep, Trivy, Gitleaks, or ZAP. The worker runs them outside the request." />
      <Panel title="Queue scan" tip="Pick a scanner, asset, and target. The worker runs the job and streams progress below.">
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
                const next = selectionForScanner(scanner, form.targetType, form.assetId, catalog);
                setForm({ ...form, scanner, targetType: next.targetType, assetId: next.assetId });
              }}
            >
              {['SEMGREP','TRIVY','GITLEAKS','ZAP'].map((item) => <option key={item}>{item}</option>)}
            </select>
          </Field>
          <Field label="Asset">
            <select className={inputClass} value={selection.matching.some((asset) => asset.id === form.assetId) ? form.assetId : ''} disabled={selection.matching.length === 1} onChange={(event) => setForm({ ...form, assetId: event.target.value })}>
              {selection.matching.length === 1 ? null : <option value="">Select asset</option>}
              {selection.matching.map((asset) => <option key={asset.id} value={asset.id}>{asset.name}</option>)}
            </select>
          </Field>
          <Field label="Target type">
            <select className={inputClass} value={selection.targetType} disabled={selection.targets.length === 1} onChange={(event) => {
              const next = selectionForScanner(form.scanner, event.target.value, form.assetId, catalog);
              setForm({ ...form, targetType: next.targetType, assetId: next.assetId });
            }}>
              {selection.targets.map((item) => <option key={item}>{item}</option>)}
            </select>
          </Field>
          <Field label="Location"><input className={inputClass} value={form.location} onChange={(event) => setForm({ ...form, location: event.target.value })} placeholder={locationHint} /></Field>
          <div className="flex items-end justify-end md:col-span-2"><Button type="submit" loading={create.isPending}>Start scan</Button></div>
        </form>
        <p className="mt-2 text-sm text-mute">{locationHint}</p>
        {assets.isError && <p className="mt-2 text-sm text-rose-500">Assets could not be loaded. {(assets.error as Error).message}</p>}
        {(assets.data?.data.length ?? 0) === 0 && !assets.isLoading && !assets.isError ? <p className="mt-2 text-sm text-mute">Add an asset before queueing a scan.</p> : null}
        {assets.data && selection.matching.length === 0 ? <p className="mt-2 text-sm text-mute">No assets of the type this scanner can target. Add one, or choose another target type.</p> : null}
        {(formError || create.isError) && <p className="mt-2 text-sm text-rose-500">{formError || (create.error as Error).message}</p>}
      </Panel>
      {actionError ? <p className="text-sm text-rose-500" role="alert">{actionError}</p> : null}
      {scans.isLoading ? <PageLoading label="Loading scans" /> : (scans.data?.data.length ?? 0) === 0 ? <Empty title="No scans" body="Queued scans run in the worker and stream progress here." /> : scans.data?.data.map((scan) => {
        const running = scanInProgress(scan.status);
        return (
          <Panel key={scan.id}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0 flex-1">
                <p className="font-medium">{scan.name}</p>
                <p className="flex items-center gap-2 text-sm text-mute">
                  {running ? <Spinner /> : null}
                  <span>{scan.scanner} · {scan.asset.name} · {running ? 'Scanning' : scan.status}{running ? ` · ${scan.progress}%` : ''}</span>
                </p>
                <div
                  className="mt-2 h-1.5 max-w-sm overflow-hidden rounded-full bg-ink"
                  role="progressbar"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={running ? scan.progress : 100}
                  aria-label={`${scan.name} progress`}
                >
                  {running && scan.progress < 8 ? (
                    <div className="seap-scan-bar h-full rounded-full bg-accent" />
                  ) : (
                    <div className="h-full rounded-full bg-accent transition-[width] duration-500" style={{ width: `${running ? scan.progress : 100}%` }} />
                  )}
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                {running ? null : (
                  <Link to={`/scans/${scan.id}`} className="inline-flex min-h-9 items-center justify-center rounded-md border border-line bg-panel px-3 py-2 text-sm font-medium hover:bg-ink">
                    View results
                  </Link>
                )}
                <Tooltip content="Queue the same scanner and target again">
                  <Button variant="secondary" loading={rescanningId === scan.id} onClick={() => void rescan(scan.id)}>Rescan</Button>
                </Tooltip>
                {running ? (
                  <Tooltip content="Stop this scan before it finishes">
                    <Button variant="secondary" loading={cancellingId === scan.id} onClick={() => void cancelScan(scan.id)}>Cancel</Button>
                  </Tooltip>
                ) : null}
              </div>
            </div>
          </Panel>
        );
      })}
    </div>
  );
}

interface ScanFinding {
  id: string;
  title: string;
  severity: string;
  status: string;
  location?: string | null;
  vulnerabilityId: string;
}

export function ScanDetailPage() {
  const { id = '' } = useParams();
  const query = useQuery({
    queryKey: ['scan', id],
    queryFn: () => api.get<{
      name: string;
      scanner: string;
      status: string;
      error?: string | null;
      asset: { id: string; name: string };
      targets: Array<{ location: string; targetType: string }>;
      result?: { findingCount: number } | null;
      findings: ScanFinding[];
    }>(`/api/scans/${id}`),
  });
  if (query.isLoading) return <PageLoading label="Loading scan results" />;
  if (query.isError || !query.data) return <p className="text-rose-500">Scan results could not be loaded.</p>;
  const scan = query.data;
  const target = scan.targets[0];
  return (
    <div className="space-y-6">
      <PageHeader
        title={scan.name}
        description={`${scan.scanner} · ${scan.asset.name} · ${scan.status}`}
        actions={<Link to="/scans" className="inline-flex min-h-9 items-center rounded-md border border-line bg-panel px-3 py-2 text-sm font-medium hover:bg-ink">Back to scans</Link>}
      />
      <Panel title="Summary">
        <dl className="grid gap-3 text-sm md:grid-cols-3">
          <div>Findings<div className="font-mono text-lg">{scan.findings.length}</div>{scan.result && scan.result.findingCount !== scan.findings.length ? <p className="text-mute">Scanner reported {scan.result.findingCount}. Duplicates were merged.</p> : null}</div>
          <div>Target<div className="break-all font-medium">{target ? `${target.targetType} · ${target.location}` : 'None'}</div></div>
          <div>Asset<div className="font-medium"><Link className="text-accent" to={`/assets/${scan.asset.id}`}>{scan.asset.name}</Link></div></div>
        </dl>
        {scan.error ? <p className="mt-3 text-sm text-rose-500">{scan.error}</p> : null}
      </Panel>
      <Panel title="Results">
        {scan.findings.length === 0 ? (
          <Empty title="No findings" body={scan.status === 'FAILED' ? 'This scan failed before it could store findings.' : 'The scanner finished without reporting findings.'} />
        ) : (
          <Table headers={['Title', 'Severity', 'Status', 'Location']}>
            {scan.findings.map((finding) => (
              <tr key={finding.id} className="border-t border-line">
                <td className="px-3 py-2.5"><Link className="font-medium text-accent" to={`/findings/${finding.vulnerabilityId}`}>{finding.title}</Link></td>
                <td className="px-3 py-2.5"><Severity value={finding.severity} /></td>
                <td className="px-3 py-2.5">{finding.status}</td>
                <td className="max-w-xs truncate px-3 py-2.5" title={finding.location ?? undefined}>{finding.location ?? '—'}</td>
              </tr>
            ))}
          </Table>
        )}
      </Panel>
    </div>
  );
}

interface AttackPathRow {
  id: string;
  title: string;
  score: number;
  summary: string;
  nodes: Array<{ explanation: string; networkNode: { label: string; kind: string; assetId?: string | null } }>;
}

function projectsOn(path: AttackPathRow) {
  const projects = new Map<string, string>();
  path.nodes.forEach((node, index) => {
    if (node.networkNode.kind !== 'VULNERABILITY' || index === 0) return;
    const asset = path.nodes[index - 1].networkNode;
    projects.set(asset.assetId || asset.label, asset.label);
  });
  if (projects.size === 0) projects.set('none', 'Unassigned');
  return [...projects.entries()].map(([id, name]) => ({ id, name }));
}

function pathProjects(paths: AttackPathRow[]) {
  const groups = new Map<string, { id: string; name: string; paths: AttackPathRow[] }>();
  for (const path of paths) {
    for (const project of projectsOn(path)) {
      const group = groups.get(project.id) ?? { id: project.id, name: project.name, paths: [] };
      group.paths.push(path);
      groups.set(project.id, group);
    }
  }
  return [...groups.values()]
    .map((group) => ({ ...group, paths: [...group.paths].sort((left, right) => right.score - left.score) }))
    .sort((left, right) => right.paths[0].score - left.paths[0].score);
}

export function AttackPathsPage() {
  const client = useQueryClient();
  const query = useQuery({ queryKey: ['paths'], queryFn: () => api.get<AttackPathRow[]>('/api/attack-paths') });
  const rebuild = useMutation({
    mutationFn: () => api.post('/api/attack-paths/rebuild'),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['paths'] }),
  });
  const [selected, setSelected] = useState<string | null>(null);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const groups = pathProjects(query.data ?? []);
  const current = query.data?.find((path) => path.id === selected) ?? groups[0]?.paths[0];
  return (
    <div className="flex flex-col md:h-[calc(100dvh-7rem)] md:overflow-hidden">
      <PageHeader
        title="Attack paths"
        description="Paths grouped by the project that carries the finding."
        actions={
          <Tooltip content="Recalculate attack paths from assets, findings, and stored relationships">
            <Button loading={rebuild.isPending} onClick={() => rebuild.mutate()}>Rebuild graph</Button>
          </Tooltip>
        }
      />
      {rebuild.isError && <p className="mt-3 text-sm text-rose-500">{(rebuild.error as Error).message}</p>}
      {query.isLoading ? <PageLoading label="Loading attack paths" /> : groups.length === 0 ? <div className="mt-6"><Empty title="No attack paths" body="Connect exposed assets to sensitive systems, ingest a vulnerability, then rebuild the graph." /></div> : (
        <div className="mt-4 grid min-h-0 min-w-0 flex-1 gap-4 md:grid-cols-[minmax(240px,380px)_minmax(0,1fr)]">
          <div className="max-h-80 min-w-0 overflow-y-auto overscroll-contain rounded-lg border border-line bg-panel md:max-h-none">
            {groups.map((group, index) => {
              const expanded = group.id in open ? open[group.id] : index === 0;
              const highest = group.paths[0]?.score ?? 0;
              return (
                <section key={group.id} className="border-b border-line last:border-b-0">
                  <button
                    type="button"
                    className="sticky top-0 z-10 flex w-full items-start gap-2 bg-panel px-4 py-3 text-left"
                    aria-expanded={expanded}
                    onClick={() => setOpen((currentOpen) => ({ ...currentOpen, [group.id]: !expanded }))}
                  >
                    <ChevronRight className={`mt-0.5 h-4 w-4 shrink-0 text-mute transition-transform ${expanded ? 'rotate-90' : ''}`} aria-hidden="true" />
                    <span className="min-w-0">
                      <span className="block text-sm font-semibold">{group.name}</span>
                      <span className="mt-0.5 block text-xs text-mute">{group.paths.length} {group.paths.length === 1 ? 'path' : 'paths'} · highest {highest}</span>
                    </span>
                  </button>
                  {expanded ? group.paths.map((path) => (
                    <button key={path.id} type="button" className={`flex w-full gap-3 border-t border-line px-4 py-2.5 text-left text-sm ${path.id === current?.id ? 'bg-accent/15 text-accent' : 'hover:bg-ink'}`} onClick={() => setSelected(path.id)}>
                      <span className="w-8 shrink-0 font-mono">{path.score}</span>
                      <span className="line-clamp-2 leading-snug">{path.title}</span>
                    </button>
                  )) : null}
                </section>
              );
            })}
          </div>
          {current && (
            <section className="min-w-0 rounded-lg border border-line bg-panel p-4">
              <div className="flex items-start justify-between gap-3">
                <h2 className="text-sm font-semibold">{projectsOn(current).map((project) => project.name).join(', ')}</h2>
                <span className="font-mono text-sm">{current.score}</span>
              </div>
              <p className="mt-2 text-sm text-mute">{current.summary}</p>
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
            </section>
          )}
        </div>
      )}
    </div>
  );
}

export function IncidentsPage() {
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ['incidents'],
    queryFn: () => api.get<Array<{
      id: string;
      title: string;
      summary?: string | null;
      severity: string;
      status: string;
      assignee?: { name: string } | null;
      assets: Array<{ asset: { name: string } }>;
      findings: Array<{ vulnerabilityId: string }>;
      events: Array<{ eventId: string }>;
      attackPaths: Array<{ attackPath: { title: string; score: number } }>;
    }>>('/api/incidents'),
  });
  const paths = useQuery({ queryKey: ['paths'], queryFn: () => api.get<Array<{ id: string }>>('/api/attack-paths') });
  const events = useQuery({ queryKey: ['events'], queryFn: () => api.get<{ data: Array<{ id: string }> }>('/api/events') });
  const [title, setTitle] = useState('');
  const create = useMutation({
    mutationFn: () => api.post('/api/incidents', {
      title,
      severity: 'HIGH',
      attackPathIds: paths.data?.[0] ? [paths.data[0].id] : undefined,
      eventIds: events.data?.data.slice(0, 5).map((event) => event.id),
    }),
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
          <input className={inputClass + ' min-w-[16rem] flex-1'} value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Incident title" required minLength={3} />
          <Button type="submit" loading={create.isPending}>Create</Button>
        </form>
        <p className="mt-2 text-sm text-mute">Create links the highest attack path, the high and medium findings on that path, and the latest events.</p>
        {create.isError && <p className="mt-2 text-sm text-rose-500">{(create.error as Error).message}</p>}
      </Panel>
      {query.isLoading ? <PageLoading label="Loading incidents" /> : (query.data?.length ?? 0) === 0 ? <Empty title="No incidents" body="Create an incident from a finding, event, or attack path." /> : query.data?.map((incident) => (
        <Panel key={incident.id}>
          <div className="flex flex-wrap items-center gap-2">
            <Severity value={incident.severity} />
            <span className="font-medium">{incident.title}</span>
            <span className="text-sm text-mute">{incident.status}{incident.assignee ? ` · ${incident.assignee.name}` : ''}</span>
          </div>
          {incident.summary ? <p className="mt-2 text-sm">{incident.summary}</p> : null}
          <p className="mt-2 text-sm text-mute">
            {incident.assets.map((item) => item.asset.name).join(', ') || 'No assets'}
            {' · '}{incident.findings.length} {incident.findings.length === 1 ? 'finding' : 'findings'}
            {' · '}{incident.events.length} {incident.events.length === 1 ? 'event' : 'events'}
            {' · '}{incident.attackPaths.length} {incident.attackPaths.length === 1 ? 'attack path' : 'attack paths'}
          </p>
          {incident.attackPaths[0] ? <p className="mt-1 text-sm">{incident.attackPaths[0].attackPath.score} · {incident.attackPaths[0].attackPath.title}</p> : null}
        </Panel>
      ))}
    </div>
  );
}

export function RemediationsPage() {
  const client = useQueryClient();
  const query = useQuery({ queryKey: ['remediations'], queryFn: () => api.get<Array<{ id: string; status: string; dueAt?: string | null; vulnerability: { title: string; severity: string; asset: { name: string } }; assignee?: { name: string } | null }>>('/api/remediations') });
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
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-medium">{item.vulnerability.title}</p>
                <Severity value={item.vulnerability.severity} />
              </div>
              <p className="mt-1 text-sm text-mute">
                {item.vulnerability.asset.name} · {item.status}{item.assignee ? ` · ${item.assignee.name}` : ''}{item.dueAt ? ` · due ${new Date(item.dueAt).toLocaleDateString()}` : ''}
              </p>
            </div>
            <Tooltip content="Re-run the scanner that found this issue. Resolves only if it is gone.">
              <Button loading={validatingId === item.id} onClick={() => void validate(item.id)}>Validate fix</Button>
            </Tooltip>
          </div>
        </Panel>
      ))}
    </div>
  );
}

export function EventsPage() {
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ['events'],
    queryFn: () => api.get<{ data: Array<{ id: string; timestamp: string; severity: string; eventType: string; source: string; actor?: string | null; asset?: { name: string } | null; incidents: Array<{ incident: { title: string } }> }> }>('/api/events'),
  });
  const assets = useQuery({ queryKey: ['assets', 'events'], queryFn: () => api.get<{ data: Array<{ id: string; name: string }> }>('/api/assets?pageSize=100') });
  const [eventType, setEventType] = useState('auth.failure');
  const [assetId, setAssetId] = useState('');
  const ingest = useMutation({
    mutationFn: () => api.post('/api/events', {
      timestamp: new Date().toISOString(),
      source: 'manual',
      eventType,
      severity: 'MEDIUM',
      assetId: assetId || undefined,
      rawEvent: { note: 'analyst submitted event' },
    }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['events'] }),
  });
  return (
    <div className="space-y-6">
      <PageHeader title="Security events" description="Normalized events from analysts today, and from a SIEM adapter later." />
      <Panel title="Ingest event">
        <form className="flex flex-wrap gap-2" onSubmit={(event) => { event.preventDefault(); ingest.mutate(); }}>
          <input aria-label="Event type" className={inputClass + ' min-w-[12rem] flex-1'} value={eventType} onChange={(event) => setEventType(event.target.value)} />
          <select aria-label="Asset" className={inputClass + ' max-w-xs'} value={assetId} onChange={(event) => setAssetId(event.target.value)}>
            <option value="">No asset</option>
            {assets.data?.data.map((asset) => <option key={asset.id} value={asset.id}>{asset.name}</option>)}
          </select>
          <Button type="submit" loading={ingest.isPending}>Ingest</Button>
        </form>
        {ingest.isError && <p className="mt-2 text-sm text-rose-500">{(ingest.error as Error).message}</p>}
      </Panel>
      {query.isLoading ? <PageLoading label="Loading events" /> : (query.data?.data.length ?? 0) === 0 ? <Empty title="No events" body="Ingest a normalized event or connect a future SIEM adapter." /> : query.data?.data.map((item) => (
        <p key={item.id} className="text-sm">
          {new Date(item.timestamp).toLocaleString()} · <Severity value={item.severity} /> {item.source} · {item.eventType} · {item.actor ?? 'unknown actor'}
          {item.asset ? ` · ${item.asset.name}` : ''}
          {item.incidents[0] ? ` · ${item.incidents[0].incident.title}` : ''}
        </p>
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
            <Tooltip key={format} content={`Export the current security posture as ${format.toUpperCase()}. Secrets stay masked.`}>
              <Button variant={format === 'pdf' ? 'primary' : 'secondary'} loading={downloading === format} disabled={downloading !== null && downloading !== format} onClick={() => void download(format)}>
                Download {format.toUpperCase()}
              </Button>
            </Tooltip>
          ))}
        </div>
        {error && <p className="mt-3 text-sm text-rose-500">{error}</p>}
      </Panel>
    </div>
  );
}

type AuditEntry = {
  id: string;
  createdAt: string;
  action: string;
  resource: string;
  actor: { name: string; email: string | null };
};

export function AuditPage() {
  const query = useQuery({
    queryKey: ['audit'],
    queryFn: () => api.get<{ data: AuditEntry[]; total: number }>('/api/audit?pageSize=100'),
  });
  const rows = query.data?.data ?? [];
  return (
    <div className="space-y-6">
      <PageHeader title="Audit log" description="Who changed authentication, scans, and workflow records. Rows cannot be edited." />
      {query.isLoading ? <PageLoading label="Loading audit log" /> : rows.length === 0 ? <Empty title="No audit events" body="Authentication, scans, and workflow changes are appended here." /> : (
        <Panel>
          <Table headers={['When', 'User', 'Action', 'Resource']}>
            {rows.map((entry) => (
              <tr key={entry.id} className="border-t border-line align-top">
                <td className="whitespace-nowrap px-3 py-2.5">{new Date(entry.createdAt).toLocaleString()}</td>
                <td className="px-3 py-2.5">
                  <p className="font-medium">{entry.actor.name}</p>
                  {entry.actor.email && entry.actor.email !== entry.actor.name ? <p className="text-xs text-mute">{entry.actor.email}</p> : null}
                </td>
                <td className="px-3 py-2.5 font-mono text-xs">{entry.action}</td>
                <td className="px-3 py-2.5">{entry.resource}</td>
              </tr>
            ))}
          </Table>
          {query.data && query.data.total > rows.length ? <p className="mt-3 text-xs text-mute">Showing the latest {rows.length} of {query.data.total}.</p> : null}
        </Panel>
      )}
    </div>
  );
}

type Member = { id: string; name: string; email: string; role: string; roleKey: string; lastLoginAt?: string | null };
type RoleRecord = { id: string; name: string; description: string; permissions: string[]; system: boolean; members: number };

const PERMISSION_GROUPS = [
  { label: 'Organization', prefix: 'org' },
  { label: 'Members', prefix: 'user' },
  { label: 'Audit', prefix: 'audit' },
  { label: 'Assets', prefix: 'asset' },
  { label: 'Findings', prefix: 'finding' },
  { label: 'Scans', prefix: 'scan' },
  { label: 'Attack paths', prefix: 'attackpath' },
  { label: 'Incidents', prefix: 'incident' },
  { label: 'Remediation', prefix: 'remediation' },
  { label: 'Events', prefix: 'event' },
  { label: 'Reports', prefix: 'report' },
  { label: 'Policies', prefix: 'policy' },
  { label: 'Notifications', prefix: 'notification' },
  { label: 'Dashboard', prefix: 'dashboard' },
];

function roleLabel(name: string) {
  if (name !== name.toUpperCase() || name.includes(' ')) return name;
  return name.toLowerCase().split('_').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(' ');
}

function permissionGroups() {
  const used = new Set<string>();
  const groups = PERMISSION_GROUPS.map((group) => {
    const items = PERMISSIONS.filter((permission) => permission.startsWith(`${group.prefix}:`));
    for (const item of items) used.add(item);
    return { label: group.label, items: [...items] };
  }).filter((group) => group.items.length > 0);
  const rest = PERMISSIONS.filter((permission) => !used.has(permission));
  if (rest.length > 0) groups.push({ label: 'Other', items: [...rest] });
  return groups;
}

export function SettingsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Organization settings"
        description="Roles, the people who hold them, and the relationships the attack-path graph walks."
        actions={
          <Button
            variant="secondary"
            onClick={() => {
              window.dispatchEvent(new CustomEvent('seap:start-tour'));
            }}
          >
            Restart platform tour
          </Button>
        }
      />
      <RolesPanel />
      <MembersPanel />
      <Panel title="Relationship" tip="Connect assets so attack paths can walk from exposure to sensitive systems.">
        <RelationshipForm />
      </Panel>
    </div>
  );
}

function MembersPanel() {
  const { user: session } = useAuth();
  const client = useQueryClient();
  const users = useQuery({ queryKey: ['users'], queryFn: () => api.get<Member[]>('/api/users') });
  const roles = useQuery({ queryKey: ['roles'], queryFn: () => api.get<{ data: RoleRecord[] }>('/api/roles') });
  const [form, setForm] = useState({ name: '', email: '', password: 'ChangeThis-Analyst-1!', role: 'SECURITY_ANALYST' });
  const [pendingRole, setPendingRole] = useState<Record<string, string>>({});
  const [rowError, setRowError] = useState<string | null>(null);
  const options = roles.data?.data ?? [];
  const create = useMutation({
    mutationFn: () => api.post('/api/users', form),
    onSuccess: () => {
      setForm((current) => ({ ...current, name: '', email: '' }));
      void client.invalidateQueries({ queryKey: ['users'] });
      void client.invalidateQueries({ queryKey: ['roles'] });
    },
  });
  const updateRole = useMutation({
    mutationFn: ({ id, role }: { id: string; role: string }) => api.patch(`/api/users/${id}`, { role }),
    onSuccess: () => {
      setRowError(null);
      void client.invalidateQueries({ queryKey: ['users'] });
      void client.invalidateQueries({ queryKey: ['roles'] });
    },
    onError: (error) => setRowError((error as Error).message),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/users/${id}`),
    onSuccess: () => {
      setRowError(null);
      void client.invalidateQueries({ queryKey: ['users'] });
      void client.invalidateQueries({ queryKey: ['roles'] });
    },
    onError: (error) => setRowError((error as Error).message),
  });

  return (
      <Panel title="Members" tip="People in this organization. Change their role inline or remove membership.">
      <form className="mb-4 grid gap-3 border-b border-line pb-4 md:grid-cols-2 xl:grid-cols-4" onSubmit={(event) => { event.preventDefault(); create.mutate(); }}>
        <Field label="Name"><input className={inputClass} value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} required /></Field>
        <Field label="Email"><input className={inputClass} type="email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} required /></Field>
        <Field label="Temporary password"><input className={inputClass} value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} required /></Field>
        <Field label="Role">
          <select className={inputClass} value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })}>
            {(options.length > 0 ? options : [{ id: 'SECURITY_ANALYST', name: 'SECURITY_ANALYST' }]).map((role) => (
              <option key={role.id} value={role.id}>{roleLabel(role.name)}</option>
            ))}
          </select>
        </Field>
        <div className="flex items-end justify-end md:col-span-2 xl:col-span-4">
          <Tooltip content="Create the account if needed and add them to this organization">
            <Button type="submit" loading={create.isPending}>Add member</Button>
          </Tooltip>
        </div>
      </form>
      {create.isError ? <p className="mb-3 text-sm text-rose-500">{(create.error as Error).message}</p> : null}
      {rowError ? <p className="mb-3 text-sm text-rose-500">{rowError}</p> : null}
      {users.isLoading ? <PageLoading label="Loading members" /> : (users.data?.length ?? 0) === 0 ? <Empty title="No members" body="Add a person above and give them a role." /> : (
        <Table headers={['Name', 'Email', 'Role', 'Last sign-in', '']}>
          {users.data?.map((member) => (
            <tr key={member.id} className="border-t border-line align-middle">
              <td className="px-3 py-2.5 font-medium">{member.name}</td>
              <td className="px-3 py-2.5 text-mute">{member.email}</td>
              <td className="px-3 py-2.5">
                <select
                  className={inputClass}
                  aria-label={`Role for ${member.name}`}
                  value={pendingRole[member.id] ?? member.roleKey}
                  disabled={updateRole.isPending && pendingRole[member.id] !== undefined}
                  onChange={(event) => {
                    const role = event.target.value;
                    setPendingRole((current) => ({ ...current, [member.id]: role }));
                    updateRole.mutate({ id: member.id, role }, {
                      onSettled: () => setPendingRole((current) => {
                        const next = { ...current };
                        delete next[member.id];
                        return next;
                      }),
                    });
                  }}
                >
                  {options.map((role) => <option key={role.id} value={role.id}>{roleLabel(role.name)}</option>)}
                  {options.length === 0 ? <option value={member.roleKey}>{roleLabel(member.role)}</option> : null}
                </select>
              </td>
              <td className="whitespace-nowrap px-3 py-2.5 text-mute">{member.lastLoginAt ? new Date(member.lastLoginAt).toLocaleString() : 'Never'}</td>
              <td className="px-3 py-2.5 text-right">
                <Button
                  variant="secondary"
                  disabled={member.id === session?.id}
                  loading={remove.isPending && remove.variables === member.id}
                  onClick={() => {
                    if (window.confirm(`Remove ${member.name} from the organization?`)) remove.mutate(member.id);
                  }}
                >
                  Remove
                </Button>
              </td>
            </tr>
          ))}
        </Table>
      )}
    </Panel>
  );
}

const emptyRole = { name: '', description: '', permissions: ['dashboard:read', 'asset:read', 'finding:read'] };

function RolesPanel() {
  const client = useQueryClient();
  const roles = useQuery({ queryKey: ['roles'], queryFn: () => api.get<{ data: RoleRecord[] }>('/api/roles') });
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<RoleRecord | null>(null);
  const [form, setForm] = useState(emptyRole);
  const open = creating || editing !== null;
  const save = useMutation({
    mutationFn: () => editing
      ? api.patch(`/api/roles/${editing.id}`, { name: form.name, description: form.description, permissions: form.permissions })
      : api.post('/api/roles', form),
    onSuccess: () => {
      setCreating(false);
      setEditing(null);
      setForm(emptyRole);
      void client.invalidateQueries({ queryKey: ['roles'] });
      void client.invalidateQueries({ queryKey: ['users'] });
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/api/roles/${id}`),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['roles'] });
    },
  });

  function beginEdit(role: RoleRecord) {
    setCreating(false);
    setEditing(role);
    setForm({ name: role.name, description: role.description, permissions: [...role.permissions] });
  }

  function cancel() {
    setCreating(false);
    setEditing(null);
    setForm(emptyRole);
  }

  return (
    <Panel
      title="Roles"
      tip="Built-in roles keep fixed names. Custom roles can be created, edited, and deleted when unused."
      action={!open ? (
        <Tooltip content="Create a custom role with a selected permission set">
          <Button onClick={() => { setEditing(null); setForm(emptyRole); setCreating(true); }}>New role</Button>
        </Tooltip>
      ) : undefined}
    >
      <p className="mb-4 text-sm text-mute">Built-in roles keep their names. Custom roles can be renamed, given a permission set, and deleted after members move off them.</p>
      {open ? (
        <form className="mb-4 space-y-4 rounded-md border border-line p-3" onSubmit={(event) => { event.preventDefault(); save.mutate(); }}>
          <div className="grid gap-3 md:grid-cols-2">
            <Field label="Name">
              <input className={inputClass} value={form.name} disabled={editing?.system} onChange={(event) => setForm({ ...form, name: event.target.value })} required />
            </Field>
            <Field label="Description">
              <input className={inputClass} value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} />
            </Field>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {permissionGroups().map((group) => (
              <fieldset key={group.label}>
                <legend className="mb-2 text-xs font-medium uppercase tracking-wide text-mute">{group.label}</legend>
                <div className="space-y-1.5">
                  {group.items.map((permission) => (
                    <label key={permission} className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={form.permissions.includes(permission)}
                        onChange={() => setForm((current) => ({
                          ...current,
                          permissions: current.permissions.includes(permission)
                            ? current.permissions.filter((item) => item !== permission)
                            : [...current.permissions, permission],
                        }))}
                      />
                      <span className="font-mono text-xs">{permission}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
            ))}
          </div>
          {save.isError ? <p className="text-sm text-rose-500">{(save.error as Error).message}</p> : null}
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={cancel}>Cancel</Button>
            <Button type="submit" loading={save.isPending} disabled={form.permissions.length === 0 || form.name.trim().length < 2}>
              {editing ? 'Save role' : 'Create role'}
            </Button>
          </div>
        </form>
      ) : null}
      {roles.isLoading ? <PageLoading label="Loading roles" /> : (
        <Table headers={['Role', 'Type', 'Members', 'Permissions', '']}>
          {roles.data?.data.map((role) => (
            <tr key={role.id} className="border-t border-line align-top">
              <td className="px-3 py-2.5">
                <p className="font-medium">{roleLabel(role.name)}</p>
                {role.description ? <p className="mt-0.5 max-w-md text-xs text-mute">{role.description}</p> : null}
              </td>
              <td className="px-3 py-2.5 text-mute">{role.system ? 'Built-in' : 'Custom'}</td>
              <td className="px-3 py-2.5">{role.members}</td>
              <td className="px-3 py-2.5 text-mute">{role.permissions.length}</td>
              <td className="px-3 py-2.5">
                <div className="flex justify-end gap-2">
                  <Button variant="secondary" onClick={() => beginEdit(role)}>Edit</Button>
                  {role.system ? null : (
                    <Button
                      variant="danger"
                      disabled={role.members > 0}
                      loading={remove.isPending && remove.variables === role.id}
                      onClick={() => {
                        if (window.confirm(`Delete the ${role.name} role?`)) remove.mutate(role.id);
                      }}
                    >
                      Delete
                    </Button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </Table>
      )}
      {remove.isError ? <p className="mt-3 text-sm text-rose-500">{(remove.error as Error).message}</p> : null}
    </Panel>
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
        <Tooltip content="Save a relationship the attack-path graph can walk">
          <Button type="submit" loading={connect.isPending}>Connect assets</Button>
        </Tooltip>
      </div>
      {connect.isError && <p className="text-sm text-rose-500 md:col-span-3">{(connect.error as Error).message}</p>}
      {connect.isSuccess && <p className="text-sm text-mute md:col-span-3">Relationship saved.</p>}
    </form>
  );
}

export function HomeLink() {
  return <Link to="/dashboard">Dashboard</Link>;
}
