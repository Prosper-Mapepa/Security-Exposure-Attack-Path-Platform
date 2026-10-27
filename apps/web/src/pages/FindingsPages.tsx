import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronRight } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Button, Empty, PageHeader, PageLoading, Panel, Severity, Table, Tooltip, inputClass } from '../components/ui';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';

interface FindingRow {
  id: string;
  title: string;
  severity: string;
  status: string;
  riskScore: number;
  cve?: string | null;
  asset: { id: string; name: string };
  findings: Array<{ source: string; scan: { id: string; name: string; createdAt: string } | null }>;
}

function groupsFor(rows: FindingRow[]) {
  const groups = new Map<string, { id: string | null; name: string; createdAt: string; rows: FindingRow[] }>();
  for (const row of rows) {
    const scans = [...new Map(row.findings.flatMap((item) => (item.scan ? [[item.scan.id, item.scan] as const] : []))).values()];
    const buckets = scans.length > 0 ? scans : [{ id: '', name: 'Not linked to a scan', createdAt: '' }];
    for (const scan of buckets) {
      const key = scan.id || 'none';
      const group = groups.get(key) ?? { id: scan.id || null, name: scan.name, createdAt: scan.createdAt, rows: [] };
      group.rows.push(row);
      groups.set(key, group);
    }
  }
  return [...groups.values()].sort((left, right) => right.createdAt.localeCompare(left.createdAt));
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function summarize(rows: FindingRow[], scanId: string | null) {
  const counts = new Map<string, number>();
  for (const row of rows) counts.set(row.severity, (counts.get(row.severity) ?? 0) + 1);
  const assets = [...new Set(rows.map((row) => row.asset.name))];
  const sources = [...new Set(rows.flatMap((row) => row.findings.filter((item) => (item.scan?.id ?? null) === scanId).map((item) => item.source)))];
  const open = rows.filter((row) => row.status === 'OPEN').length;
  const highest = rows.reduce((max, row) => Math.max(max, row.riskScore), 0);
  const breakdown = SEVERITY_ORDER.filter((level) => counts.has(level)).map((level) => `${counts.get(level)} ${level.toLowerCase()}`);
  const assetLabel = assets.length === 1 ? assets[0] : `${assets.length} assets`;
  return {
    counts: SEVERITY_ORDER.filter((level) => counts.has(level)).map((level) => ({ level, count: counts.get(level) ?? 0 })),
    text: `${rows.length} finding${rows.length === 1 ? '' : 's'} on ${assetLabel}: ${breakdown.join(', ')}. ${open} open. Highest risk ${highest}. ${sources.join(', ')}.`,
  };
}

function ScanGroup({ group, open, onToggle }: { group: ReturnType<typeof groupsFor>[number]; open: boolean; onToggle: () => void }) {
  const summary = summarize(group.rows, group.id);
  const panelId = `scan-${group.id ?? 'none'}`;
  return (
    <section className="rounded-lg border border-line bg-panel">
      <div className="flex items-start gap-2 p-4">
        <button
          type="button"
          className="flex min-w-0 flex-1 items-start gap-2 text-left"
          aria-expanded={open}
          aria-controls={panelId}
          onClick={onToggle}
        >
          <ChevronRight className={`mt-0.5 h-4 w-4 shrink-0 text-mute transition-transform ${open ? 'rotate-90' : ''}`} aria-hidden="true" />
          <span className="min-w-0">
            <span className="block text-sm font-semibold">{group.name}</span>
            <span className="mt-1 block text-sm text-mute">{summary.text}</span>
            <span className="mt-2 flex flex-wrap gap-2">
              {summary.counts.map((item) => (
                <span key={item.level} className="inline-flex items-center gap-1.5">
                  <Severity value={item.level} />
                  <span className="font-mono text-xs">{item.count}</span>
                </span>
              ))}
            </span>
          </span>
        </button>
        {group.id ? <Link className="shrink-0 text-sm text-accent" to={`/scans/${group.id}`}>View scan</Link> : null}
      </div>
      {open ? (
        <div id={panelId} className="border-t border-line px-4 pb-4">
          <Table headers={['Title', 'Asset', 'Severity', 'Risk', 'Status', 'Source']}>
            {group.rows.map((finding) => (
              <tr key={finding.id} className="border-t border-line hover:bg-ink/70">
                <td className="px-3 py-2.5"><Link className="font-medium text-accent" to={`/findings/${finding.id}`}>{finding.title}</Link></td>
                <td className="px-3 py-2.5">{finding.asset.name}</td>
                <td className="px-3 py-2.5"><Severity value={finding.severity} /></td>
                <td className="px-3 py-2.5 font-mono">{finding.riskScore}</td>
                <td className="px-3 py-2.5">{finding.status}</td>
                <td className="px-3 py-2.5">{[...new Set(finding.findings.map((item) => item.source))].join(', ')}</td>
              </tr>
            ))}
          </Table>
        </div>
      ) : null}
    </section>
  );
}

export function FindingsPage() {
  const [severity, setSeverity] = useState('');
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const query = useQuery({
    queryKey: ['findings', severity],
    queryFn: async () => {
      const pageSize = 100;
      const severityQuery = severity ? `&severity=${severity}` : '';
      const first = await api.get<{ data: FindingRow[]; total: number }>(`/api/findings?page=1&pageSize=${pageSize}${severityQuery}`);
      const pageCount = Math.ceil(first.total / pageSize);
      if (pageCount <= 1) return first;
      const rest = await Promise.all(
        Array.from({ length: pageCount - 1 }, (_, index) => api.get<{ data: FindingRow[] }>(`/api/findings?page=${index + 2}&pageSize=${pageSize}${severityQuery}`)),
      );
      return { data: first.data.concat(...rest.map((page) => page.data)), total: first.total };
    },
  });
  const groups = groupsFor(query.data?.data ?? []);
  return (
    <div className="space-y-6">
      <PageHeader
        title="Vulnerabilities"
        description="Findings grouped by the scan that reported them. Open a scan to see each result."
        actions={(
          <select aria-label="Severity filter" className={inputClass + ' w-44'} value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">All severities</option>
            {SEVERITY_ORDER.map((item) => <option key={item}>{item}</option>)}
          </select>
        )}
      />
      {query.isLoading ? <PageLoading label="Loading findings" /> : groups.length === 0 ? <Empty title="No findings" body="Normalized scanner results will appear here." /> : groups.map((group) => {
        const key = group.id ?? 'none';
        const expanded = open[key] ?? false;
        return (
          <ScanGroup
            key={key}
            group={group}
            open={expanded}
            onToggle={() => setOpen((current) => ({ ...current, [key]: !expanded }))}
          />
        );
      })}
    </div>
  );
}

export function FindingDetailPage() {
  const { id = '' } = useParams();
  const client = useQueryClient();
  const query = useQuery({
    queryKey: ['finding', id],
    queryFn: () => api.get<{
      vulnerability: {
        title: string; severity: string; riskScore: number; riskRating: string; cve?: string | null; cwe?: string | null; cvss?: number | null;
        status: string; firstSeen: string; lastSeen: string; description: string; component?: string | null;
        riskExplanation?: { summary?: string; factors?: Array<{ label: string; contribution: number; reason: string }> };
        asset: { name: string };
        findings: Array<{ source: string; location?: string | null; remediationGuidance?: string | null; evidence: Array<{ redacted: string }> }>;
        remediations: Array<{ id: string; status: string; dueAt?: string | null; assignee?: { id: string; name: string } | null; tasks: Array<{ id: string; title: string; status: string }> }>;
        validations: Array<{ id: string; outcome: string; summary?: string | null; createdAt: string; scan?: { id: string; status: string; name: string } | null }>;
      };
      attackPaths: Array<{ id: string; title: string }>;
      audit: Array<{ id: string; action: string; resource: string; createdAt: string; userName?: string | null }>;
      securePattern: { vulnerable: string; secure: string } | null;
    }>(`/api/vulnerabilities/${id}`),
    refetchInterval: (current) => (current.state.data?.vulnerability.validations.some((run) => run.outcome === 'PENDING') ? 3000 : false),
  });
  const [assignee, setAssignee] = useState('');
  const { user } = useAuth();
  const users = useQuery({ queryKey: ['users'], queryFn: () => api.get<Array<{ id: string; name: string; email: string }>>('/api/users') });
  const people = [
    ...(user && !(users.data ?? []).some((member) => member.id === user.id) ? [{ id: user.id, name: user.name, email: user.email }] : []),
    ...(users.data ?? []),
  ];
  useEffect(() => {
    if (assignee) return;
    const current = query.data?.vulnerability.remediations.find((item) => item.status !== 'CLOSED' && item.status !== 'VALIDATED');
    if (current?.assignee?.id) setAssignee(current.assignee.id);
    else if (user) setAssignee(user.id);
  }, [assignee, query.data, user]);
  const validate = useMutation({ mutationFn: () => api.post(`/api/vulnerabilities/${id}/validate`), onSuccess: () => void client.invalidateQueries({ queryKey: ['finding', id] }) });
  const mitigate = useMutation({
    mutationFn: () => api.patch(`/api/vulnerabilities/${id}/status`, { status: 'MITIGATED', note: 'Marked mitigated from finding detail' }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['finding', id] });
      void client.invalidateQueries({ queryKey: ['findings'] });
      void client.invalidateQueries({ queryKey: ['dashboard'] });
      void client.invalidateQueries({ queryKey: ['remediations'] });
    },
  });
  const remediate = useMutation({
    mutationFn: () => api.post('/api/remediations', {
      vulnerabilityId: id,
      assigneeId: assignee || undefined,
      ...(query.data?.vulnerability.remediations.length ? {} : { taskTitle: 'Remediate finding' }),
    }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['finding', id] });
      void client.invalidateQueries({ queryKey: ['remediations'] });
    },
  });
  if (query.isLoading) return <PageLoading label="Loading finding" />;
  if (!query.data) return <p>Finding was not found.</p>;
  const item = query.data.vulnerability;
  return (
    <div className="space-y-6">
      <PageHeader
        title={item.title}
        description={`${item.asset.name} · risk ${item.riskScore} · ${item.riskRating}`}
        actions={<Severity value={item.severity} />}
      />
      <Panel title="Record">
        <dl className="grid gap-2 text-sm md:grid-cols-2">
          <div>CVE<div>{item.cve || 'None'}</div></div>
          <div>CWE<div>{item.cwe || 'None'}</div></div>
          <div>CVSS<div>{item.cvss ?? 'n/a'}</div></div>
          <div>Asset<div>{item.asset.name}</div></div>
          <div>Component<div>{item.component || 'n/a'}</div></div>
          <div>Status<div>{item.status}</div></div>
          <div>First seen<div>{new Date(item.firstSeen).toLocaleString()}</div></div>
          <div>Last seen<div>{new Date(item.lastSeen).toLocaleString()}</div></div>
        </dl>
        <p className="mt-3 text-sm">{item.description}</p>
      </Panel>
      <Panel title="Why this score" tip="Each factor contributes to the 0–100 risk score shown above.">
        <p className="text-sm">{item.riskExplanation?.summary}</p>
        <ul className="mt-3 space-y-2 text-sm">
          {item.riskExplanation?.factors?.map((factor) => (
            <li key={factor.label} className="flex justify-between gap-4 border-t border-line py-2"><span>{factor.label}: {factor.reason}</span><span className="font-mono">{factor.contribution}</span></li>
          ))}
        </ul>
      </Panel>
      <Panel title="Evidence">
        {item.findings.map((finding, index) => (
          <div key={index} className="border-t border-line py-2 text-sm">
            <p>{finding.source} · {finding.location}</p>
            <pre className="mt-1 overflow-x-auto font-mono text-xs">{finding.evidence.map((entry) => entry.redacted).join('\n')}</pre>
            {finding.remediationGuidance && <p className="mt-1">{finding.remediationGuidance}</p>}
          </div>
        ))}
      </Panel>
      {query.data.securePattern && (
        <Panel title="Secure pattern">
          <p className="text-sm">Current issue: {query.data.securePattern.vulnerable}</p>
          <p className="mt-2 text-sm">Recommended: {query.data.securePattern.secure}</p>
        </Panel>
      )}
      <Panel title="Attack paths">
        {query.data.attackPaths.length === 0 ? <Empty title="Not on an attack path" body="Rebuild attack paths after modeling relationships." /> : query.data.attackPaths.map((path) => <p key={path.id}>{path.title}</p>)}
      </Panel>
      <Panel title="Remediation" tip="Assign ownership, validate the fix with a scan, or mark the finding mitigated.">
        {item.remediations.length === 0 ? <p className="mb-3 text-sm text-mute">No one is assigned yet.</p> : (
          <ul className="mb-3 space-y-2 text-sm">
            {item.remediations.map((remediation) => (
              <li key={remediation.id} className="border-t border-line pt-2 first:border-t-0 first:pt-0">
                <p>{remediation.status}{remediation.assignee ? ` · ${remediation.assignee.name}` : ''}{remediation.dueAt ? ` · due ${new Date(remediation.dueAt).toLocaleDateString()}` : ''}</p>
                {remediation.tasks.map((task) => <p key={task.id} className="text-mute">{task.title} · {task.status}</p>)}
              </li>
            ))}
          </ul>
        )}
        <div className="flex flex-wrap gap-2">
          <select aria-label="Assignee" className={inputClass + ' max-w-xs'} value={assignee} onChange={(event) => setAssignee(event.target.value)}>
            <option value="">Unassigned</option>
            {people.map((person) => <option key={person.id} value={person.id}>{person.name}</option>)}
          </select>
          <Tooltip content="Assign or update the engineer responsible for this finding">
            <Button loading={remediate.isPending} onClick={() => remediate.mutate()}>{item.remediations.length ? 'Update assignment' : 'Assign remediation'}</Button>
          </Tooltip>
          <Tooltip content="Re-run the original scanner. The finding resolves only if it is no longer reported.">
            <Button variant="secondary" loading={validate.isPending} onClick={() => validate.mutate()}>Validate fix</Button>
          </Tooltip>
          {item.status !== 'MITIGATED' && item.status !== 'RESOLVED' ? (
            <Tooltip content="Record that the risk is mitigated. This feeds mean time to remediate.">
              <Button variant="secondary" loading={mitigate.isPending} onClick={() => mitigate.mutate()}>Mark mitigated</Button>
            </Tooltip>
          ) : null}
        </div>
        {remediate.isSuccess && <p className="mt-2 text-sm text-mute">Assignment saved.</p>}
        {mitigate.isSuccess && <p className="mt-2 text-sm text-mute">Finding marked mitigated. Mean time to remediate uses this timestamp.</p>}
        {(validate.error || remediate.error || mitigate.error) && <p className="mt-2 text-sm text-rose-500">{((validate.error || remediate.error || mitigate.error) as Error).message}</p>}
      </Panel>
      <Panel title="Validation history" tip="Each validation scan and whether the finding was still present.">
        {item.validations.length === 0 ? <p className="text-sm text-mute">No validation runs. Validate fix queues a scan of the original target.</p> : item.validations.map((run) => (
          <div key={run.id} className="border-t border-line py-2 text-sm first:border-t-0 first:pt-0">
            <p>{new Date(run.createdAt).toLocaleString()} · {run.outcome}</p>
            <p className="text-mute">{run.summary}</p>
            {run.scan ? <Link className="text-accent" to={`/scans/${run.scan.id}`}>{run.scan.name} · {run.scan.status}</Link> : null}
          </div>
        ))}
      </Panel>
      <Panel title="Audit history" tip="Who changed this finding, its remediations, and related validation scans.">
        {query.data.audit.length === 0 ? <p className="text-sm text-mute">No audit history yet. Assigning remediation or validating a fix is recorded here.</p> : query.data.audit.map((entry) => (
          <p key={entry.id} className="border-t border-line py-2 text-sm first:border-t-0 first:pt-0">
            {new Date(entry.createdAt).toLocaleString()} · {entry.userName ?? 'System'} · {entry.action} · {entry.resource}
          </p>
        ))}
      </Panel>
    </div>
  );
}

export function DeveloperPage() {
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const query = useQuery({
    queryKey: ['mine'],
    queryFn: () => api.get<Array<{ id: string; title: string; severity: string; riskScore: number; status: string; description: string; asset: { id: string; name: string }; findings: Array<{ remediationGuidance?: string | null; location?: string | null }> }>>('/api/me/findings'),
  });
  const groups = new Map<string, { id: string; name: string; rows: NonNullable<typeof query.data> }>();
  for (const finding of query.data ?? []) {
    const group = groups.get(finding.asset.id) ?? { id: finding.asset.id, name: finding.asset.name, rows: [] };
    group.rows.push(finding);
    groups.set(finding.asset.id, group);
  }
  const projects = [...groups.values()].sort((left, right) => Math.max(...right.rows.map((row) => row.riskScore)) - Math.max(...left.rows.map((row) => row.riskScore)));
  return (
    <div className="space-y-6">
      <PageHeader title="My security findings" description="Findings grouped by the project you own." />
      {query.isLoading ? <PageLoading label="Loading findings" /> : projects.length === 0 ? <Empty title="No findings assigned to you" body="Findings on assets you own, or remediations assigned to you, show up here." /> : projects.map((project, index) => {
        const counts = new Map<string, number>();
        for (const row of project.rows) counts.set(row.severity, (counts.get(row.severity) ?? 0) + 1);
        const breakdown = SEVERITY_ORDER.filter((level) => counts.has(level));
        const highest = project.rows.reduce((max, row) => Math.max(max, row.riskScore), 0);
        const summary = {
          counts: breakdown.map((level) => ({ level, count: counts.get(level) ?? 0 })),
          text: `${project.rows.length} finding${project.rows.length === 1 ? '' : 's'}: ${breakdown.map((level) => `${counts.get(level)} ${level.toLowerCase()}`).join(', ')}. Highest risk ${highest}.`,
        };
        const expanded = project.id in open ? open[project.id] : index === 0;
        return (
          <section key={project.id} className="rounded-lg border border-line bg-panel">
            <button
              type="button"
              className="flex w-full items-start gap-2 p-4 text-left"
              aria-expanded={expanded}
              onClick={() => setOpen((current) => ({ ...current, [project.id]: !expanded }))}
            >
              <ChevronRight className={`mt-0.5 h-4 w-4 shrink-0 text-mute transition-transform ${expanded ? 'rotate-90' : ''}`} aria-hidden="true" />
              <span className="min-w-0">
                <span className="block text-sm font-semibold">{project.name}</span>
                <span className="mt-1 block text-sm text-mute">{summary.text}</span>
                <span className="mt-2 flex flex-wrap gap-2">
                  {summary.counts.map((item) => (
                    <span key={item.level} className="inline-flex items-center gap-1.5">
                      <Severity value={item.level} />
                      <span className="font-mono text-xs">{item.count}</span>
                    </span>
                  ))}
                </span>
              </span>
            </button>
            {expanded ? (
              <div className="divide-y divide-line border-t border-line px-4">
                {project.rows.map((finding) => (
                  <div key={finding.id} className="py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link className="font-medium text-accent" to={`/findings/${finding.id}`}>{finding.title}</Link>
                      <Severity value={finding.severity} />
                      <span className="font-mono text-xs">{finding.riskScore}</span>
                      <span className="text-xs text-mute">{finding.status}</span>
                    </div>
                    <p className="mt-1 text-sm text-mute">{finding.findings[0]?.location}</p>
                    {finding.findings[0]?.remediationGuidance ? <p className="mt-1 text-sm">{finding.findings[0].remediationGuidance}</p> : null}
                  </div>
                ))}
              </div>
            ) : null}
          </section>
        );
      })}
    </div>
  );
}
