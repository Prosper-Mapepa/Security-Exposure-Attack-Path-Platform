import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Button, Empty, PageHeader, PageLoading, Panel, Severity, Table, inputClass } from '../components/ui';
import { api } from '../lib/api';

interface FindingRow {
  id: string;
  title: string;
  severity: string;
  status: string;
  riskScore: number;
  cve?: string | null;
  asset: { id: string; name: string };
  findings: Array<{ source: string }>;
}

export function FindingsPage() {
  const [severity, setSeverity] = useState('');
  const query = useQuery({
    queryKey: ['findings', severity],
    queryFn: () => api.get<{ data: FindingRow[] }>(`/api/findings?page=1&pageSize=50${severity ? `&severity=${severity}` : ''}`),
  });
  return (
    <div className="space-y-6">
      <PageHeader
        title="Vulnerabilities"
        description="Deduplicated findings scored with the asset's business context."
        actions={(
          <select aria-label="Severity filter" className={inputClass + ' w-44'} value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">All severities</option>
            {['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map((item) => <option key={item}>{item}</option>)}
          </select>
        )}
      />
      {query.isLoading ? <PageLoading label="Loading findings" /> : (query.data?.data.length ?? 0) === 0 ? <Empty title="No findings" body="Normalized scanner results will appear here." /> : (
        <Panel>
          <Table headers={['Title', 'Asset', 'Severity', 'Risk', 'Status', 'Source']}>
            {query.data?.data.map((finding) => (
              <tr key={finding.id} className="border-t border-line hover:bg-ink/70">
                <td className="px-3 py-2.5"><Link className="font-medium text-accent" to={`/findings/${finding.id}`}>{finding.title}</Link></td>
                <td className="px-3 py-2.5">{finding.asset.name}</td>
                <td className="px-3 py-2.5"><Severity value={finding.severity} /></td>
                <td className="px-3 py-2.5 font-mono">{finding.riskScore}</td>
                <td className="px-3 py-2.5">{finding.status}</td>
                <td className="px-3 py-2.5">{finding.findings.map((item) => item.source).join(', ')}</td>
              </tr>
            ))}
          </Table>
        </Panel>
      )}
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
        remediations: Array<{ id: string; status: string }>;
        validations: Array<{ outcome: string; summary?: string | null; createdAt: string }>;
      };
      attackPaths: Array<{ id: string; title: string }>;
      audit: Array<{ id: string; action: string; createdAt: string }>;
      securePattern: { vulnerable: string; secure: string } | null;
    }>(`/api/vulnerabilities/${id}`),
  });
  const [assignee, setAssignee] = useState('');
  const validate = useMutation({ mutationFn: () => api.post(`/api/vulnerabilities/${id}/validate`), onSuccess: () => void client.invalidateQueries({ queryKey: ['finding', id] }) });
  const remediate = useMutation({
    mutationFn: () => api.post('/api/remediations', { vulnerabilityId: id, assigneeId: assignee || undefined, taskTitle: 'Remediate finding' }),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['finding', id] }),
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
      <Panel title="Why this score">
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
      <Panel title="Remediation">
        <div className="flex flex-wrap gap-2">
          <input className={inputClass + ' max-w-xs'} placeholder="Assignee user id" value={assignee} onChange={(event) => setAssignee(event.target.value)} />
          <Button loading={remediate.isPending} onClick={() => remediate.mutate()}>Assign remediation</Button>
          <Button variant="secondary" loading={validate.isPending} onClick={() => validate.mutate()}>Validate fix</Button>
        </div>
        {(validate.error || remediate.error) && <p className="mt-2 text-sm text-rose-500">{((validate.error || remediate.error) as Error).message}</p>}
      </Panel>
      <Panel title="Validation history">
        {item.validations.length === 0 ? <p className="text-sm text-mute">No validation runs.</p> : item.validations.map((run) => <p key={run.createdAt} className="text-sm">{run.outcome}: {run.summary}</p>)}
      </Panel>
      <Panel title="Audit history">
        {query.data.audit.map((entry) => <p key={entry.id} className="text-sm">{new Date(entry.createdAt).toLocaleString()} · {entry.action}</p>)}
      </Panel>
    </div>
  );
}

export function DeveloperPage() {
  const query = useQuery({
    queryKey: ['mine'],
    queryFn: () => api.get<Array<{ id: string; title: string; severity: string; riskScore: number; description: string; asset: { name: string }; findings: Array<{ remediationGuidance?: string | null; location?: string | null }> }>>('/api/me/findings'),
  });
  return (
    <div className="space-y-6">
      <PageHeader title="My security findings" description="Findings on assets you own, and remediations assigned to you." />
      {query.isLoading ? <PageLoading label="Loading findings" /> : (query.data?.length ?? 0) === 0 ? <Empty title="No findings assigned to you" body="Findings on assets you own, or remediations assigned to you, show up here." /> : query.data?.map((finding) => (
        <Panel key={finding.id} title={finding.asset.name}>
          <div className="flex items-center gap-2"><Link className="font-medium text-accent" to={`/findings/${finding.id}`}>{finding.title}</Link><Severity value={finding.severity} /></div>
          <p className="mt-2 text-sm">{finding.description}</p>
          <p className="mt-2 text-sm text-mute">{finding.findings[0]?.location}</p>
          <p className="mt-2 text-sm">{finding.findings[0]?.remediationGuidance}</p>
        </Panel>
      ))}
    </div>
  );
}
