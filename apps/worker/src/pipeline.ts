import { discoverAttackPaths, type GraphEdgeInput, type GraphNodeInput } from '@seap/attack-path-engine';
import { prisma, type AssetType, type EdgeType, type NodeKind, type Prisma } from '@seap/db';
import { createEmailAdapter } from '@seap/integrations';
import { calculateRisk, type RiskInput } from '@seap/risk-engine';
import { bindFindingToAsset, createScanner, runCommand, type NormalizedFinding } from '@seap/scanner-adapters';
import { assertSafeScanUrl, isPathInsideAllowlist, maskSecrets, resolveScanAllowlist } from '@seap/security';
import { DEFAULT_RISK_WEIGHTS, explainPolicyViolation, type RiskWeights } from '@seap/shared';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import Redis from 'ioredis';

const OPEN = ['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'REOPENED'] as const;
const SEVERITY_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 } as const;
const PRIVILEGE_EDGES = new Set<EdgeType>(['CAN_ACCESS', 'ASSUMES_ROLE', 'AUTHENTICATES_TO', 'CONNECTS_TO', 'DEPENDS_ON']);

function log(event: string, fields: Record<string, unknown>) {
  console.info(JSON.stringify({ time: new Date().toISOString(), service: 'worker', level: 'info', event, ...fields }));
}

async function scanLog(scanId: string, level: string, message: string) {
  await prisma.scanLog.create({ data: { scanId, level, message: maskSecrets(message).slice(0, 2000) } });
}

async function publish(payload: Record<string, unknown>) {
  const redis = new Redis(process.env.REDIS_URL ?? 'redis://localhost:6379', { maxRetriesPerRequest: 1 });
  await redis.publish('scan.progress', JSON.stringify(payload));
  await redis.quit();
}

export async function executeScan(scanId: string): Promise<void> {
  const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { targets: true, asset: true } });
  if (!scan) return;
  if (scan.cancelRequested) {
    await prisma.scan.update({ where: { id: scanId }, data: { status: 'CANCELLED', finishedAt: new Date() } });
    return;
  }
  const target = scan.targets[0];
  if (!target) throw new Error('Scan target missing');
  const workdir = path.join(path.resolve(process.env.SCAN_WORKDIR ?? './scan-data'), scan.organizationId, scan.id);
  await mkdir(workdir, { recursive: true });
  await prisma.scan.update({ where: { id: scanId }, data: { status: 'RUNNING', startedAt: new Date(), progress: 10 } });
  await publish({ organizationId: scan.organizationId, scanId, status: 'RUNNING', progress: 10 });
  const abort = new AbortController();
  const watcher = setInterval(() => {
    void prisma.scan.findUnique({ where: { id: scanId }, select: { cancelRequested: true } }).then((current) => {
      if (current?.cancelRequested) abort.abort();
    });
  }, 2000);
  try {
    const location = await prepareLocation(target.targetType, target.location, workdir, abort.signal);
    await scanLog(scanId, 'info', `Running ${scan.scanner} against ${target.targetType} target`);
    await prisma.scan.update({ where: { id: scanId }, data: { progress: 35 } });
    const adapter = createScanner(scan.scanner);
    const raw = await adapter.scan({ scanId, targetType: target.targetType, location, workdir, signal: abort.signal });
    if (abort.signal.aborted) {
      await prisma.scan.update({ where: { id: scanId }, data: { status: 'CANCELLED', finishedAt: new Date(), progress: 100 } });
      return;
    }
    const normalized = adapter.parseResults(raw).map((finding) => bindFindingToAsset(finding, scan.assetId));
    await scanLog(scanId, 'info', `Parsed ${normalized.length} findings`);
    await ingestFindings(scan.organizationId, scan.assetId, scan.id, normalized);
    await prisma.scanResult.upsert({
      where: { scanId },
      create: { scanId, findingCount: normalized.length, summary: { findingCount: normalized.length, scanner: scan.scanner } },
      update: { findingCount: normalized.length, summary: { findingCount: normalized.length, scanner: scan.scanner } },
    });
    await finalizeValidation(scan.organizationId, scan.validationVulnerabilityId, scan.id, normalized);
    await rebuildGraph(scan.organizationId);
    await prisma.scan.update({ where: { id: scanId }, data: { status: 'COMPLETED', progress: 100, finishedAt: new Date() } });
    await publish({ organizationId: scan.organizationId, scanId, status: 'COMPLETED', progress: 100 });
    await notify(scan.organizationId, null, 'scan.completed', 'Scan completed', `${scan.name} finished with ${normalized.length} findings`);
    await prisma.auditLog.create({
      data: { organizationId: scan.organizationId, userId: scan.requestedById, action: 'scan.completed', resource: 'scan', resourceId: scan.id, metadata: { findingCount: normalized.length } },
    });
  } catch (error) {
    const message = maskSecrets(error instanceof Error ? error.message : 'Scan failed').slice(0, 1000);
    await prisma.scan.update({ where: { id: scanId }, data: { status: abort.signal.aborted ? 'CANCELLED' : 'FAILED', error: message, finishedAt: new Date(), progress: 100 } });
    await scanLog(scanId, 'error', message);
    await publish({ organizationId: scan.organizationId, scanId, status: abort.signal.aborted ? 'CANCELLED' : 'FAILED', progress: 100 });
    if (scan.validationVulnerabilityId) {
      await prisma.validationRun.updateMany({
        where: { scanId, outcome: 'PENDING' },
        data: { outcome: 'ERROR', summary: message, completedAt: new Date() },
      });
    }
  } finally {
    clearInterval(watcher);
  }
}

async function prepareLocation(targetType: string, location: string, workdir: string, signal: AbortSignal): Promise<string> {
  if (targetType === 'PATH') {
    const allowlist = resolveScanAllowlist(process.env.SCAN_PATH_ALLOWLIST);
    if (!isPathInsideAllowlist(location, allowlist)) throw new Error('Scan path is outside the configured allowlist');
    return path.resolve(location);
  }
  if (targetType === 'URL') {
    const url = await assertSafeScanUrl(location, {
      allowPrivate: process.env.ALLOW_PRIVATE_SCAN_TARGETS === 'true',
      labCidrs: (process.env.LAB_NETWORK_CIDR ?? '').split(',').filter(Boolean),
    });
    return url.toString();
  }
  if (targetType === 'GIT') {
    const url = await assertSafeScanUrl(location, {
      allowPrivate: process.env.ALLOW_PRIVATE_SCAN_TARGETS === 'true',
      labCidrs: (process.env.LAB_NETWORK_CIDR ?? '').split(',').filter(Boolean),
    });
    const dest = path.join(workdir, 'repo');
    const result = await runCommand('git', ['clone', '--depth', '1', url.toString(), dest], {
      timeoutMs: Number(process.env.SCAN_COMMAND_TIMEOUT_MS ?? 600000),
      signal,
    });
    if (result.code !== 0) throw new Error(result.stderr || 'git clone failed');
    return dest;
  }
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,300}$/.test(location)) throw new Error('Container image reference is invalid');
  return location;
}

async function ingestFindings(organizationId: string, assetId: string, scanId: string, findings: NormalizedFinding[]) {
  const asset = await prisma.asset.findUnique({ where: { id: assetId } });
  if (!asset) return;
  const weights = await loadWeights(organizationId);
  for (const finding of findings) {
    const risk = scoreFinding(finding, asset, weights, false, false);
    const severity = finding.severity;
    const vulnerability = await prisma.vulnerability.upsert({
      where: { organizationId_dedupKey: { organizationId, dedupKey: finding.dedupKey } },
      create: {
        organizationId,
        assetId,
        dedupKey: finding.dedupKey,
        title: finding.title,
        description: finding.description,
        severity,
        status: 'OPEN',
        cve: finding.cve,
        cwe: finding.cwe,
        cvss: finding.cvss,
        component: finding.affectedComponent,
        riskScore: risk.score,
        riskRating: risk.rating,
        riskExplanation: risk as unknown as Prisma.InputJsonValue,
      },
      update: {
        lastSeen: new Date(),
        title: finding.title,
        description: finding.description,
        severity: higherSeverity(severity, severity),
        cvss: finding.cvss,
        deletedAt: null,
      },
    });
    const existing = await prisma.vulnerability.findUnique({ where: { id: vulnerability.id } });
    if (existing && existing.status === 'RESOLVED') {
      await prisma.vulnerability.update({ where: { id: existing.id }, data: { status: 'REOPENED', resolvedAt: null } });
      await notify(organizationId, null, 'vulnerability.reopened', 'Vulnerability reopened', existing.title);
    }
    if (existing && SEVERITY_RANK[finding.severity] > SEVERITY_RANK[existing.severity]) {
      await prisma.vulnerability.update({ where: { id: existing.id }, data: { severity: finding.severity } });
    }
    await prisma.finding.upsert({
      where: { organizationId_fingerprint: { organizationId, fingerprint: finding.fingerprint } },
      create: {
        organizationId,
        vulnerabilityId: vulnerability.id,
        assetId,
        scanId,
        source: finding.source,
        ruleId: finding.ruleId,
        title: finding.title,
        description: finding.description,
        severity: finding.severity,
        confidence: finding.confidence,
        cve: finding.cve,
        cwe: finding.cwe,
        cvss: finding.cvss,
        fingerprint: finding.fingerprint,
        affectedComponent: finding.affectedComponent,
        location: finding.location,
        remediationGuidance: finding.remediation,
        references: finding.references,
        riskScore: risk.score,
        riskRating: risk.rating,
        riskExplanation: risk as unknown as Prisma.InputJsonValue,
        evidence: { create: { summary: finding.title, location: finding.location, redacted: finding.evidence } },
      },
      update: {
        lastSeen: new Date(),
        scanId,
        title: finding.title,
        description: finding.description,
        status: vulnerability.status === 'RESOLVED' ? 'REOPENED' : undefined,
      },
    });
    if (finding.severity === 'CRITICAL') {
      await notify(organizationId, null, 'vulnerability.critical', 'Critical vulnerability detected', finding.title);
    }
  }
  await evaluatePolicies(organizationId);
}

function higherSeverity(left: NormalizedFinding['severity'], right: NormalizedFinding['severity']) {
  return SEVERITY_RANK[left] >= SEVERITY_RANK[right] ? left : right;
}

function scoreFinding(
  finding: Pick<NormalizedFinding, 'severity' | 'cvss' | 'references' | 'cwe'>,
  asset: { criticality: RiskInput['criticality']; exposure: RiskInput['exposure']; internetFacing: boolean; authRequired: boolean | null; privilegeRequired: string | null; dataSensitivity: RiskInput['dataSensitivity']; metadata: Prisma.JsonValue },
  weights: RiskWeights,
  onAttackPath: boolean,
  onSensitiveAttackPath: boolean,
) {
  const metadata = asset.metadata && typeof asset.metadata === 'object' && !Array.isArray(asset.metadata) ? asset.metadata : {};
  const controls = typeof metadata.compensatingControlScore === 'number' ? metadata.compensatingControlScore : 0;
  const references = finding.references.join(' ').toLowerCase();
  return calculateRisk({
    cvss: finding.cvss,
    severity: finding.severity,
    knownExploited: false,
    publicExploit: references.includes('exploit-db.com'),
    exploitIntelAvailable: references.includes('exploit-db.com'),
    criticality: asset.criticality,
    exposure: asset.exposure,
    internetFacing: asset.internetFacing,
    authRequired: asset.authRequired,
    privilegeRequired: (asset.privilegeRequired as RiskInput['privilegeRequired']) ?? 'UNKNOWN',
    dataSensitivity: asset.dataSensitivity,
    firstSeen: new Date(),
    onAttackPath,
    onSensitiveAttackPath,
    compensatingControlScore: controls,
    weights,
  });
}

async function loadWeights(organizationId: string): Promise<RiskWeights> {
  const config = await prisma.riskModelConfig.findUnique({ where: { organizationId } });
  if (!config || !config.weights || typeof config.weights !== 'object' || Array.isArray(config.weights)) {
    return { ...DEFAULT_RISK_WEIGHTS };
  }
  return { ...DEFAULT_RISK_WEIGHTS, ...(config.weights as Partial<RiskWeights>) };
}

async function finalizeValidation(organizationId: string, vulnerabilityId: string | null, scanId: string, findings: NormalizedFinding[]) {
  if (!vulnerabilityId) return;
  const vulnerability = await prisma.vulnerability.findFirst({ where: { id: vulnerabilityId, organizationId } });
  if (!vulnerability) return;
  const present = findings.some((finding) => finding.dedupKey === vulnerability.dedupKey);
  if (present) {
    await prisma.vulnerability.update({ where: { id: vulnerability.id }, data: { status: 'REOPENED', resolvedAt: null } });
    await prisma.finding.updateMany({ where: { vulnerabilityId: vulnerability.id }, data: { status: 'REOPENED' } });
    await prisma.remediation.updateMany({ where: { vulnerabilityId: vulnerability.id }, data: { status: 'REOPENED' } });
    await prisma.validationRun.updateMany({
      where: { vulnerabilityId: vulnerability.id, scanId },
      data: { outcome: 'REOPENED', summary: 'Validation scan still detected the finding', completedAt: new Date() },
    });
    await notify(organizationId, null, 'vulnerability.reopened', 'Validation reopened a finding', vulnerability.title);
    return;
  }
  await prisma.vulnerability.update({ where: { id: vulnerability.id }, data: { status: 'RESOLVED', resolvedAt: new Date() } });
  await prisma.finding.updateMany({ where: { vulnerabilityId: vulnerability.id }, data: { status: 'RESOLVED' } });
  await prisma.remediation.updateMany({ where: { vulnerabilityId: vulnerability.id }, data: { status: 'VALIDATED' } });
  await prisma.validationRun.updateMany({
    where: { vulnerabilityId: vulnerability.id, scanId },
    data: { outcome: 'RESOLVED', summary: 'Validation scan did not detect the finding', completedAt: new Date() },
  });
}

export async function rebuildGraph(organizationId: string): Promise<void> {
  const assets = await prisma.asset.findMany({
    where: { organizationId, deletedAt: null },
    include: { cloudResource: true, kubernetesWorkload: true, container: true, iamRole: true },
  });
  await prisma.networkNode.upsert({
    where: { organizationId_stableKey: { organizationId, stableKey: 'internet' } },
    create: { organizationId, kind: 'INTERNET', stableKey: 'internet', label: 'Internet', properties: { exposure: 'PUBLIC' } },
    update: {},
  });
  for (const asset of assets) {
    await prisma.networkNode.upsert({
      where: { assetId: asset.id },
      create: {
        organizationId,
        assetId: asset.id,
        kind: nodeKind(asset.type, asset.cloudResource?.resourceType),
        stableKey: `asset:${asset.id}`,
        label: asset.name,
        properties: propertiesFor(asset),
      },
      update: {
        label: asset.name,
        kind: nodeKind(asset.type, asset.cloudResource?.resourceType),
        properties: propertiesFor(asset),
      },
    });
  }
  await prisma.attackPath.deleteMany({ where: { organizationId } });
  await prisma.networkRelationship.deleteMany({ where: { organizationId, properties: { path: ['system'], equals: true } } });
  await prisma.networkNode.deleteMany({ where: { organizationId, kind: 'VULNERABILITY' } });
  const nodes = await prisma.networkNode.findMany({ where: { organizationId } });
  const internet = nodes.find((node) => node.stableKey === 'internet');
  const byAsset = new Map(nodes.filter((node) => node.assetId).map((node) => [node.assetId as string, node]));
  if (internet) {
    for (const asset of assets.filter((asset) => asset.internetFacing || asset.exposure === 'PUBLIC')) {
      const target = byAsset.get(asset.id);
      if (!target) continue;
      await systemEdge(organizationId, internet.id, target.id, 'CONNECTS_TO');
    }
  }
  for (const asset of assets) {
    const source = byAsset.get(asset.id);
    if (!source) continue;
    if (asset.cloudResource?.accountAssetId) {
      const account = byAsset.get(asset.cloudResource.accountAssetId);
      if (account) await systemEdge(organizationId, account.id, source.id, 'CONTAINS');
    }
    if (asset.kubernetesWorkload?.clusterAssetId) {
      const cluster = byAsset.get(asset.kubernetesWorkload.clusterAssetId);
      if (cluster) await systemEdge(organizationId, cluster.id, source.id, 'CONTAINS');
    }
    if (asset.container?.imageAssetId) {
      const image = byAsset.get(asset.container.imageAssetId);
      if (image) await systemEdge(organizationId, source.id, image.id, 'DEPENDS_ON');
    }
  }
  const vulnerabilities = await prisma.vulnerability.findMany({
    where: { organizationId, deletedAt: null, status: { in: [...OPEN] } },
  });
  for (const vulnerability of vulnerabilities) {
    const assetNode = byAsset.get(vulnerability.assetId);
    if (!assetNode) continue;
    const vulnNode = await prisma.networkNode.create({
      data: {
        organizationId,
        kind: 'VULNERABILITY',
        stableKey: `vuln:${vulnerability.id}`,
        label: vulnerability.title,
        properties: {
          severity: vulnerability.severity,
          riskScore: vulnerability.riskScore,
          explanation: `${vulnerability.title} is an open finding on this asset`,
        },
      },
    });
    await systemEdge(organizationId, assetNode.id, vulnNode.id, 'EXPOSES');
    const outgoing = await prisma.networkRelationship.findMany({ where: { organizationId, sourceId: assetNode.id } });
    for (const edge of outgoing) {
      if (!PRIVILEGE_EDGES.has(edge.type) || edge.targetId === vulnNode.id) continue;
      await systemEdge(organizationId, vulnNode.id, edge.targetId, edge.type);
    }
  }
  const graphNodes = await prisma.networkNode.findMany({ where: { organizationId } });
  const graphEdges = await prisma.networkRelationship.findMany({ where: { organizationId } });
  const discovered = discoverAttackPaths(
    graphNodes.map((node) => toEngineNode(node)),
    graphEdges.map((edge) => ({ id: edge.id, source: edge.sourceId, target: edge.targetId, type: edge.type })),
    { maxPaths: 2000 },
  );
  const kindById = new Map(graphNodes.map((node) => [node.id, node.kind]));
  const routes = new Map<string, { path: (typeof discovered)[number]; findings: Set<string> }>();
  for (const path of discovered) {
    const key = path.nodeIds.map((id) => (kindById.get(id) === 'VULNERABILITY' ? 'vulnerability' : id)).join('>');
    const findings = path.nodeIds.filter((id) => kindById.get(id) === 'VULNERABILITY');
    const existing = routes.get(key);
    if (!existing) routes.set(key, { path, findings: new Set(findings) });
    else {
      for (const id of findings) existing.findings.add(id);
      if (path.score > existing.path.score) existing.path = path;
    }
  }
  const sensitive = new Set(
    graphNodes.filter((node) => {
      const properties = objectProps(node.properties);
      return node.kind === 'DATABASE' || node.kind === 'S3_BUCKET' || node.kind === 'IAM_ROLE' || properties.dataSensitivity === 'RESTRICTED' || properties.dataSensitivity === 'CONFIDENTIAL' || properties.privileged === true || properties.criticality === 'CRITICAL';
    }).map((node) => node.id),
  );
  const sensitivePathNodes = new Set<string>();
  for (const path of discovered) {
    if (sensitive.has(path.sinkNodeId)) {
      for (const nodeId of path.nodeIds) sensitivePathNodes.add(nodeId);
    }
  }
  for (const route of routes.values()) {
    const path = route.path;
    const summary = route.findings.size === 1 ? path.summary : `${path.summary}. ${route.findings.size} open findings share this route.`;
    await prisma.attackPath.create({
      data: {
        organizationId,
        signature: path.signature,
        title: path.title.slice(0, 500),
        score: path.score,
        summary: summary.slice(0, 2000),
        stepCount: path.stepCount,
        entryNodeId: path.entryNodeId,
        sinkNodeId: path.sinkNodeId,
        factors: path.factors as unknown as Prisma.InputJsonValue,
        nodes: {
          create: path.nodeIds.map((networkNodeId, position) => ({
            networkNodeId,
            position,
            explanation: path.explanations[position] ?? 'Reachable from the previous hop',
          })),
        },
        edges: {
          create: path.edges.map((edge, position) => ({
            sourceNodeId: edge.source,
            targetNodeId: edge.target,
            type: edge.type,
            position,
          })),
        },
      },
    });
    if (sensitive.has(path.sinkNodeId)) {
      await notify(organizationId, null, 'attack-path.discovered', 'Attack path discovered', path.title.slice(0, 240));
    }
  }
  await refreshRisk(organizationId, new Set(discovered.flatMap((path) => path.nodeIds)), sensitivePathNodes);
  log('graph.rebuilt', { organizationId, paths: routes.size, discovered: discovered.length });
}

async function refreshRisk(organizationId: string, pathNodeIds: Set<string>, sensitivePathNodes: Set<string>) {
  const weights = await loadWeights(organizationId);
  const vulnerabilities = await prisma.vulnerability.findMany({
    where: { organizationId, deletedAt: null, status: { in: [...OPEN] } },
    include: { asset: true, findings: true },
  });
  const nodes = await prisma.networkNode.findMany({ where: { organizationId, kind: 'VULNERABILITY' } });
  for (const vulnerability of vulnerabilities) {
    const node = nodes.find((item) => item.stableKey === `vuln:${vulnerability.id}`);
    const onAttackPath = node ? pathNodeIds.has(node.id) : false;
    const onSensitive = node ? sensitivePathNodes.has(node.id) : false;
    const finding = vulnerability.findings[0];
    const risk = scoreFinding(
      {
        severity: vulnerability.severity,
        cvss: vulnerability.cvss ?? undefined,
        references: finding?.references ?? [],
        cwe: vulnerability.cwe ?? undefined,
      },
      vulnerability.asset,
      weights,
      onAttackPath,
      onSensitive,
    );
    await prisma.vulnerability.update({
      where: { id: vulnerability.id },
      data: { riskScore: risk.score, riskRating: risk.rating, riskExplanation: risk as unknown as Prisma.InputJsonValue },
    });
  }
}

async function systemEdge(organizationId: string, sourceId: string, targetId: string, type: EdgeType) {
  await prisma.networkRelationship.upsert({
    where: { organizationId_sourceId_targetId_type: { organizationId, sourceId, targetId, type } },
    create: { organizationId, sourceId, targetId, type, properties: { system: true } },
    update: { properties: { system: true } },
  });
}

function propertiesFor(asset: { exposure: string; criticality: string; dataSensitivity: string; iamRole?: { privileged: boolean } | null }): Prisma.InputJsonValue {
  return {
    exposure: asset.exposure,
    criticality: asset.criticality,
    dataSensitivity: asset.dataSensitivity,
    privileged: asset.iamRole?.privileged ?? false,
  };
}

function objectProps(value: Prisma.JsonValue): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function toEngineNode(node: { id: string; kind: string; label: string; properties: Prisma.JsonValue }): GraphNodeInput {
  const properties = objectProps(node.properties);
  return {
    id: node.id,
    kind: node.kind,
    label: node.label,
    exposure: typeof properties.exposure === 'string' ? properties.exposure : undefined,
    criticality: typeof properties.criticality === 'string' ? properties.criticality : undefined,
    dataSensitivity: typeof properties.dataSensitivity === 'string' ? properties.dataSensitivity : undefined,
    privileged: properties.privileged === true,
    severity: typeof properties.severity === 'string' ? properties.severity : undefined,
    riskScore: typeof properties.riskScore === 'number' ? properties.riskScore : undefined,
    explanation: typeof properties.explanation === 'string' ? properties.explanation : undefined,
  };
}

function nodeKind(type: AssetType, resourceType?: string | null): NodeKind {
  if (type === 'CLOUD_RESOURCE' && resourceType?.toLowerCase().includes('s3')) return 'S3_BUCKET';
  const map: Partial<Record<AssetType, NodeKind>> = {
    APPLICATION: 'APPLICATION',
    API: 'API',
    DOMAIN: 'DOMAIN',
    ENDPOINT: 'ENDPOINT',
    IDENTITY: 'IDENTITY',
    SERVICE_ACCOUNT: 'IDENTITY',
    IAM_ROLE: 'IAM_ROLE',
    SERVER: 'SERVER',
    CONTAINER: 'CONTAINER',
    CONTAINER_IMAGE: 'CONTAINER',
    DATABASE: 'DATABASE',
    KUBERNETES_WORKLOAD: 'KUBERNETES_WORKLOAD',
    CLOUD_RESOURCE: 'CLOUD_RESOURCE',
  };
  return map[type] ?? 'ASSET';
}

async function evaluatePolicies(organizationId: string) {
  const policies = await prisma.securityPolicy.findMany({ where: { organizationId, enabled: true, deletedAt: null } });
  if (policies.length === 0) return;
  const assets = await prisma.asset.findMany({ where: { organizationId, deletedAt: null }, include: { vulnerabilities: { where: { deletedAt: null } } } });
  for (const policy of policies) {
    for (const asset of assets) {
      const findings = asset.vulnerabilities.length ? asset.vulnerabilities : [null];
      for (const finding of findings) {
        const detail = explainPolicyViolation(
          policy.rule,
          { type: asset.type, exposure: asset.exposure, environment: asset.environment, ownerId: asset.ownerId, riskScore: finding?.riskScore },
          finding ? { severity: finding.severity, status: finding.status } : undefined,
        );
        if (!detail) continue;
        const existing = await prisma.policyViolation.findFirst({ where: { organizationId, policyId: policy.id, assetId: asset.id, detail, status: 'OPEN' } });
        if (existing) continue;
        await prisma.policyViolation.create({ data: { organizationId, policyId: policy.id, assetId: asset.id, detail } });
      }
    }
  }
}

async function notify(organizationId: string, userId: string | null, event: string, title: string, body: string) {
  const recent = await prisma.notification.findFirst({
    where: { organizationId, event, title, createdAt: { gt: new Date(Date.now() - 60 * 60 * 1000) } },
  });
  if (recent) return;
  await prisma.notification.create({ data: { organizationId, userId, channel: 'IN_APP', event, title, body: body.slice(0, 500) } });
  const admins = await prisma.membership.findMany({
    where: { organizationId, role: { in: ['SECURITY_ADMIN', 'SECURITY_ANALYST'] } },
    include: { user: true },
  });
  const email = createEmailAdapter();
  for (const admin of admins) {
    await email.send({ to: admin.user.email, subject: title, text: body });
  }
}

export async function runMaintenance(): Promise<void> {
  const overdue = await prisma.remediation.findMany({
    where: { dueAt: { lt: new Date() }, status: { notIn: ['VALIDATED', 'CLOSED'] } },
    include: { vulnerability: true },
  });
  for (const remediation of overdue) {
    await notify(remediation.organizationId, remediation.assigneeId, 'remediation.overdue', 'Remediation overdue', remediation.vulnerability.title);
  }
  const organizations = await prisma.organization.findMany({ where: { deletedAt: null }, select: { id: true } });
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);
  for (const organization of organizations) {
    const open = await prisma.vulnerability.groupBy({
      by: ['severity'],
      where: { organizationId: organization.id, deletedAt: null, status: { in: [...OPEN] } },
      _count: true,
    });
    const average = await prisma.vulnerability.aggregate({
      where: { organizationId: organization.id, deletedAt: null, status: { in: [...OPEN] } },
      _avg: { riskScore: true },
    });
    const count = (severity: string) => open.find((row) => row.severity === severity)?._count ?? 0;
    await prisma.riskSnapshot.upsert({
      where: { organizationId_capturedOn: { organizationId: organization.id, capturedOn: today } },
      create: {
        organizationId: organization.id,
        capturedOn: today,
        openCritical: count('CRITICAL'),
        openHigh: count('HIGH'),
        openMedium: count('MEDIUM'),
        openLow: count('LOW'),
        averageRisk: average._avg.riskScore ?? 0,
      },
      update: {
        openCritical: count('CRITICAL'),
        openHigh: count('HIGH'),
        openMedium: count('MEDIUM'),
        openLow: count('LOW'),
        averageRisk: average._avg.riskScore ?? 0,
      },
    });
  }
}

export type EngineEdge = GraphEdgeInput;
