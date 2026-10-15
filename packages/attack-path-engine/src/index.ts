export type EdgeType =
  | 'CONNECTS_TO'
  | 'CAN_ACCESS'
  | 'RUNS_ON'
  | 'AUTHENTICATES_TO'
  | 'ASSUMES_ROLE'
  | 'CONTAINS'
  | 'EXPOSES'
  | 'DEPENDS_ON';

export interface GraphNodeInput {
  id: string;
  kind: string;
  label: string;
  exposure?: string;
  criticality?: string;
  dataSensitivity?: string;
  privileged?: boolean;
  severity?: string;
  riskScore?: number;
  explanation?: string;
}

export interface GraphEdgeInput {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
}

export interface DiscoveredPath {
  signature: string;
  title: string;
  score: number;
  summary: string;
  stepCount: number;
  entryNodeId: string;
  sinkNodeId: string;
  nodeIds: string[];
  edges: Array<{ source: string; target: string; type: EdgeType }>;
  explanations: string[];
  factors: {
    exposure: number;
    vulnerability: number;
    privilegeSteps: number;
    sink: number;
    data: number;
    stepPenalty: number;
  };
}

export interface DiscoverOptions {
  maxDepth?: number;
  maxPaths?: number;
}

const PRIVILEGE_EDGES = new Set<EdgeType>(['CAN_ACCESS', 'ASSUMES_ROLE', 'AUTHENTICATES_TO']);
const SENSITIVE_KINDS = new Set(['DATABASE', 'S3_BUCKET', 'IAM_ROLE']);

function isSensitive(node: GraphNodeInput): boolean {
  return (
    node.criticality === 'CRITICAL' ||
    node.dataSensitivity === 'RESTRICTED' ||
    node.dataSensitivity === 'CONFIDENTIAL' ||
    node.privileged === true ||
    SENSITIVE_KINDS.has(node.kind)
  );
}

function severityPoints(severity?: string): number {
  switch (severity) {
    case 'CRITICAL':
      return 25;
    case 'HIGH':
      return 18;
    case 'MEDIUM':
      return 10;
    case 'LOW':
      return 4;
    default:
      return 0;
  }
}

export function discoverAttackPaths(
  nodes: GraphNodeInput[],
  edges: GraphEdgeInput[],
  options: DiscoverOptions = {},
): DiscoveredPath[] {
  const maxDepth = options.maxDepth ?? 8;
  const maxPaths = options.maxPaths ?? 100;
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const adjacency = new Map<string, GraphEdgeInput[]>();
  for (const edge of edges) {
    const list = adjacency.get(edge.source) ?? [];
    list.push(edge);
    adjacency.set(edge.source, list);
  }

  const entries = nodes.filter((node) => node.kind === 'INTERNET' || node.exposure === 'PUBLIC');
  const results: DiscoveredPath[] = [];
  const seen = new Set<string>();

  for (const entry of entries) {
    const stack: Array<{ nodeId: string; nodeIds: string[]; edges: GraphEdgeInput[] }> = [
      { nodeId: entry.id, nodeIds: [entry.id], edges: [] },
    ];
    while (stack.length > 0) {
      const current = stack.pop();
      if (!current) break;
      const node = byId.get(current.nodeId);
      if (!node) continue;
      const vulnOnPath = current.nodeIds.some((id) => byId.get(id)?.kind === 'VULNERABILITY');
      if (current.nodeIds.length > 2 && node.id !== entry.id && isSensitive(node) && vulnOnPath) {
        const signature = current.nodeIds.join('>');
        if (!seen.has(signature)) {
          seen.add(signature);
          results.push(scorePath(current.nodeIds, current.edges, byId, entry.id, node.id));
        }
      }
      if (current.nodeIds.length >= maxDepth) continue;
      for (const edge of adjacency.get(current.nodeId) ?? []) {
        if (current.nodeIds.includes(edge.target)) continue;
        stack.push({
          nodeId: edge.target,
          nodeIds: [...current.nodeIds, edge.target],
          edges: [...current.edges, edge],
        });
      }
    }
  }

  return results.sort((a, b) => b.score - a.score).slice(0, maxPaths);
}

function scorePath(
  nodeIds: string[],
  edges: GraphEdgeInput[],
  byId: Map<string, GraphNodeInput>,
  entryNodeId: string,
  sinkNodeId: string,
): DiscoveredPath {
  const pathNodes = nodeIds.map((id) => byId.get(id)).filter((node): node is GraphNodeInput => Boolean(node));
  const entry = byId.get(entryNodeId);
  const sink = byId.get(sinkNodeId);
  const exposure = entry?.kind === 'INTERNET' || entry?.exposure === 'PUBLIC' ? 25 : 8;
  const vulnerability = Math.max(
    ...pathNodes.filter((node) => node.kind === 'VULNERABILITY').map((node) => node.riskScore ?? severityPoints(node.severity)),
    0,
  );
  const privilegeSteps = edges.filter((edge) => PRIVILEGE_EDGES.has(edge.type)).length;
  const sinkPoints = sink?.criticality === 'CRITICAL' ? 20 : sink?.criticality === 'HIGH' ? 12 : 8;
  const data = sink?.dataSensitivity === 'RESTRICTED' || sink?.dataSensitivity === 'CONFIDENTIAL' ? 15 : 0;
  const stepPenalty = Math.max(0, nodeIds.length - 2) * 4;
  const score = Math.max(
    0,
    Math.min(100, Math.round(exposure + vulnerability * 0.4 + privilegeSteps * 8 + sinkPoints + data - stepPenalty)),
  );
  const explanations = pathNodes.map((node) => node.explanation || defaultExplanation(node));
  const title = pathNodes.map((node) => node.label).join(' → ');
  return {
    signature: nodeIds.join('>'),
    title,
    score,
    summary: `${pathNodes.length} hop path reaching ${sink?.label ?? 'sensitive asset'}`,
    stepCount: Math.max(0, nodeIds.length - 1),
    entryNodeId,
    sinkNodeId,
    nodeIds,
    edges: edges.map((edge) => ({ source: edge.source, target: edge.target, type: edge.type })),
    explanations,
    factors: {
      exposure,
      vulnerability,
      privilegeSteps,
      sink: sinkPoints,
      data,
      stepPenalty,
    },
  };
}

function defaultExplanation(node: GraphNodeInput): string {
  if (node.kind === 'INTERNET') return 'Untrusted internet entry point';
  if (node.kind === 'VULNERABILITY') return `Vulnerability ${node.label} is present on this path`;
  if (node.exposure === 'PUBLIC') return `${node.label} is publicly exposed`;
  if (node.privileged) return `${node.label} is a privileged identity`;
  if (node.dataSensitivity === 'RESTRICTED' || node.dataSensitivity === 'CONFIDENTIAL') {
    return `${node.label} stores sensitive data`;
  }
  return `${node.label} is reachable from the previous hop`;
}
