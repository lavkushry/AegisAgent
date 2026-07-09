import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";

export type GraphNodeGroup =
  | "agent"
  | "run"
  | "tool_call"
  | "decision"
  | "approval"
  | "receipt"
  | "incident"
  | "mcp_server"
  | "policy"
  | string;

export interface EvidenceNode {
  readonly id: string;
  readonly group: GraphNodeGroup;
  readonly label: string;
  readonly timestamp?: string | null;
  readonly metadata?: Record<string, unknown> | null;
}

export interface EvidenceEdge {
  readonly from: string;
  readonly to: string;
  readonly label?: string;
  readonly timestamp?: string | null;
}

export interface EvidenceGraph {
  readonly nodes: EvidenceNode[];
  readonly edges: EvidenceEdge[];
}

export type GraphScope =
  | { kind: "incident"; id: string }
  | { kind: "agent"; id: string; depth?: number }
  | { kind: "run"; id: string };

function graphPath(scope: GraphScope): string {
  switch (scope.kind) {
    case "incident":
      return `/v1/graph/incident/${encodeURIComponent(scope.id)}`;
    case "agent": {
      const depth = scope.depth ?? 3;
      return `/v1/graph/agent/${encodeURIComponent(scope.id)}?depth=${depth}`;
    }
    case "run":
      return `/v1/graph/run/${encodeURIComponent(scope.id)}`;
  }
}

function asNode(raw: Record<string, unknown>): EvidenceNode | null {
  const id = raw.id;
  if (id === undefined || id === null) return null;
  return {
    id: String(id),
    group: String(raw.group ?? raw.kind ?? "unknown"),
    label: String(raw.label ?? raw.id ?? ""),
    timestamp:
      raw.timestamp !== undefined && raw.timestamp !== null
        ? String(raw.timestamp)
        : null,
    metadata:
      raw.metadata && typeof raw.metadata === "object"
        ? (raw.metadata as Record<string, unknown>)
        : null,
  };
}

function asEdge(raw: Record<string, unknown>): EvidenceEdge | null {
  const from = raw.from;
  const to = raw.to;
  if (from === undefined || to === undefined) return null;
  return {
    from: String(from),
    to: String(to),
    label: raw.label !== undefined ? String(raw.label) : undefined,
    timestamp:
      raw.timestamp !== undefined && raw.timestamp !== null
        ? String(raw.timestamp)
        : null,
  };
}

/** Normalize a gateway EvidenceGraph payload (fail-closed empty on garbage). */
export function normalizeEvidenceGraph(raw: unknown): EvidenceGraph {
  if (!raw || typeof raw !== "object") {
    return { nodes: [], edges: [] };
  }
  const obj = raw as { nodes?: unknown; edges?: unknown };
  const nodes: EvidenceNode[] = [];
  if (Array.isArray(obj.nodes)) {
    for (const n of obj.nodes) {
      if (n && typeof n === "object") {
        const node = asNode(n as Record<string, unknown>);
        if (node) nodes.push(node);
      }
    }
  }
  const edges: EvidenceEdge[] = [];
  if (Array.isArray(obj.edges)) {
    for (const e of obj.edges) {
      if (e && typeof e === "object") {
        const edge = asEdge(e as Record<string, unknown>);
        if (edge) edges.push(edge);
      }
    }
  }
  return { nodes, edges };
}

/** Tenant-scoped evidence graph for incident / agent / run. */
export async function fetchEvidenceGraph(
  opts: FetchOptions,
  scope: GraphScope,
): Promise<EvidenceGraph> {
  const raw = await fetchFromGateway<unknown>(opts, graphPath(scope));
  return normalizeEvidenceGraph(raw);
}
