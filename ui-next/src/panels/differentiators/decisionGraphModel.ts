import type { EvidenceEdge, EvidenceGraph, EvidenceNode } from "@/domains/graph";

/** Layer order for left-to-right evidence layout (vis.js group semantics). */
export const GRAPH_LAYERS: readonly string[] = [
  "agent",
  "run",
  "tool_call",
  "decision",
  "approval",
  "receipt",
  "policy",
  "incident",
  "mcp_server",
];

export interface LayoutNode extends EvidenceNode {
  readonly x: number;
  readonly y: number;
  readonly layer: number;
}

export interface LayoutEdge {
  readonly from: LayoutNode;
  readonly to: LayoutNode;
  readonly label?: string;
}

export interface GraphLayout {
  readonly nodes: LayoutNode[];
  readonly edges: LayoutEdge[];
  readonly width: number;
  readonly height: number;
}

const COL_W = 110;
const ROW_H = 48;
const PAD = 24;
const NODE_W = 88;
const NODE_H = 28;

function layerIndex(group: string): number {
  const i = GRAPH_LAYERS.indexOf(group);
  return i >= 0 ? i : GRAPH_LAYERS.length;
}

/**
 * Deterministic layered layout — no external graph lib.
 * Nodes columned by group; edges connect laid-out endpoints.
 */
export function layoutEvidenceGraph(
  graph: EvidenceGraph,
  maxNodes = 40,
): GraphLayout {
  const nodes = graph.nodes.slice(0, Math.max(1, maxNodes));
  const idSet = new Set(nodes.map((n) => n.id));
  const byLayer = new Map<number, EvidenceNode[]>();
  for (const node of nodes) {
    const layer = layerIndex(String(node.group));
    const list = byLayer.get(layer) ?? [];
    list.push(node);
    byLayer.set(layer, list);
  }

  const laid: LayoutNode[] = [];
  const maxLayer = Math.max(0, ...byLayer.keys(), 0);
  let maxRows = 1;
  for (const [layer, list] of byLayer) {
    maxRows = Math.max(maxRows, list.length);
    list.forEach((node, row) => {
      laid.push({
        ...node,
        layer,
        x: PAD + layer * COL_W,
        y: PAD + row * ROW_H,
      });
    });
  }

  const byId = new Map(laid.map((n) => [n.id, n]));
  const edges: LayoutEdge[] = [];
  for (const e of graph.edges) {
    if (!idSet.has(e.from) || !idSet.has(e.to)) continue;
    const from = byId.get(e.from);
    const to = byId.get(e.to);
    if (!from || !to) continue;
    edges.push({ from, to, label: e.label });
  }

  const width = PAD * 2 + (maxLayer + 1) * COL_W;
  const height = PAD * 2 + maxRows * ROW_H;
  return { nodes: laid, edges, width, height };
}

export function nodeFill(group: string): string {
  switch (group) {
    case "decision":
      return "var(--brand)";
    case "approval":
      return "var(--decision-approval)";
    case "receipt":
      return "var(--state-verified)";
    case "tool_call":
      return "var(--sev-low)";
    case "agent":
    case "run":
      return "var(--text-secondary)";
    case "policy":
      return "var(--sev-medium)";
    case "incident":
      return "var(--sev-high)";
    default:
      return "var(--text-muted)";
  }
}

export function shortLabel(label: string, max = 12): string {
  const t = label.trim();
  if (t.length <= max) return t;
  return `${t.slice(0, max - 1)}…`;
}

export { NODE_W, NODE_H };

export function countByGroup(
  nodes: ReadonlyArray<EvidenceNode>,
): Record<string, number> {
  const out: Record<string, number> = {};
  for (const n of nodes) {
    const g = String(n.group);
    out[g] = (out[g] ?? 0) + 1;
  }
  return out;
}

export function edgeCountFor(edges: ReadonlyArray<EvidenceEdge>): number {
  return edges.length;
}
