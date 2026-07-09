import { useEffect, useMemo, useState } from "react";
import { useAppStore } from "@/app/store";
import { frameRows } from "@/datasources/frame";
import {
  fetchEvidenceGraph,
  type EvidenceGraph,
  type GraphScope,
} from "@/domains/graph";
import { errorMessage } from "@/lib/format";
import type { PanelProps } from "../types";
import {
  NODE_H,
  NODE_W,
  countByGroup,
  layoutEvidenceGraph,
  nodeFill,
  shortLabel,
} from "./decisionGraphModel";

export interface DecisionGraphOptions {
  /** Graph root: incident (default), agent, or run. */
  scopeKind?: "incident" | "agent" | "run";
  /** Field on the panel frame used as scope id (default: id). */
  scopeIdField?: string;
  /** Prefer this id when present (template pin). */
  fixedScopeId?: string;
  /** Cap nodes rendered (default: 40). */
  maxNodes?: number;
  /** Agent graph depth 1–5 (default: 3). */
  depth?: number;
}

function resolveScope(
  options: DecisionGraphOptions | undefined,
  rows: Array<Record<string, unknown>>,
): GraphScope | null {
  const kind = options?.scopeKind ?? "incident";
  const field = options?.scopeIdField ?? "id";
  const fixed = options?.fixedScopeId?.trim();
  const fromRow = rows[0]?.[field];
  const id = fixed || (fromRow !== undefined ? String(fromRow).trim() : "");
  if (!id) return null;
  if (kind === "agent") {
    return { kind: "agent", id, depth: options?.depth ?? 3 };
  }
  if (kind === "run") return { kind: "run", id };
  return { kind: "incident", id };
}

/**
 * ★ Decision / evidence graph — layered SVG of gateway EvidenceGraph nodes.
 *
 * Frame supplies the scope id (e.g. latest incident from entity:incident).
 * Graph payload is loaded via GET /v1/graph/{incident|agent|run}/:id.
 * No vis.js dependency — pure SVG layout by node group.
 */
export default function DecisionGraphPanel(
  props: PanelProps<DecisionGraphOptions>,
) {
  const rows = frameRows(props.data);
  const scope = useMemo(
    () => resolveScope(props.definition.options, rows),
    [props.definition.options, rows],
  );
  const maxNodes = props.definition.options?.maxNodes ?? 40;

  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);

  const [graph, setGraph] = useState<EvidenceGraph | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scopeKey = scope
    ? scope.kind === "agent"
      ? `${scope.kind}:${scope.id}:${scope.depth ?? 3}`
      : `${scope.kind}:${scope.id}`
    : "";

  useEffect(() => {
    if (!scope || !activeTenant.trim()) {
      setGraph(null);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    const opts = { gatewayUrl, bearerToken, tenantId: activeTenant };
    void fetchEvidenceGraph(opts, scope)
      .then((g) => {
        if (!cancelled) setGraph(g);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setGraph(null);
          setError(errorMessage(err));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scopeKey, scope, gatewayUrl, bearerToken, activeTenant]);

  if (!scope) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-[var(--text-muted)]">
        No graph scope (need an incident / agent / run id)
      </div>
    );
  }

  if (loading && !graph) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-[var(--text-muted)]">
        Loading evidence graph…
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-[var(--sev-high)]">
        {error}
      </div>
    );
  }

  const g = graph ?? { nodes: [], edges: [] };
  if (g.nodes.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-[var(--text-muted)]">
        Empty graph for {scope.kind} {scope.id}
      </div>
    );
  }

  const layout = layoutEvidenceGraph(g, maxNodes);
  const counts = countByGroup(g.nodes);

  return (
    <div
      className="flex h-full flex-col gap-1"
      data-testid="decision-graph-panel"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-2 text-[10px] text-[var(--text-muted)]">
        <span className="font-mono truncate">
          {scope.kind}:{scope.id}
        </span>
        <span className="tabular-nums">
          {g.nodes.length} nodes · {g.edges.length} edges
          {counts.decision
            ? ` · ${counts.decision} decision${counts.decision === 1 ? "" : "s"}`
            : ""}
        </span>
      </div>
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        className="h-full min-h-[8rem] w-full"
        role="img"
        aria-label={`Evidence graph for ${scope.kind} ${scope.id}: ${g.nodes.length} nodes`}
      >
        {layout.edges.map((e, i) => {
          const x1 = e.from.x + NODE_W;
          const y1 = e.from.y + NODE_H / 2;
          const x2 = e.to.x;
          const y2 = e.to.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          return (
            <g key={`e-${i}-${e.from.id}-${e.to.id}`}>
              <path
                d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
                fill="none"
                stroke="var(--border-default)"
                strokeWidth={1.25}
              />
            </g>
          );
        })}
        {layout.nodes.map((n) => (
          <g key={n.id}>
            <title>
              {n.group}: {n.label}
            </title>
            <rect
              x={n.x}
              y={n.y}
              width={NODE_W}
              height={NODE_H}
              rx={4}
              fill={nodeFill(String(n.group))}
              fillOpacity={0.22}
              stroke={nodeFill(String(n.group))}
              strokeWidth={1}
            />
            <text
              x={n.x + NODE_W / 2}
              y={n.y + 11}
              textAnchor="middle"
              fill="var(--text-muted)"
              fontSize={7}
              fontFamily="ui-sans-serif, system-ui, sans-serif"
            >
              {String(n.group)}
            </text>
            <text
              x={n.x + NODE_W / 2}
              y={n.y + 22}
              textAnchor="middle"
              fill="var(--text-primary)"
              fontSize={9}
              fontFamily="ui-monospace, monospace"
              fontWeight={600}
            >
              {shortLabel(n.label, 11)}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}
