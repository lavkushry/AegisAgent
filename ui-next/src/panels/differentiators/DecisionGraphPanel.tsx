import { useEffect, useMemo, useState } from "react";
import { useAppStore } from "@/app/store";
import { frameRows } from "@/datasources/frame";
import { EvidenceGraphSvg } from "@/components/graph/EvidenceGraphSvg";
import {
  fetchEvidenceGraph,
  type EvidenceGraph,
  type GraphScope,
} from "@/domains/graph";
import { errorMessage } from "@/lib/format";
import type { PanelProps } from "../types";

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

  return (
    <div data-testid="decision-graph-panel" className="h-full">
      <EvidenceGraphSvg
        graph={g}
        maxNodes={maxNodes}
        scopeLabel={`${scope.kind}:${scope.id}`}
      />
    </div>
  );
}
