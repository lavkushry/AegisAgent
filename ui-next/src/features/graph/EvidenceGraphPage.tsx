import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { EvidenceGraphSvg } from "@/components/graph/EvidenceGraphSvg";
import { fetchEvidenceGraph, type GraphScope } from "@/domains/graph";
import { errorMessage } from "@/lib/format";

type ScopeKind = GraphScope["kind"];

export function EvidenceGraphPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };

  const [kind, setKind] = useState<ScopeKind>("incident");
  const [id, setId] = useState("");
  const [depth, setDepth] = useState(3);
  const [submittedScope, setSubmittedScope] = useState<GraphScope | null>(
    null,
  );

  const query = useQuery({
    queryKey: [
      "evidence-graph",
      gatewayUrl,
      activeTenant,
      submittedScope?.kind,
      submittedScope && "id" in submittedScope ? submittedScope.id : "",
      submittedScope?.kind === "agent" ? submittedScope.depth : undefined,
    ],
    queryFn: () => fetchEvidenceGraph(apiOpts, submittedScope!),
    enabled: tenantReady && submittedScope !== null,
    retry: false,
  });

  if (!tenantReady)
    return <TenantGate title="Select a tenant for Evidence Graph" />;

  const submit = () => {
    const trimmed = id.trim();
    if (!trimmed) return;
    if (kind === "agent") {
      setSubmittedScope({ kind: "agent", id: trimmed, depth });
    } else {
      setSubmittedScope({ kind, id: trimmed });
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">
          Evidence Graph
        </h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Layered evidence graph for an incident, agent, or run — tool calls,
          decisions, approvals, and receipts.
        </p>
      </div>

      <div className="panel-card space-y-3">
        <div className="grid gap-3 sm:grid-cols-[auto_1fr_auto_auto]">
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Scope
            <select
              className="input-field normal-case tracking-normal"
              value={kind}
              onChange={(e) => setKind(e.target.value as ScopeKind)}
            >
              <option value="incident">Incident</option>
              <option value="agent">Agent</option>
              <option value="run">Run</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            ID
            <input
              className="input-field normal-case tracking-normal"
              placeholder="incident / agent / run id"
              value={id}
              onChange={(e) => setId(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") submit();
              }}
            />
          </label>
          {kind === "agent" ? (
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
              Depth
              <input
                type="number"
                min={1}
                max={5}
                className="input-field w-16 normal-case tracking-normal"
                value={depth}
                onChange={(e) =>
                  setDepth(Math.min(5, Math.max(1, Number(e.target.value) || 1)))
                }
              />
            </label>
          ) : null}
          <button
            type="button"
            className="btn-primary self-end"
            disabled={!id.trim()}
            onClick={submit}
          >
            Load graph
          </button>
        </div>
      </div>

      {!submittedScope ? (
        <p className="text-xs text-[var(--text-muted)]">
          Enter a scope id above to load its evidence graph.
        </p>
      ) : query.isLoading ? (
        <p className="text-xs text-[var(--text-muted)]">
          Loading evidence graph…
        </p>
      ) : query.error ? (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(query.error)}
        </div>
      ) : query.data ? (
        <div className="panel-card h-[32rem]">
          <EvidenceGraphSvg
            graph={query.data}
            scopeLabel={`${submittedScope.kind}:${submittedScope.id}`}
          />
        </div>
      ) : null}
    </div>
  );
}
