import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { HashChip } from "@/components/security/HashChip";
import { TrustBadge } from "@/components/security/TrustBadge";
import { DecisionBadge } from "@/components/security/DecisionBadge";
import {
  parseSimpleExploreQuery,
  searchDecisions,
} from "@/domains/decisions";
import { errorMessage, formatTime } from "@/lib/format";

const EXAMPLE =
  "decision:require_approval trust:untrusted_external";

export function ExplorePage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = {
    gatewayUrl,
    bearerToken,
    tenantId: activeTenant,
  };

  const [draft, setDraft] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filters = useMemo(
    () => parseSimpleExploreQuery(submitted),
    [submitted],
  );

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: [
      "explore",
      gatewayUrl,
      bearerToken,
      activeTenant,
      submitted,
    ],
    queryFn: () => searchDecisions(apiOpts, filters),
    enabled: tenantReady,
    refetchInterval: 12_000,
    retry: false,
  });

  if (!tenantReady) {
    return <TenantGate title="Select a tenant for Explore" />;
  }

  const rows = data ?? [];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">Explore</h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Discover-style search over authorization decisions. Phase 2 supports
          field chips (<code className="font-mono">decision:</code>,{" "}
          <code className="font-mono">agent_id:</code>,{" "}
          <code className="font-mono">trust:</code>,{" "}
          <code className="font-mono">skill:</code>) plus free-text{" "}
          <code className="font-mono">q</code>.
          {isFetching ? " · refreshing…" : null}
        </p>
      </div>

      <form
        className="panel-card flex flex-col gap-2 sm:flex-row sm:items-center"
        onSubmit={(e) => {
          e.preventDefault();
          setSubmitted(draft.trim());
          setExpandedId(null);
        }}
      >
        <div className="relative min-w-0 flex-1">
          <Search
            size={14}
            className="pointer-events-none absolute top-1/2 left-2.5 -translate-y-1/2 text-[var(--text-muted)]"
          />
          <input
            className="input-field pl-8"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={EXAMPLE}
            aria-label="Explore query"
          />
        </div>
        <button type="submit" className="btn-primary shrink-0">
          Search
        </button>
      </form>

      <div className="flex flex-wrap gap-2 text-[10px] text-[var(--text-muted)]">
        <span>Active filters:</span>
        {filters.decision ? (
          <code className="rounded bg-[var(--interactive-bg)] px-1.5 py-0.5 font-mono">
            decision:{filters.decision}
          </code>
        ) : null}
        {filters.agentId ? (
          <code className="rounded bg-[var(--interactive-bg)] px-1.5 py-0.5 font-mono">
            agent_id:{filters.agentId}
          </code>
        ) : null}
        {filters.sourceTrust ? (
          <code className="rounded bg-[var(--interactive-bg)] px-1.5 py-0.5 font-mono">
            trust:{filters.sourceTrust}
          </code>
        ) : null}
        {filters.skill ? (
          <code className="rounded bg-[var(--interactive-bg)] px-1.5 py-0.5 font-mono">
            skill:{filters.skill}
          </code>
        ) : null}
        {filters.q ? (
          <code className="rounded bg-[var(--interactive-bg)] px-1.5 py-0.5 font-mono">
            q:{filters.q}
          </code>
        ) : null}
        {!filters.decision &&
        !filters.agentId &&
        !filters.sourceTrust &&
        !filters.skill &&
        !filters.q ? (
          <span className="text-[var(--text-secondary)]">
            none (latest decisions)
          </span>
        ) : null}
      </div>

      {isLoading && (
        <p className="text-xs text-[var(--text-muted)]">Searching…</p>
      )}
      {error && (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(error)}
        </div>
      )}

      {!isLoading && !error ? (
        <p className="text-[11px] text-[var(--text-muted)]">
          {rows.length} result{rows.length === 1 ? "" : "s"}
        </p>
      ) : null}

      <div className="overflow-hidden rounded-[var(--radius-panel)] border border-[var(--border-default)]">
        <table className="w-full border-collapse text-left text-[11px]">
          <thead className="bg-[var(--surface-elevated)] text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            <tr>
              <th className="px-3 py-2 font-medium">Time</th>
              <th className="px-3 py-2 font-medium">Decision</th>
              <th className="px-3 py-2 font-medium">Agent</th>
              <th className="px-3 py-2 font-medium">Trust</th>
              <th className="px-3 py-2 font-medium">Tool / skill</th>
              <th className="px-3 py-2 font-medium">Action hash</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const open = expandedId === row.id;
              return (
                <tr
                  key={row.id}
                  className="cursor-pointer border-t border-[var(--border-default)] hover:bg-[var(--interactive-bg-hover)]"
                  onClick={() => setExpandedId(open ? null : row.id)}
                >
                  <td className="px-3 py-2 whitespace-nowrap text-[var(--text-secondary)]">
                    {formatTime(row.ts ?? row.created_at) || "—"}
                  </td>
                  <td className="px-3 py-2">
                    <DecisionBadge decision={row.decision} />
                  </td>
                  <td className="px-3 py-2 font-mono text-[var(--text-secondary)]">
                    {row.agent_id ?? "—"}
                  </td>
                  <td className="px-3 py-2">
                    <TrustBadge
                      trust={row.source_trust ?? row.root_trust_level}
                    />
                  </td>
                  <td className="px-3 py-2 text-[var(--text-secondary)]">
                    {row.tool ?? row.skill ?? "—"}
                  </td>
                  <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
                    <HashChip hash={row.action_hash} kind="action" />
                  </td>
                </tr>
              );
            })}
            {!isLoading && rows.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-6 text-center text-[var(--text-muted)]"
                >
                  No decisions matched.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      {expandedId ? (
        <div className="panel-card">
          <div className="mb-2 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Event detail · {expandedId}
          </div>
          <pre className="max-h-64 overflow-auto font-mono text-[10px] text-[var(--text-secondary)]">
            {JSON.stringify(
              rows.find((r) => r.id === expandedId) ?? {},
              null,
              2,
            )}
          </pre>
        </div>
      ) : null}
    </div>
  );
}
