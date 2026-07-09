import { useQuery } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { pillStyle } from "@/components/security/pill";
import { severityColorVar } from "@/domains/incidents";
import { conditionPreview, listSocRules } from "@/domains/rules";
import { errorMessage } from "@/lib/format";

export function RulesPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ["soc-rules", gatewayUrl, bearerToken, activeTenant],
    queryFn: () => listSocRules(apiOpts),
    enabled: tenantReady,
    refetchInterval: 30_000,
    retry: false,
  });

  if (!tenantReady) return <TenantGate title="Select a tenant for Rules" />;

  const rows = data ?? [];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">Rules</h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Deterministic detection rule catalogue
          {isFetching ? " · refreshing…" : null}
        </p>
      </div>

      {isLoading && (
        <p className="text-xs text-[var(--text-muted)]">Loading rules…</p>
      )}
      {error && (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(error)}
        </div>
      )}

      <div className="grid gap-3 md:grid-cols-2">
        {rows.map((r) => (
          <article
            key={r.id || r.rule_key}
            className="panel-card space-y-2"
          >
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="text-xs font-semibold text-[var(--text-primary)]">
                  {r.name || r.rule_key}
                </div>
                <div className="font-mono text-[10px] text-[var(--text-muted)]">
                  {r.rule_key}
                </div>
              </div>
              <div className="flex flex-col items-end gap-1">
                <span
                  className="rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                  style={pillStyle(severityColorVar(r.severity))}
                >
                  {r.severity}
                </span>
                <span
                  className="rounded-full border px-2 py-0.5 text-[10px] font-semibold"
                  style={pillStyle(
                    r.enabled ? "--state-verified" : "--sev-info",
                  )}
                >
                  {r.enabled ? "enabled" : "disabled"}
                </span>
              </div>
            </div>
            <p className="text-[11px] text-[var(--text-secondary)]">
              {r.summary_template || "—"}
            </p>
            <pre className="overflow-x-auto rounded border border-[var(--border-default)] bg-[var(--surface-app)] p-2 font-mono text-[10px] text-[var(--text-muted)]">
              {conditionPreview(r.condition)}
            </pre>
            {r.source ? (
              <div className="text-[10px] text-[var(--text-muted)]">
                source: {r.source}
              </div>
            ) : null}
          </article>
        ))}
        {!isLoading && rows.length === 0 ? (
          <div className="panel-card text-xs text-[var(--text-secondary)] md:col-span-2">
            No detection rules for this tenant.
          </div>
        ) : null}
      </div>
    </div>
  );
}
