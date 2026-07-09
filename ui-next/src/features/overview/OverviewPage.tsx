import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { useAppStore } from "@/app/store";
import { getTenantStats } from "@/domains/stats";
import { TenantRequiredError } from "@/lib/http/errors";

export function OverviewPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ["stats", gatewayUrl, bearerToken, activeTenant],
    queryFn: () =>
      getTenantStats({
        gatewayUrl,
        bearerToken,
        tenantId: activeTenant,
      }),
    enabled: tenantReady,
    retry: false,
  });

  if (!tenantReady) {
    return (
      <div className="panel-card max-w-lg space-y-3">
        <h1 className="text-sm font-bold">Select a tenant</h1>
        <p className="text-xs text-[var(--text-secondary)]">
          Select a tenant before loading SOC data. Open Settings and set Tenant
          ID + Bearer token (local demo: both are the tenant id).
        </p>
        <Link className="btn-primary inline-block" to="/settings">
          Open Settings
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">Overview</h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Tenant <span className="font-mono text-[var(--text-primary)]">{activeTenant}</span>
          {isFetching ? " · refreshing…" : null}
        </p>
      </div>

      {isLoading && (
        <p className="text-xs text-[var(--text-muted)]">Loading stats…</p>
      )}

      {error && (
        <div className="panel-card border-[var(--sev-high)] text-xs text-[var(--sev-high)]">
          {error instanceof TenantRequiredError
            ? error.message
            : error instanceof Error
              ? error.message
              : "Failed to load stats"}
        </div>
      )}

      {data && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
          {[
            ["Decisions", data.total_decisions],
            ["Allow", data.decisions_allow],
            ["Deny", data.decisions_deny],
            ["Require approval", data.decisions_require_approval],
            ["Agents", data.total_agents],
            ["Receipts", data.total_receipts],
          ].map(([label, value]) => (
            <div key={String(label)} className="panel-card">
              <div className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                {label}
              </div>
              <div className="mt-1 font-mono text-xl text-[var(--text-primary)]">
                {value}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
