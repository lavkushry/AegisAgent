import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { pillStyle } from "@/components/security/pill";
import {
  listWebhookSubscriptions,
  reactivateWebhook,
  redactUrl,
} from "@/domains/alerting";
import { errorMessage, formatTime } from "@/lib/format";

export function AlertingPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ["webhooks", gatewayUrl, bearerToken, activeTenant],
    queryFn: () => listWebhookSubscriptions(apiOpts, 50),
    enabled: tenantReady,
    refetchInterval: 20_000,
    retry: false,
  });

  const reactivate = useMutation({
    mutationFn: (id: string) => reactivateWebhook(apiOpts, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["webhooks"] });
    },
  });

  if (!tenantReady) return <TenantGate title="Select a tenant for Alerting" />;

  const rows = data ?? [];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">
          Alerting
        </h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Webhook subscriptions and delivery health (circuit breaker / reactivate)
          {isFetching ? " · refreshing…" : null}
        </p>
      </div>

      {isLoading && (
        <p className="text-xs text-[var(--text-muted)]">Loading webhooks…</p>
      )}
      {error && (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(error)}
        </div>
      )}

      {reactivate.error ? (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(reactivate.error)}
        </div>
      ) : null}

      <div className="space-y-2">
        {rows.map((w) => {
          const dead =
            String(w.delivery_status ?? "").toLowerCase() === "dead" ||
            (w.consecutive_failures ?? 0) >= 10;
          return (
            <article key={w.id} className="panel-card space-y-2">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="break-all font-mono text-[11px] text-[var(--text-primary)]">
                    {redactUrl(w.url)}
                  </div>
                  <div className="mt-1 text-[10px] text-[var(--text-muted)]">
                    events: {w.event_types || "—"} · min severity:{" "}
                    {w.min_severity || "info"} · format: {w.format || "json"}
                  </div>
                </div>
                <div className="flex flex-wrap gap-1">
                  <span
                    className="rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                    style={pillStyle(
                      w.status === "active"
                        ? "--state-verified"
                        : "--sev-info",
                    )}
                  >
                    {w.status || "unknown"}
                  </span>
                  <span
                    className="rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                    style={pillStyle(
                      dead ? "--state-failed" : "--state-verified",
                    )}
                  >
                    {w.delivery_status || "healthy"}
                  </span>
                </div>
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] text-[var(--text-secondary)]">
                <span>
                  failures: {w.consecutive_failures ?? 0} · last delivery:{" "}
                  {formatTime(w.last_delivery_at) || "—"} · last success:{" "}
                  {formatTime(w.last_success_at) || "—"}
                </span>
                {dead ? (
                  <button
                    type="button"
                    className="btn-primary"
                    disabled={reactivate.isPending}
                    onClick={() => reactivate.mutate(w.id)}
                  >
                    Reactivate
                  </button>
                ) : null}
              </div>
            </article>
          );
        })}
        {!isLoading && rows.length === 0 ? (
          <div className="panel-card text-xs text-[var(--text-secondary)]">
            No webhook subscriptions for this tenant.
          </div>
        ) : null}
      </div>
    </div>
  );
}
