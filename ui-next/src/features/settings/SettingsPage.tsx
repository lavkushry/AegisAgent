import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { KeyRound, Server, User } from "lucide-react";
import { DEMO_MODE } from "@/app/runtimeConfig";
import { useAppStore } from "@/app/store";
import { probeLivez } from "@/lib/http/client";

export function SettingsPage() {
  const {
    gatewayUrl,
    bearerToken,
    activeTenant,
    operatorId,
    applyConnection,
  } = useAppStore();

  const [localUrl, setLocalUrl] = useState(gatewayUrl);
  const [localTenant, setLocalTenant] = useState(activeTenant);
  const [localToken, setLocalToken] = useState("");
  const [localOperator, setLocalOperator] = useState(operatorId);

  const { data: live } = useQuery({
    queryKey: ["livez", gatewayUrl],
    queryFn: ({ signal }) => probeLivez(gatewayUrl, signal),
    refetchInterval: 15_000,
  });

  const onApply = () => {
    applyConnection({
      gatewayUrl: localUrl,
      activeTenant: localTenant,
      bearerToken: localToken.trim() || undefined,
      operatorId: localOperator,
    });
    setLocalToken("");
  };

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">Settings</h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Gateway connection. Tenant is required before any SOC data loads.
          {DEMO_MODE
            ? " Demo mode may prefill and persist the bearer token."
            : " Production keeps tokens in memory only."}
        </p>
      </div>

      <section className="panel-card space-y-4">
        <h2 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-[var(--text-secondary)]">
          <Server size={14} className="text-[var(--brand)]" />
          Gateway connection
        </h2>

        <div className="rounded-md border border-[var(--border-default)] p-3 text-xs">
          Liveness:{" "}
          <span
            className={
              live
                ? "text-[var(--state-verified)]"
                : "text-[var(--state-failed)]"
            }
          >
            {live ? "/livez OK" : "/livez unreachable"}
          </span>
        </div>

        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
          Gateway URL
          <input
            className="input-field"
            type="url"
            name="gatewayUrl"
            aria-label="Gateway URL"
            value={localUrl}
            onChange={(e) => setLocalUrl(e.target.value)}
          />
        </label>

        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
          Tenant ID
          <input
            className="input-field"
            type="text"
            name="tenantId"
            aria-label="Tenant ID"
            value={localTenant}
            onChange={(e) => setLocalTenant(e.target.value)}
            placeholder="tenant_123"
          />
        </label>

        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
          <span className="flex items-center gap-1">
            <KeyRound size={12} aria-hidden="true" /> Bearer token
            {bearerToken ? " (set)" : " (empty)"}
          </span>
          <input
            className="input-field"
            type="password"
            name="bearerToken"
            aria-label="Bearer token"
            value={localToken}
            onChange={(e) => setLocalToken(e.target.value)}
            placeholder={
              bearerToken ? "Leave blank to keep current token" : "tenant_123"
            }
            autoComplete="off"
          />
        </label>

        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
          <span className="flex items-center gap-1">
            <User size={12} aria-hidden="true" /> Operator ID
          </span>
          <input
            className="input-field"
            type="text"
            name="operatorId"
            aria-label="Operator ID"
            value={localOperator}
            onChange={(e) => setLocalOperator(e.target.value)}
            placeholder="platform_admin"
          />
          <span className="normal-case tracking-normal text-[var(--text-muted)]">
            Sent as <code className="font-mono">approver_user_id</code> on
            approve/reject. Required for Approvals mutations.
          </span>
        </label>

        <button type="button" className="btn-primary" onClick={onApply}>
          Apply Config
        </button>
      </section>
    </div>
  );
}
