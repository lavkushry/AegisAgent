import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { pillStyle } from "@/components/security/pill";
import {
  controlDisabledReason,
  freezeAgent,
  getAgent,
  listAgentPermissions,
  restoreAgent,
  revokeAgent,
  statusColorVar,
  unfreezeAgent,
  type AgentControlKind,
} from "@/domains/agents";
import { errorMessage, formatTime } from "@/lib/format";

export function AgentDetailPage() {
  const { agentId = "" } = useParams();
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const [pending, setPending] = useState<AgentControlKind | null>(null);
  const [reason, setReason] = useState("");
  const [flash, setFlash] = useState<string | null>(null);

  const agentQuery = useQuery({
    queryKey: ["agent", agentId, gatewayUrl, activeTenant],
    queryFn: () => getAgent(apiOpts, agentId),
    enabled: tenantReady && Boolean(agentId),
    retry: false,
  });

  const permsQuery = useQuery({
    queryKey: ["agent-perms", agentId, gatewayUrl, activeTenant],
    queryFn: () => listAgentPermissions(apiOpts, agentId),
    enabled: tenantReady && Boolean(agentId),
    retry: false,
  });

  const mutation = useMutation({
    mutationFn: async () => {
      if (!pending) throw new Error("No action");
      const r = reason.trim() || undefined;
      switch (pending) {
        case "freeze":
          return freezeAgent(apiOpts, agentId, r);
        case "unfreeze":
          return unfreezeAgent(apiOpts, agentId, r);
        case "restore":
          return restoreAgent(apiOpts, agentId, r);
        case "revoke":
          return revokeAgent(apiOpts, agentId, r);
      }
    },
    onSuccess: () => {
      setFlash(`${pending} completed`);
      setPending(null);
      setReason("");
      void queryClient.invalidateQueries({ queryKey: ["agent", agentId] });
      void queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
    onError: (err: unknown) => setFlash(errorMessage(err)),
  });

  if (!tenantReady) return <TenantGate title="Select a tenant for Agents" />;

  const agent = agentQuery.data;

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <Link
        to="/agents"
        className="text-[11px] text-[var(--brand)] underline"
      >
        ← Fleet
      </Link>

      {agentQuery.isLoading && (
        <p className="text-xs text-[var(--text-muted)]">Loading agent…</p>
      )}
      {agentQuery.error && (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(agentQuery.error)}
        </div>
      )}

      {agent ? (
        <>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h1 className="text-sm font-bold uppercase tracking-wider">
                {agent.name || agent.agent_key}
              </h1>
              <p className="mt-1 font-mono text-[11px] text-[var(--text-muted)]">
                {agent.agent_key} · {agent.id}
              </p>
            </div>
            <span
              className="rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
              style={pillStyle(statusColorVar(agent.status))}
            >
              {agent.status}
            </span>
          </div>

          {flash ? (
            <p className="text-[11px] text-[var(--text-secondary)]" role="status">
              {flash}
            </p>
          ) : null}

          <section className="panel-card grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-[11px]">
            <dt className="text-[var(--text-muted)]">Environment</dt>
            <dd>{agent.environment}</dd>
            <dt className="text-[var(--text-muted)]">Risk tier</dt>
            <dd>{agent.risk_tier}</dd>
            <dt className="text-[var(--text-muted)]">Framework</dt>
            <dd>{agent.framework || "—"}</dd>
            <dt className="text-[var(--text-muted)]">Model</dt>
            <dd>{agent.model_name || "—"}</dd>
            <dt className="text-[var(--text-muted)]">Last seen</dt>
            <dd>{formatTime(agent.last_seen_at) || "—"}</dd>
            {agent.frozen_reason ? (
              <>
                <dt className="text-[var(--text-muted)]">Frozen reason</dt>
                <dd className="text-[var(--sev-high)]">{agent.frozen_reason}</dd>
              </>
            ) : null}
          </section>

          <section className="panel-card space-y-2">
            <h2 className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">
              Active response
            </h2>
            <div className="flex flex-wrap gap-2">
              {(
                ["freeze", "unfreeze", "restore", "revoke"] as AgentControlKind[]
              ).map((kind) => {
                const disabled = controlDisabledReason(kind, agent.status);
                return (
                  <button
                    key={kind}
                    type="button"
                    disabled={Boolean(disabled) || mutation.isPending}
                    title={disabled ?? kind}
                    className="rounded border border-[var(--border-default)] px-2 py-1 text-[11px] capitalize disabled:opacity-40"
                    onClick={() => {
                      setFlash(null);
                      setReason("");
                      setPending(kind);
                    }}
                  >
                    {kind}
                  </button>
                );
              })}
            </div>
          </section>

          <section className="panel-card space-y-2">
            <h2 className="text-[10px] font-bold uppercase tracking-wider text-[var(--text-muted)]">
              Tool permissions
            </h2>
            {permsQuery.isLoading ? (
              <p className="text-[11px] text-[var(--text-muted)]">Loading…</p>
            ) : (
              <ul className="space-y-1 font-mono text-[11px]">
                {(permsQuery.data ?? []).map((p) => (
                  <li
                    key={p.id ?? p.tool_key}
                    className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-1"
                  >
                    {p.tool_key}
                  </li>
                ))}
                {(permsQuery.data ?? []).length === 0 ? (
                  <li className="text-[var(--text-muted)]">No permissions.</li>
                ) : null}
              </ul>
            )}
          </section>
        </>
      ) : null}

      {pending ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--surface-overlay)] p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full max-w-md space-y-3 rounded-[var(--radius-panel)] border border-[var(--border-default)] bg-[var(--surface-modal)] p-4 shadow-[var(--shadow-elevated)]">
            <h2 className="text-sm font-bold uppercase tracking-wider">
              Confirm {pending}
            </h2>
            <textarea
              className="input-field min-h-[64px] resize-y"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Reason (optional)"
            />
            <div className="flex justify-end gap-2">
              <button
                type="button"
                className="rounded border border-[var(--border-default)] px-3 py-1.5 text-xs"
                onClick={() => setPending(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn-primary"
                disabled={mutation.isPending}
                onClick={() => mutation.mutate()}
              >
                Confirm {pending}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
