import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { pillStyle } from "@/components/security/pill";
import {
  controlDisabledReason,
  freezeAgent,
  listAgents,
  restoreAgent,
  revokeAgent,
  statusColorVar,
  unfreezeAgent,
  type AgentControlKind,
  type AgentRecord,
} from "@/domains/agents";
import { errorMessage, formatTime } from "@/lib/format";

export function AgentsPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const [pending, setPending] = useState<{
    kind: AgentControlKind;
    agent: AgentRecord;
  } | null>(null);
  const [reason, setReason] = useState("");
  const [flash, setFlash] = useState<{ ok: boolean; message: string } | null>(
    null,
  );

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ["agents", gatewayUrl, bearerToken, activeTenant],
    queryFn: () => listAgents(apiOpts),
    enabled: tenantReady,
    refetchInterval: 12_000,
    retry: false,
  });

  const mutation = useMutation({
    mutationFn: async () => {
      if (!pending) throw new Error("No agent selected");
      const id = pending.agent.id;
      const r = reason.trim() || undefined;
      switch (pending.kind) {
        case "freeze":
          return freezeAgent(apiOpts, id, r);
        case "unfreeze":
          return unfreezeAgent(apiOpts, id, r);
        case "restore":
          return restoreAgent(apiOpts, id, r);
        case "revoke":
          return revokeAgent(apiOpts, id, r);
      }
    },
    onSuccess: () => {
      setFlash({
        ok: true,
        message: `Agent ${pending?.kind} completed.`,
      });
      setPending(null);
      setReason("");
      queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
    onError: (err: unknown) => {
      setFlash({ ok: false, message: errorMessage(err) });
    },
  });

  if (!tenantReady) return <TenantGate title="Select a tenant for Fleet" />;

  const rows = data ?? [];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">Agents</h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Fleet inventory and active-response controls (freeze / unfreeze /
          quarantine restore / revoke)
          {isFetching ? " · refreshing…" : null}
        </p>
      </div>

      {flash ? (
        <p
          role="status"
          className={`rounded border px-3 py-2 text-[11px] ${
            flash.ok
              ? "border-emerald-500/30 text-[var(--state-verified)]"
              : "border-rose-500/30 text-[var(--state-failed)]"
          }`}
        >
          {flash.message}
        </p>
      ) : null}

      {isLoading && (
        <p className="text-xs text-[var(--text-muted)]">Loading agents…</p>
      )}
      {error && (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(error)}
        </div>
      )}

      <div className="overflow-hidden rounded-[var(--radius-panel)] border border-[var(--border-default)]">
        <table className="w-full border-collapse text-left text-[11px]">
          <thead className="bg-[var(--surface-elevated)] text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            <tr>
              <th className="px-3 py-2 font-medium">Agent</th>
              <th className="px-3 py-2 font-medium">Env</th>
              <th className="px-3 py-2 font-medium">Risk</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Last seen</th>
              <th className="px-3 py-2 font-medium">Controls</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <tr
                key={a.id}
                className="border-t border-[var(--border-default)] hover:bg-[var(--interactive-bg-hover)]"
              >
                <td className="px-3 py-2">
                  <div className="font-medium text-[var(--text-primary)]">
                    {a.name || a.agent_key}
                  </div>
                  <div className="font-mono text-[10px] text-[var(--text-muted)]">
                    {a.agent_key}
                  </div>
                </td>
                <td className="px-3 py-2 text-[var(--text-secondary)]">
                  {a.environment}
                </td>
                <td className="px-3 py-2 text-[var(--text-secondary)]">
                  {a.risk_tier}
                </td>
                <td className="px-3 py-2">
                  <span
                    className="inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                    style={pillStyle(statusColorVar(a.status))}
                  >
                    {a.status}
                  </span>
                </td>
                <td className="px-3 py-2 whitespace-nowrap text-[var(--text-secondary)]">
                  {formatTime(a.last_seen_at) || "—"}
                </td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-1">
                    {(
                      [
                        "freeze",
                        "unfreeze",
                        "restore",
                        "revoke",
                      ] as AgentControlKind[]
                    ).map((kind) => {
                      const disabled = controlDisabledReason(kind, a.status);
                      return (
                        <button
                          key={kind}
                          type="button"
                          disabled={Boolean(disabled) || mutation.isPending}
                          title={disabled ?? kind}
                          className="rounded border border-[var(--border-default)] px-1.5 py-0.5 text-[10px] capitalize text-[var(--text-secondary)] hover:bg-[var(--interactive-bg)] disabled:opacity-40"
                          onClick={() => {
                            setFlash(null);
                            setReason("");
                            setPending({ kind, agent: a });
                          }}
                        >
                          {kind}
                        </button>
                      );
                    })}
                  </div>
                </td>
              </tr>
            ))}
            {!isLoading && rows.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-6 text-center text-[var(--text-muted)]"
                >
                  No agents registered for this tenant.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      {pending ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--surface-overlay)] p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full max-w-md space-y-3 rounded-[var(--radius-panel)] border border-[var(--border-default)] bg-[var(--surface-modal)] p-4 shadow-[var(--shadow-elevated)]">
            <h2 className="text-sm font-bold uppercase tracking-wider">
              Confirm {pending.kind}
            </h2>
            <p className="text-xs text-[var(--text-secondary)]">
              {pending.agent.name}{" "}
              <span className="font-mono">({pending.agent.agent_key})</span>
            </p>
            {pending.kind === "revoke" ? (
              <p className="text-[11px] text-[var(--sev-high)]">
                Permanent. Existing receipts remain as evidence.
              </p>
            ) : null}
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
              Reason (optional except revoke recommended)
              <textarea
                className="input-field min-h-[64px] resize-y normal-case tracking-normal"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </label>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                className="rounded-md border border-[var(--border-default)] px-3 py-1.5 text-xs"
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
                {mutation.isPending ? "Working…" : `Confirm ${pending.kind}`}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
