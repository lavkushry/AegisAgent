import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { pillStyle } from "@/components/security/pill";
import {
  blockEgress,
  egressDecisionColorVar,
  listEgressEvents,
  unblockEgress,
} from "@/domains/egress";
import { errorMessage, formatTime } from "@/lib/format";

export function EgressEventsPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const [blockForm, setBlockForm] = useState({
    destination: "",
    actor: "",
    reason: "",
  });
  const [unblockForm, setUnblockForm] = useState({ ban_id: "", revoked_by: "" });
  const [flash, setFlash] = useState<{ ok: boolean; message: string } | null>(
    null,
  );

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ["egress-events", gatewayUrl, bearerToken, activeTenant],
    queryFn: () => listEgressEvents(apiOpts, 100),
    enabled: tenantReady,
    refetchInterval: 10_000,
    retry: false,
  });

  const blockMutation = useMutation({
    mutationFn: () =>
      blockEgress(apiOpts, {
        destination: blockForm.destination.trim(),
        actor: blockForm.actor.trim(),
        reason: blockForm.reason,
      }),
    onSuccess: (ban) => {
      setFlash({
        ok: true,
        message: `Blocked ${ban.target_value} (ban ${ban.id}).`,
      });
      setBlockForm({ destination: "", actor: "", reason: "" });
      queryClient.invalidateQueries({ queryKey: ["egress-events"] });
    },
    onError: (err: unknown) => setFlash({ ok: false, message: errorMessage(err) }),
  });

  const unblockMutation = useMutation({
    mutationFn: () =>
      unblockEgress(
        apiOpts,
        unblockForm.ban_id.trim(),
        unblockForm.revoked_by.trim(),
      ),
    onSuccess: () => {
      setFlash({ ok: true, message: "Egress ban revoked." });
      setUnblockForm({ ban_id: "", revoked_by: "" });
      queryClient.invalidateQueries({ queryKey: ["egress-events"] });
    },
    onError: (err: unknown) => setFlash({ ok: false, message: errorMessage(err) }),
  });

  if (!tenantReady) return <TenantGate title="Select a tenant for Egress" />;

  const rows = data ?? [];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">
          Egress Events
        </h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Outbound network decisions from the egress proxy, plus explicit
          block / unblock of a destination.
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

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel-card space-y-3">
          <h2 className="text-xs font-bold uppercase tracking-wider">
            Block destination
          </h2>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Destination (host or IP)
            <input
              className="input-field normal-case tracking-normal"
              placeholder="evil.example.com"
              value={blockForm.destination}
              onChange={(e) =>
                setBlockForm((f) => ({ ...f, destination: e.target.value }))
              }
            />
          </label>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Actor
            <input
              className="input-field normal-case tracking-normal"
              placeholder="you@team"
              value={blockForm.actor}
              onChange={(e) =>
                setBlockForm((f) => ({ ...f, actor: e.target.value }))
              }
            />
          </label>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Reason
            <textarea
              className="input-field min-h-[48px] resize-y normal-case tracking-normal"
              value={blockForm.reason}
              onChange={(e) =>
                setBlockForm((f) => ({ ...f, reason: e.target.value }))
              }
            />
          </label>
          <button
            type="button"
            className="btn-primary"
            disabled={
              !blockForm.destination.trim() ||
              !blockForm.actor.trim() ||
              blockMutation.isPending
            }
            onClick={() => {
              setFlash(null);
              blockMutation.mutate();
            }}
          >
            {blockMutation.isPending ? "Blocking…" : "Block destination"}
          </button>
        </div>

        <div className="panel-card space-y-3">
          <h2 className="text-xs font-bold uppercase tracking-wider">
            Unblock (revoke ban)
          </h2>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Ban ID
            <input
              className="input-field normal-case tracking-normal"
              placeholder="ban returned from block above"
              value={unblockForm.ban_id}
              onChange={(e) =>
                setUnblockForm((f) => ({ ...f, ban_id: e.target.value }))
              }
            />
          </label>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Revoked by
            <input
              className="input-field normal-case tracking-normal"
              value={unblockForm.revoked_by}
              onChange={(e) =>
                setUnblockForm((f) => ({ ...f, revoked_by: e.target.value }))
              }
            />
          </label>
          <button
            type="button"
            className="btn-primary"
            disabled={
              !unblockForm.ban_id.trim() ||
              !unblockForm.revoked_by.trim() ||
              unblockMutation.isPending
            }
            onClick={() => {
              setFlash(null);
              unblockMutation.mutate();
            }}
          >
            {unblockMutation.isPending ? "Unblocking…" : "Unblock destination"}
          </button>
          <p className="text-[10px] text-[var(--text-muted)]">
            See the Ban Center for a full list of active egress bans.
          </p>
        </div>
      </div>

      {isLoading && (
        <p className="text-xs text-[var(--text-muted)]">
          Loading egress events…
        </p>
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
              <th className="px-3 py-2 font-medium">Event</th>
              <th className="px-3 py-2 font-medium">Decision</th>
              <th className="px-3 py-2 font-medium">Agent / Run</th>
              <th className="px-3 py-2 font-medium">Reason</th>
              <th className="px-3 py-2 font-medium">Observed</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr
                key={e.id}
                className="border-t border-[var(--border-default)] hover:bg-[var(--interactive-bg-hover)]"
              >
                <td className="px-3 py-2 font-mono text-[var(--text-primary)]">
                  {e.event_type}
                </td>
                <td className="px-3 py-2">
                  <span
                    className="inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                    style={pillStyle(egressDecisionColorVar(e.decision))}
                  >
                    {e.decision || "—"}
                  </span>
                </td>
                <td className="px-3 py-2 font-mono text-[var(--text-secondary)]">
                  {e.agent_id || e.run_id || "—"}
                </td>
                <td className="px-3 py-2 text-[var(--text-secondary)]">
                  {e.reason || "—"}
                </td>
                <td className="px-3 py-2 whitespace-nowrap text-[var(--text-secondary)]">
                  {formatTime(e.observed_at)}
                </td>
              </tr>
            ))}
            {!isLoading && rows.length === 0 ? (
              <tr>
                <td
                  colSpan={5}
                  className="px-3 py-6 text-center text-[var(--text-muted)]"
                >
                  No egress events for this tenant.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}
