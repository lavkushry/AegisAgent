import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { pillStyle } from "@/components/security/pill";
import {
  QUARANTINE_TARGET_TYPES,
  createQuarantine,
  listQuarantine,
  quarantineStatusColorVar,
  releaseQuarantine,
  type QuarantineRecord,
} from "@/domains/quarantine";
import { errorMessage, formatTime } from "@/lib/format";

const EMPTY_FORM = {
  target_type: "agent",
  target_value: "",
  actor: "",
  reason: "",
  incident_id: "",
};

export function QuarantineCenterPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const [form, setForm] = useState(EMPTY_FORM);
  const [releasing, setReleasing] = useState<QuarantineRecord | null>(null);
  const [releasedBy, setReleasedBy] = useState("");
  const [flash, setFlash] = useState<{ ok: boolean; message: string } | null>(
    null,
  );

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ["quarantine", gatewayUrl, bearerToken, activeTenant],
    queryFn: () => listQuarantine(apiOpts),
    enabled: tenantReady,
    refetchInterval: 15_000,
    retry: false,
  });

  const createMutation = useMutation({
    mutationFn: () =>
      createQuarantine(apiOpts, {
        target_type: form.target_type,
        target_value: form.target_value.trim(),
        actor: form.actor.trim(),
        reason: form.reason,
        incident_id: form.incident_id,
      }),
    onSuccess: () => {
      setFlash({ ok: true, message: "Quarantine recorded." });
      setForm(EMPTY_FORM);
      queryClient.invalidateQueries({ queryKey: ["quarantine"] });
    },
    onError: (err: unknown) => setFlash({ ok: false, message: errorMessage(err) }),
  });

  const releaseMutation = useMutation({
    mutationFn: () => {
      if (!releasing) throw new Error("No quarantine selected");
      return releaseQuarantine(apiOpts, releasing.id, releasedBy.trim());
    },
    onSuccess: () => {
      setFlash({ ok: true, message: "Quarantine released." });
      setReleasing(null);
      setReleasedBy("");
      queryClient.invalidateQueries({ queryKey: ["quarantine"] });
    },
    onError: (err: unknown) => setFlash({ ok: false, message: errorMessage(err) }),
  });

  if (!tenantReady)
    return <TenantGate title="Select a tenant for Quarantine" />;

  const rows = data ?? [];
  const canCreate =
    form.target_value.trim().length > 0 && form.actor.trim().length > 0;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">
          Quarantine Center
        </h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Preserve evidence while freezing a target for review, optionally
          linked to an incident.
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

      <div className="panel-card space-y-3">
        <h2 className="text-xs font-bold uppercase tracking-wider">
          New quarantine
        </h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Target type
            <select
              className="input-field normal-case tracking-normal"
              value={form.target_type}
              onChange={(e) =>
                setForm((f) => ({ ...f, target_type: e.target.value }))
              }
            >
              {QUARANTINE_TARGET_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Target value
            <input
              className="input-field normal-case tracking-normal"
              placeholder="agent_key / run id / file path…"
              value={form.target_value}
              onChange={(e) =>
                setForm((f) => ({ ...f, target_value: e.target.value }))
              }
            />
          </label>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Actor
            <input
              className="input-field normal-case tracking-normal"
              placeholder="you@team"
              value={form.actor}
              onChange={(e) => setForm((f) => ({ ...f, actor: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
            Incident ID (optional)
            <input
              className="input-field normal-case tracking-normal"
              value={form.incident_id}
              onChange={(e) =>
                setForm((f) => ({ ...f, incident_id: e.target.value }))
              }
            />
          </label>
        </div>
        <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
          Reason
          <textarea
            className="input-field min-h-[56px] resize-y normal-case tracking-normal"
            placeholder="Why is this being quarantined?"
            value={form.reason}
            onChange={(e) => setForm((f) => ({ ...f, reason: e.target.value }))}
          />
        </label>
        <button
          type="button"
          className="btn-primary"
          disabled={!canCreate || createMutation.isPending}
          onClick={() => {
            setFlash(null);
            createMutation.mutate();
          }}
        >
          {createMutation.isPending ? "Recording…" : "Record quarantine"}
        </button>
      </div>

      {isLoading && (
        <p className="text-xs text-[var(--text-muted)]">
          Loading quarantines…
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
              <th className="px-3 py-2 font-medium">Target</th>
              <th className="px-3 py-2 font-medium">Incident</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Actor</th>
              <th className="px-3 py-2 font-medium">Created</th>
              <th className="px-3 py-2 font-medium">Controls</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((q) => (
              <tr
                key={q.id}
                className="border-t border-[var(--border-default)] hover:bg-[var(--interactive-bg-hover)]"
              >
                <td className="px-3 py-2">
                  <div className="font-mono text-[var(--text-primary)]">
                    {q.target_value}
                  </div>
                  <div className="text-[10px] text-[var(--text-muted)]">
                    {q.target_type}
                  </div>
                </td>
                <td className="px-3 py-2 font-mono text-[var(--text-secondary)]">
                  {q.incident_id || "—"}
                </td>
                <td className="px-3 py-2">
                  <span
                    className="inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                    style={pillStyle(quarantineStatusColorVar(q.status))}
                  >
                    {q.status}
                  </span>
                </td>
                <td className="px-3 py-2 text-[var(--text-secondary)]">
                  {q.actor}
                </td>
                <td className="px-3 py-2 whitespace-nowrap text-[var(--text-secondary)]">
                  {formatTime(q.created_at)}
                </td>
                <td className="px-3 py-2">
                  <button
                    type="button"
                    disabled={q.status !== "active"}
                    className="rounded border border-[var(--border-default)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)] hover:bg-[var(--interactive-bg)] disabled:opacity-40"
                    onClick={() => {
                      setFlash(null);
                      setReleasedBy("");
                      setReleasing(q);
                    }}
                  >
                    Release
                  </button>
                </td>
              </tr>
            ))}
            {!isLoading && rows.length === 0 ? (
              <tr>
                <td
                  colSpan={6}
                  className="px-3 py-6 text-center text-[var(--text-muted)]"
                >
                  No quarantines recorded for this tenant.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      {releasing ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--surface-overlay)] p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full max-w-md space-y-3 rounded-[var(--radius-panel)] border border-[var(--border-default)] bg-[var(--surface-modal)] p-4 shadow-[var(--shadow-elevated)]">
            <h2 className="text-sm font-bold uppercase tracking-wider">
              Release quarantine
            </h2>
            <p className="text-xs text-[var(--text-secondary)]">
              <span className="font-mono">{releasing.target_value}</span> (
              {releasing.target_type})
            </p>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
              Released by
              <input
                className="input-field normal-case tracking-normal"
                value={releasedBy}
                onChange={(e) => setReleasedBy(e.target.value)}
              />
            </label>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                className="rounded-md border border-[var(--border-default)] px-3 py-1.5 text-xs"
                onClick={() => setReleasing(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn-primary"
                disabled={!releasedBy.trim() || releaseMutation.isPending}
                onClick={() => releaseMutation.mutate()}
              >
                {releaseMutation.isPending ? "Working…" : "Confirm release"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
