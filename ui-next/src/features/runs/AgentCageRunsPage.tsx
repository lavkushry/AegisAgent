import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { pillStyle } from "@/components/security/pill";
import {
  AGENT_RUNS_PAGE_SIZE,
  controlAgentRun,
  listAgentRuns,
  runControlDisabledReason,
  runStatusColorVar,
  type AgentRunRecord,
  type RunControlKind,
} from "@/domains/agentRuns";
import { errorMessage, formatTime } from "@/lib/format";

export function AgentCageRunsPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const [pending, setPending] = useState<{
    kind: RunControlKind;
    run: AgentRunRecord;
  } | null>(null);
  const [actor, setActor] = useState("");
  const [reason, setReason] = useState("");
  const [flash, setFlash] = useState<{ ok: boolean; message: string } | null>(
    null,
  );
  const [page, setPage] = useState(0);

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ["agent-runs", gatewayUrl, bearerToken, activeTenant, page],
    queryFn: () =>
      listAgentRuns(apiOpts, AGENT_RUNS_PAGE_SIZE, page * AGENT_RUNS_PAGE_SIZE),
    enabled: tenantReady,
    refetchInterval: 8_000,
    retry: false,
  });

  const mutation = useMutation({
    mutationFn: () => {
      if (!pending) throw new Error("No run selected");
      return controlAgentRun(
        apiOpts,
        pending.run.id,
        pending.kind,
        actor.trim(),
        reason,
      );
    },
    onSuccess: () => {
      setFlash({ ok: true, message: `Run ${pending?.kind} command issued.` });
      setPending(null);
      setActor("");
      setReason("");
      queryClient.invalidateQueries({ queryKey: ["agent-runs"] });
    },
    onError: (err: unknown) => setFlash({ ok: false, message: errorMessage(err) }),
  });

  if (!tenantReady)
    return <TenantGate title="Select a tenant for Agent Cage Runs" />;

  const rows = data ?? [];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">
          Agent Cage Runs
        </h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Controlled agent runs and signed control commands (pause / resume /
          kill / quarantine).
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
        <p className="text-xs text-[var(--text-muted)]">Loading runs…</p>
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
              <th className="px-3 py-2 font-medium">Run</th>
              <th className="px-3 py-2 font-medium">Source</th>
              <th className="px-3 py-2 font-medium">Mode</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium">Started</th>
              <th className="px-3 py-2 font-medium">Controls</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr
                key={r.id}
                className="border-t border-[var(--border-default)] hover:bg-[var(--interactive-bg-hover)]"
              >
                <td className="px-3 py-2">
                  <Link
                    to={`/runs/${encodeURIComponent(r.id)}`}
                    className="font-medium text-[var(--text-primary)] hover:text-[var(--brand)] hover:underline"
                  >
                    {r.run_key}
                  </Link>
                  <div className="font-mono text-[10px] text-[var(--text-muted)]">
                    {r.id}
                  </div>
                </td>
                <td className="px-3 py-2 text-[var(--text-secondary)]">
                  {r.source_component}
                </td>
                <td className="px-3 py-2 text-[var(--text-secondary)]">
                  {r.mode}
                </td>
                <td className="px-3 py-2">
                  <span
                    className="inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                    style={pillStyle(runStatusColorVar(r.status))}
                  >
                    {r.status}
                  </span>
                </td>
                <td className="px-3 py-2 whitespace-nowrap text-[var(--text-secondary)]">
                  {formatTime(r.started_at)}
                </td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-1">
                    {(
                      [
                        "pause",
                        "resume",
                        "kill",
                        "quarantine",
                      ] as RunControlKind[]
                    ).map((kind) => {
                      const disabled = runControlDisabledReason(kind, r.status);
                      return (
                        <button
                          key={kind}
                          type="button"
                          disabled={Boolean(disabled) || mutation.isPending}
                          title={disabled ?? kind}
                          className="rounded border border-[var(--border-default)] px-1.5 py-0.5 text-[10px] capitalize text-[var(--text-secondary)] hover:bg-[var(--interactive-bg)] disabled:opacity-40"
                          onClick={() => {
                            setFlash(null);
                            setActor("");
                            setReason("");
                            setPending({ kind, run: r });
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
                  No agent-cage runs registered for this tenant.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-[11px] text-[var(--text-muted)]">
        <span>Page {page + 1}</span>
        <div className="flex gap-2">
          <button
            type="button"
            className="rounded border border-[var(--border-default)] px-2 py-1 disabled:opacity-40"
            disabled={page === 0 || isFetching}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
          >
            Previous
          </button>
          <button
            type="button"
            className="rounded border border-[var(--border-default)] px-2 py-1 disabled:opacity-40"
            disabled={rows.length < AGENT_RUNS_PAGE_SIZE || isFetching}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </button>
        </div>
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
              <span className="font-mono">{pending.run.run_key}</span>
            </p>
            {pending.kind === "kill" ? (
              <p className="text-[11px] text-[var(--sev-high)]">
                Issues a signed kill command to the sensor/cage-runner.
              </p>
            ) : null}
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
              Actor
              <input
                className="input-field normal-case tracking-normal"
                placeholder="you@team"
                value={actor}
                onChange={(e) => setActor(e.target.value)}
              />
            </label>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
              Reason (optional)
              <textarea
                className="input-field min-h-[56px] resize-y normal-case tracking-normal"
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
                disabled={!actor.trim() || mutation.isPending}
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
