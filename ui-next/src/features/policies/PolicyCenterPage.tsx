import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { pillStyle } from "@/components/security/pill";
import {
  createPolicy,
  deletePolicy,
  listPolicies,
  listPolicyAuditLog,
  policyStatusColorVar,
  rollbackPolicy,
  updatePolicy,
  type PolicyRecord,
} from "@/domains/policies";
import { errorMessage, formatTime } from "@/lib/format";

const EMPTY_FORM = { policy_key: "", name: "", body: "" };

export function PolicyCenterPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editBody, setEditBody] = useState("");
  const [createForm, setCreateForm] = useState(EMPTY_FORM);
  const [flash, setFlash] = useState<{ ok: boolean; message: string } | null>(
    null,
  );

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ["policies", gatewayUrl, bearerToken, activeTenant],
    queryFn: () => listPolicies(apiOpts),
    enabled: tenantReady,
    refetchInterval: 20_000,
    retry: false,
  });

  const auditQuery = useQuery({
    queryKey: ["policy-audit-log", gatewayUrl, activeTenant],
    queryFn: () => listPolicyAuditLog(apiOpts),
    enabled: tenantReady,
    retry: false,
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["policies"] });
    queryClient.invalidateQueries({ queryKey: ["policy-audit-log"] });
  };

  const createMutation = useMutation({
    mutationFn: () =>
      createPolicy(apiOpts, {
        policy_key: createForm.policy_key.trim(),
        name: createForm.name.trim(),
        body: createForm.body,
      }),
    onSuccess: () => {
      setFlash({ ok: true, message: "Policy created." });
      setCreateForm(EMPTY_FORM);
      invalidate();
    },
    onError: (err: unknown) => setFlash({ ok: false, message: errorMessage(err) }),
  });

  const saveMutation = useMutation({
    mutationFn: () => {
      if (!selectedId) throw new Error("No policy selected");
      return updatePolicy(apiOpts, selectedId, { body: editBody });
    },
    onSuccess: () => {
      setFlash({ ok: true, message: "Policy updated (new version)." });
      invalidate();
    },
    onError: (err: unknown) => setFlash({ ok: false, message: errorMessage(err) }),
  });

  const rollbackMutation = useMutation({
    mutationFn: () => {
      if (!selectedId) throw new Error("No policy selected");
      return rollbackPolicy(apiOpts, selectedId);
    },
    onSuccess: (p) => {
      setFlash({ ok: true, message: `Rolled back to version ${p.version}.` });
      setEditBody(p.body);
      invalidate();
    },
    onError: (err: unknown) => setFlash({ ok: false, message: errorMessage(err) }),
  });

  const deleteMutation = useMutation({
    mutationFn: () => {
      if (!selectedId) throw new Error("No policy selected");
      return deletePolicy(apiOpts, selectedId);
    },
    onSuccess: () => {
      setFlash({ ok: true, message: "Policy deleted." });
      setSelectedId(null);
      setEditBody("");
      invalidate();
    },
    onError: (err: unknown) => setFlash({ ok: false, message: errorMessage(err) }),
  });

  if (!tenantReady) return <TenantGate title="Select a tenant for Policies" />;

  const rows = data ?? [];
  const selected = rows.find((p) => p.id === selectedId) ?? null;

  const selectPolicy = (p: PolicyRecord) => {
    setSelectedId(p.id);
    setEditBody(p.body);
    setFlash(null);
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">
          Policy Center
        </h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Cedar policy bodies, versioned edits, rollback, and the change
          audit log.
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
        <p className="text-xs text-[var(--text-muted)]">Loading policies…</p>
      )}
      {error && (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(error)}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <div className="space-y-2">
          {rows.map((p) => (
            <button
              key={p.id}
              type="button"
              onClick={() => selectPolicy(p)}
              className={`panel-card w-full cursor-pointer text-left transition-colors ${
                selectedId === p.id
                  ? "ring-1 ring-[var(--border-active)]"
                  : "hover:bg-[var(--interactive-bg-hover)]"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="truncate text-xs font-semibold text-[var(--text-primary)]">
                    {p.name}
                  </div>
                  <div className="font-mono text-[10px] text-[var(--text-muted)]">
                    {p.policy_key} · v{p.version}
                  </div>
                </div>
                <span
                  className="shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-semibold capitalize"
                  style={pillStyle(policyStatusColorVar(p.status))}
                >
                  {p.status}
                </span>
              </div>
            </button>
          ))}
          {!isLoading && rows.length === 0 ? (
            <div className="panel-card text-xs text-[var(--text-secondary)]">
              No policies for this tenant.
            </div>
          ) : null}

          <div className="panel-card space-y-2">
            <h2 className="text-xs font-bold uppercase tracking-wider">
              New policy
            </h2>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
              Policy key
              <input
                className="input-field normal-case tracking-normal"
                value={createForm.policy_key}
                onChange={(e) =>
                  setCreateForm((f) => ({ ...f, policy_key: e.target.value }))
                }
              />
            </label>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
              Name
              <input
                className="input-field normal-case tracking-normal"
                value={createForm.name}
                onChange={(e) =>
                  setCreateForm((f) => ({ ...f, name: e.target.value }))
                }
              />
            </label>
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
              Cedar body
              <textarea
                className="input-field min-h-[96px] resize-y font-mono normal-case tracking-normal"
                value={createForm.body}
                onChange={(e) =>
                  setCreateForm((f) => ({ ...f, body: e.target.value }))
                }
              />
            </label>
            <button
              type="button"
              className="btn-primary"
              disabled={
                !createForm.policy_key.trim() ||
                !createForm.name.trim() ||
                !createForm.body.trim() ||
                createMutation.isPending
              }
              onClick={() => createMutation.mutate()}
            >
              {createMutation.isPending ? "Creating…" : "Create policy"}
            </button>
          </div>
        </div>

        <div className="panel-card min-h-[200px] space-y-3">
          {!selected ? (
            <p className="text-xs text-[var(--text-muted)]">
              Select a policy to view and edit its body.
            </p>
          ) : (
            <>
              <div className="flex items-center justify-between gap-2">
                <h2 className="text-xs font-bold uppercase tracking-wider">
                  {selected.name}
                </h2>
                <span className="font-mono text-[10px] text-[var(--text-muted)]">
                  v{selected.version}
                </span>
              </div>
              <textarea
                className="input-field min-h-[280px] w-full resize-y font-mono normal-case tracking-normal"
                value={editBody}
                onChange={(e) => setEditBody(e.target.value)}
              />
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className="btn-primary"
                  disabled={saveMutation.isPending || editBody === selected.body}
                  onClick={() => saveMutation.mutate()}
                >
                  {saveMutation.isPending ? "Saving…" : "Save (new version)"}
                </button>
                <button
                  type="button"
                  className="rounded-md border border-[var(--border-default)] px-3 py-1.5 text-xs disabled:opacity-40"
                  disabled={rollbackMutation.isPending}
                  onClick={() => rollbackMutation.mutate()}
                >
                  {rollbackMutation.isPending
                    ? "Rolling back…"
                    : "Rollback to previous version"}
                </button>
                <button
                  type="button"
                  className="rounded-md border border-[var(--border-default)] px-3 py-1.5 text-xs text-[var(--sev-high)] disabled:opacity-40"
                  disabled={deleteMutation.isPending}
                  onClick={() => {
                    if (
                      window.confirm(
                        `Delete policy "${selected.name}"? This cannot be undone.`,
                      )
                    ) {
                      deleteMutation.mutate();
                    }
                  }}
                >
                  {deleteMutation.isPending ? "Deleting…" : "Delete"}
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      <div className="panel-card space-y-2">
        <h2 className="text-xs font-bold uppercase tracking-wider">
          Change audit log
        </h2>
        {auditQuery.isLoading ? (
          <p className="text-xs text-[var(--text-muted)]">Loading…</p>
        ) : auditQuery.error ? (
          <p className="text-xs text-[var(--sev-high)]">
            {errorMessage(auditQuery.error)}
          </p>
        ) : (auditQuery.data ?? []).length === 0 ? (
          <p className="text-xs text-[var(--text-muted)]">
            No policy changes recorded yet.
          </p>
        ) : (
          <ul className="space-y-1 text-[11px]">
            {(auditQuery.data ?? []).map((entry) => (
              <li
                key={entry.id}
                className="flex items-center justify-between gap-2 border-t border-[var(--border-default)] pt-1 first:border-t-0 first:pt-0"
              >
                <span className="font-mono text-[var(--text-secondary)]">
                  {entry.policy_key || entry.policy_id} · {entry.action}
                </span>
                <span className="text-[10px] text-[var(--text-muted)]">
                  {entry.actor ? `${entry.actor} · ` : ""}
                  {formatTime(entry.created_at)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
