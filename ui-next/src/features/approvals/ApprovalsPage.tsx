import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Edit3, X } from "lucide-react";
import { useAppStore } from "@/app/store";
import { TenantGate } from "@/components/TenantGate";
import { HashChip } from "@/components/security/HashChip";
import { TrustBadge } from "@/components/security/TrustBadge";
import {
  actionLabel,
  approvalActionDisabledReason,
  approvalId,
  approveApproval,
  currentToolCall,
  editApproval,
  effectiveActionHash,
  listApprovals,
  parseEditedToolCall,
  rejectApproval,
  type ApprovalRecord,
  type AuthorizeToolCall,
} from "@/domains/approvals";
import { errorMessage } from "@/lib/format";

type PendingAction =
  | { kind: "approve"; approval: ApprovalRecord }
  | { kind: "reject"; approval: ApprovalRecord }
  | {
      kind: "edit";
      approval: ApprovalRecord;
      editedToolCall: AuthorizeToolCall;
    };

export function ApprovalsPage() {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const operatorId = useAppStore((s) => s.operatorId);
  const tenantReady = Boolean(activeTenant.trim());
  const apiOpts = {
    gatewayUrl,
    bearerToken,
    tenantId: activeTenant,
  };
  const queryClient = useQueryClient();

  const [selected, setSelected] = useState<PendingAction | null>(null);
  const [reason, setReason] = useState("");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editParamsJson, setEditParamsJson] = useState("");
  const [editError, setEditError] = useState<string | null>(null);
  const [flash, setFlash] = useState<{ ok: boolean; message: string } | null>(
    null,
  );

  const { data, error, isLoading, isFetching } = useQuery({
    queryKey: ["approvals", gatewayUrl, bearerToken, activeTenant],
    queryFn: () => listApprovals(apiOpts),
    enabled: tenantReady,
    refetchInterval: 10_000,
    retry: false,
  });

  const canAct = Boolean(operatorId.trim());

  const mutation = useMutation({
    mutationFn: async () => {
      if (!selected) throw new Error("No approval selected");
      const id = approvalId(selected.approval);
      const op = operatorId.trim();
      if (!op) throw new Error("Operator ID required");
      if (!reason.trim()) throw new Error("Audit reason required");
      if (selected.kind === "approve") {
        return approveApproval(apiOpts, id, op, reason.trim());
      }
      if (selected.kind === "reject") {
        return rejectApproval(apiOpts, id, op, reason.trim());
      }
      return editApproval(
        apiOpts,
        id,
        op,
        selected.editedToolCall,
        reason.trim(),
      );
    },
    onSuccess: () => {
      const messages = {
        approve: "Approval recorded and bound to the frozen action hash.",
        reject: "Action rejected; decision recorded for audit.",
        edit: "Edited action submitted. Gateway re-hashed and re-evaluated policy.",
      } as const;
      setFlash({
        ok: true,
        message: selected ? messages[selected.kind] : "Done.",
      });
      setSelected(null);
      setReason("");
      setEditingId(null);
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
    },
    onError: (err: unknown) => {
      setFlash({ ok: false, message: errorMessage(err) });
    },
  });

  if (!tenantReady) {
    return <TenantGate title="Select a tenant for Approvals" />;
  }

  const rows = data ?? [];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-sm font-bold uppercase tracking-wider">
          Approvals
        </h1>
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Human-in-the-loop queue. Approve / Reject / Edit re-hash bind to{" "}
          <span className="font-mono">action_hash</span>
          {isFetching ? " · refreshing…" : null}
        </p>
      </div>

      {!canAct ? (
        <p className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-3 py-2 text-[11px] text-[var(--text-secondary)]">
          Read-only: set an <strong>Operator ID</strong> in Settings to act. The
          gateway also enforces identity server-side.
        </p>
      ) : null}

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
        <p className="text-xs text-[var(--text-muted)]">Loading queue…</p>
      )}
      {error && (
        <div className="panel-card text-xs text-[var(--sev-high)]">
          {errorMessage(error)}
        </div>
      )}

      {!isLoading && !error && rows.length === 0 ? (
        <div className="panel-card text-xs text-[var(--text-secondary)]">
          No pending approvals for this tenant.
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        {rows.map((a) => {
          const id = approvalId(a);
          const disabled = approvalActionDisabledReason(a, {
            busy: mutation.isPending,
            canAct,
            denyReason: "Set Operator ID in Settings",
          });
          const hash = effectiveActionHash(a);
          const call = currentToolCall(a);
          const isEditing = editingId === id;

          return (
            <article key={id || Math.random()} className="panel-card space-y-3">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="text-xs font-semibold text-[var(--text-primary)]">
                    {actionLabel(a)}
                    {a.is_edited ? (
                      <span className="ml-2 text-[10px] text-[var(--decision-approval)]">
                        edited
                      </span>
                    ) : null}
                  </div>
                  <div className="mt-1 font-mono text-[10px] text-[var(--text-muted)]">
                    {id || "missing-id"}
                  </div>
                </div>
                <TrustBadge trust={a.source_trust ?? a.root_trust_level} />
              </div>

              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px]">
                <dt className="text-[var(--text-muted)]">Agent</dt>
                <dd className="font-mono text-[var(--text-secondary)]">
                  {a.agent_id ?? "—"}
                </dd>
                <dt className="text-[var(--text-muted)]">Status</dt>
                <dd className="text-[var(--text-secondary)]">
                  {a.status ?? "pending"}
                </dd>
                <dt className="text-[var(--text-muted)]">Action hash</dt>
                <dd>
                  <HashChip hash={hash} kind="action" />
                </dd>
              </dl>

              {isEditing ? (
                <div className="space-y-2">
                  <label className="text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
                    Parameters JSON (tool/action frozen; gateway re-hashes)
                    <textarea
                      className="input-field mt-1 min-h-[120px] resize-y font-mono normal-case tracking-normal"
                      value={editParamsJson}
                      onChange={(e) => {
                        setEditParamsJson(e.target.value);
                        setEditError(null);
                      }}
                    />
                  </label>
                  {editError ? (
                    <p className="text-[11px] text-[var(--state-failed)]">
                      {editError}
                    </p>
                  ) : null}
                  <div className="flex gap-2">
                    <button
                      type="button"
                      className="btn-primary"
                      disabled={Boolean(disabled)}
                      onClick={() => {
                        const parsed = parseEditedToolCall(a, editParamsJson);
                        if (!parsed.ok) {
                          setEditError(parsed.error);
                          return;
                        }
                        setFlash(null);
                        setReason("");
                        setSelected({
                          kind: "edit",
                          approval: a,
                          editedToolCall: parsed.editedToolCall,
                        });
                      }}
                    >
                      Review edit…
                    </button>
                    <button
                      type="button"
                      className="rounded-md border border-[var(--border-default)] px-2 py-1 text-[11px]"
                      onClick={() => setEditingId(null)}
                    >
                      Cancel edit
                    </button>
                  </div>
                </div>
              ) : call ? (
                <pre className="max-h-36 overflow-auto rounded border border-[var(--border-default)] bg-[var(--surface-app)] p-2 font-mono text-[10px] text-[var(--text-secondary)]">
                  {JSON.stringify(call, null, 2)}
                </pre>
              ) : null}

              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={Boolean(disabled) || mutation.isPending}
                  title={disabled}
                  className="inline-flex items-center gap-1 rounded-md bg-[var(--decision-allow)] px-2.5 py-1.5 text-[11px] font-semibold text-white disabled:opacity-40"
                  onClick={() => {
                    setFlash(null);
                    setReason("");
                    setSelected({ kind: "approve", approval: a });
                  }}
                >
                  <Check size={12} /> Approve
                </button>
                <button
                  type="button"
                  disabled={Boolean(disabled) || mutation.isPending}
                  title={disabled}
                  className="inline-flex items-center gap-1 rounded-md bg-[var(--decision-deny)] px-2.5 py-1.5 text-[11px] font-semibold text-white disabled:opacity-40"
                  onClick={() => {
                    setFlash(null);
                    setReason("");
                    setSelected({ kind: "reject", approval: a });
                  }}
                >
                  <X size={12} /> Reject
                </button>
                <button
                  type="button"
                  disabled={
                    Boolean(disabled) ||
                    mutation.isPending ||
                    !currentToolCall(a)
                  }
                  title={
                    disabled ??
                    (!currentToolCall(a)
                      ? "Frozen tool call unavailable"
                      : "Edit parameters")
                  }
                  className="inline-flex items-center gap-1 rounded-md border border-[var(--border-default)] px-2.5 py-1.5 text-[11px] font-semibold text-[var(--text-primary)] disabled:opacity-40"
                  onClick={() => {
                    setEditingId(id);
                    setEditParamsJson(
                      JSON.stringify(
                        currentToolCall(a)?.parameters ?? {},
                        null,
                        2,
                      ),
                    );
                    setEditError(null);
                  }}
                >
                  <Edit3 size={12} /> Edit
                </button>
              </div>
            </article>
          );
        })}
      </div>

      {selected ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--surface-overlay)] p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="approval-confirm-title"
        >
          <div className="w-full max-w-md space-y-3 rounded-[var(--radius-panel)] border border-[var(--border-default)] bg-[var(--surface-modal)] p-4 shadow-[var(--shadow-elevated)]">
            <h2
              id="approval-confirm-title"
              className="text-sm font-bold uppercase tracking-wider"
            >
              Confirm {selected.kind}
            </h2>
            <p className="text-xs text-[var(--text-secondary)]">
              {selected.kind === "approve"
                ? "Binds your identity to the frozen action hash."
                : selected.kind === "reject"
                  ? "Rejects the pending action and writes an audit decision."
                  : "Submits edited parameters; gateway re-hashes and re-evaluates (fail-closed on policy deny)."}
            </p>
            <div className="text-[11px]">
              <div className="text-[var(--text-muted)]">Target</div>
              <div className="font-mono text-[var(--text-primary)]">
                {actionLabel(selected.approval)}
              </div>
              <div className="mt-1">
                <HashChip
                  hash={effectiveActionHash(selected.approval)}
                  kind="action"
                />
              </div>
            </div>
            {selected.kind === "edit" ? (
              <pre className="max-h-28 overflow-auto rounded border border-[var(--border-default)] bg-[var(--surface-app)] p-2 font-mono text-[10px]">
                {JSON.stringify(selected.editedToolCall.parameters, null, 2)}
              </pre>
            ) : null}
            <label className="flex flex-col gap-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">
              Audit reason (required)
              <textarea
                className="input-field min-h-[72px] resize-y normal-case tracking-normal"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Why are you taking this action?"
              />
            </label>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                className="rounded-md border border-[var(--border-default)] px-3 py-1.5 text-xs text-[var(--text-secondary)]"
                onClick={() => setSelected(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn-primary"
                disabled={!reason.trim() || mutation.isPending}
                onClick={() => mutation.mutate()}
              >
                {mutation.isPending ? "Submitting…" : "Confirm"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
