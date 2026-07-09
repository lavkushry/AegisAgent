import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, X } from "lucide-react";
import { useAppStore } from "@/app/store";
import { HashChip } from "@/components/security/HashChip";
import { TrustBadge } from "@/components/security/TrustBadge";
import {
  actionLabel,
  approvalActionDisabledReason,
  approvalId,
  approveApproval,
  currentToolCall,
  effectiveActionHash,
  rejectApproval,
  type ApprovalRecord,
} from "@/domains/approvals";
import { frameRows } from "@/datasources/frame";
import { errorMessage } from "@/lib/format";
import { redactJsonForDisplay } from "@/lib/redact";
import type { PanelProps } from "../types";

export interface ApprovalCardOptions {
  /** Max cards to render (default: 6). */
  maxCards?: number;
  /** When false, hide Approve/Reject controls (display-only template). Default true. */
  interactive?: boolean;
}

function rowToApproval(row: Record<string, unknown>): ApprovalRecord {
  return row as unknown as ApprovalRecord;
}

function parametersPreview(approval: ApprovalRecord): string {
  const call = currentToolCall(approval);
  if (!call) return "—";
  try {
    return redactJsonForDisplay(call.parameters, 2);
  } catch {
    return "[unreadable parameters]";
  }
}

/**
 * ★ Differentiator panel — frozen action bound to action_hash.
 *
 * Renders gateway approval rows as HITL cards (trust, hash, redacted params).
 * Approve/Reject use the same domain helpers as ApprovalsPage; Edit stays on
 * the dedicated Approvals page (re-hash + re-evaluate is higher-friction).
 */
export default function ApprovalCardPanel(
  props: PanelProps<ApprovalCardOptions>,
) {
  const maxCards = props.definition.options?.maxCards ?? 6;
  const interactive = props.definition.options?.interactive !== false;
  const rows = frameRows(props.data)
    .slice(0, maxCards)
    .map(rowToApproval);

  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const activeTenant = useAppStore((s) => s.activeTenant);
  const operatorId = useAppStore((s) => s.operatorId);
  const queryClient = useQueryClient();

  const [pending, setPending] = useState<{
    id: string;
    kind: "approve" | "reject";
  } | null>(null);
  const [reason, setReason] = useState("");
  const [flash, setFlash] = useState<{ ok: boolean; message: string } | null>(
    null,
  );

  const apiOpts = {
    gatewayUrl,
    bearerToken,
    tenantId: activeTenant,
  };
  const canAct = Boolean(operatorId.trim());

  const mutation = useMutation({
    mutationFn: async () => {
      if (!pending) throw new Error("No approval selected");
      const op = operatorId.trim();
      if (!op) throw new Error("Operator ID required");
      if (!reason.trim()) throw new Error("Audit reason required");
      if (pending.kind === "approve") {
        return approveApproval(apiOpts, pending.id, op, reason.trim());
      }
      return rejectApproval(apiOpts, pending.id, op, reason.trim());
    },
    onSuccess: () => {
      setFlash({
        ok: true,
        message:
          pending?.kind === "approve"
            ? "Approval recorded and bound to the frozen action hash."
            : "Action rejected; decision recorded for audit.",
      });
      setPending(null);
      setReason("");
      // Refresh panel queries + dedicated Approvals page cache.
      void queryClient.invalidateQueries({ queryKey: ["panel"] });
      void queryClient.invalidateQueries({ queryKey: ["approvals"] });
    },
    onError: (err: unknown) => {
      setFlash({ ok: false, message: errorMessage(err) });
    },
  });

  if (rows.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-xs text-[var(--text-muted)]">
        No pending approvals
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col gap-2 overflow-auto pr-1">
      {flash ? (
        <p
          role="status"
          className={`rounded border px-2 py-1 text-[10px] ${
            flash.ok
              ? "border-emerald-500/30 text-[var(--state-verified)]"
              : "border-rose-500/30 text-[var(--state-failed)]"
          }`}
        >
          {flash.message}
        </p>
      ) : null}

      {interactive && !canAct ? (
        <p className="text-[10px] text-[var(--text-muted)]">
          Read-only: set Operator ID in Settings to approve or reject.
        </p>
      ) : null}

      {rows.map((approval) => {
        const id = approvalId(approval);
        const hash = effectiveActionHash(approval);
        const disabled = approvalActionDisabledReason(approval, {
          busy: mutation.isPending,
          canAct,
          denyReason: "Set Operator ID in Settings",
        });
        const isPendingThis = pending?.id === id;

        return (
          <article
            key={id || actionLabel(approval)}
            className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] p-2 space-y-2"
            data-testid="approval-card"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="truncate text-xs font-semibold text-[var(--text-primary)]">
                  {actionLabel(approval)}
                  {approval.is_edited ? (
                    <span className="ml-1 text-[10px] text-[var(--decision-approval)]">
                      edited
                    </span>
                  ) : null}
                </div>
                <div className="mt-0.5 truncate font-mono text-[10px] text-[var(--text-muted)]">
                  {id || "missing-id"}
                </div>
              </div>
              <TrustBadge
                trust={approval.source_trust ?? approval.root_trust_level}
              />
            </div>

            <dl className="grid grid-cols-[auto_1fr] gap-x-2 gap-y-0.5 text-[10px]">
              <dt className="text-[var(--text-muted)]">Agent</dt>
              <dd className="truncate font-mono text-[var(--text-secondary)]">
                {approval.agent_id ?? "—"}
              </dd>
              <dt className="text-[var(--text-muted)]">Status</dt>
              <dd className="text-[var(--text-secondary)]">
                {approval.status ?? "pending"}
              </dd>
              <dt className="text-[var(--text-muted)]">Action hash</dt>
              <dd>
                <HashChip hash={hash} kind="action" />
              </dd>
            </dl>

            <pre className="max-h-16 overflow-auto rounded bg-[var(--surface-elevated)] p-1.5 font-mono text-[9px] text-[var(--text-secondary)] custom-scrollbar">
              {parametersPreview(approval)}
            </pre>

            {interactive ? (
              isPendingThis ? (
                <div className="space-y-1.5">
                  <label className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)]">
                    Audit reason
                    <input
                      className="input-field mt-0.5 w-full normal-case tracking-normal"
                      value={reason}
                      onChange={(e) => setReason(e.target.value)}
                      placeholder="Why this decision?"
                      autoFocus
                    />
                  </label>
                  <div className="flex flex-wrap gap-1.5">
                    <button
                      type="button"
                      className="btn-primary text-[10px]"
                      disabled={
                        mutation.isPending || !reason.trim() || Boolean(disabled)
                      }
                      onClick={() => mutation.mutate()}
                    >
                      Confirm {pending.kind}
                    </button>
                    <button
                      type="button"
                      className="rounded border border-[var(--border-default)] px-2 py-0.5 text-[10px]"
                      disabled={mutation.isPending}
                      onClick={() => {
                        setPending(null);
                        setReason("");
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  <button
                    type="button"
                    className="inline-flex items-center gap-1 rounded bg-emerald-600/20 px-2 py-0.5 text-[10px] text-emerald-400 disabled:opacity-40"
                    disabled={Boolean(disabled)}
                    title={disabled}
                    onClick={() => {
                      setFlash(null);
                      setReason("");
                      setPending({ id, kind: "approve" });
                    }}
                  >
                    <Check className="h-3 w-3" aria-hidden />
                    Approve
                  </button>
                  <button
                    type="button"
                    className="inline-flex items-center gap-1 rounded bg-rose-600/20 px-2 py-0.5 text-[10px] text-rose-400 disabled:opacity-40"
                    disabled={Boolean(disabled)}
                    title={disabled}
                    onClick={() => {
                      setFlash(null);
                      setReason("");
                      setPending({ id, kind: "reject" });
                    }}
                  >
                    <X className="h-3 w-3" aria-hidden />
                    Reject
                  </button>
                  {props.definition.drilldowns?.[0] ? (
                    <button
                      type="button"
                      className="rounded border border-[var(--border-default)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)]"
                      onClick={() =>
                        props.onDrilldown(
                          props.definition.drilldowns![0],
                          approval as unknown as Record<string, unknown>,
                        )
                      }
                    >
                      {props.definition.drilldowns[0].label}
                    </button>
                  ) : null}
                </div>
              )
            ) : null}
          </article>
        );
      })}
    </div>
  );
}
