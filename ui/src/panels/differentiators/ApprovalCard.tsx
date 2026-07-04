"use client";

import React, { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, X, Edit3, Save, ArrowUpRight } from "lucide-react";
import { useAppStore, canApprove } from "@/app/store";
import { useEffectiveRole } from "@/hooks/useSessionRole";
import { approveApproval, editApproval, rejectApproval, type AuthorizeToolCall } from "@/app/api";
import { frameRows } from "@/datasources/frame";
import { errorMessage } from "@/lib/format";
import TrustBadge from "@/components/security/TrustBadge";
import HashChip from "@/components/security/HashChip";
import { ConfirmDialog } from "@/components/primitives";
import type { PanelProps } from "../types";
import {
  actionLabel,
  approvalActionDisabledReason,
  approvalConfirmationTarget,
  approvalId,
  approvalMetadataRows,
  canonicalActionBytes,
  currentToolCall,
  editDisabledReason,
  effectiveActionHash,
  parseEditedToolCall,
  type ApprovalRow,
} from "./approvalCardModel";

type PendingAction =
  | { kind: "approve"; approval: ApprovalRow }
  | { kind: "reject"; approval: ApprovalRow }
  | { kind: "edit"; approval: ApprovalRow; editedToolCall: AuthorizeToolCall };

/**
 * The Approval Queue panel — the human-in-the-loop control made visible.
 * Renders the frozen canonical action (the exact bytes that will run), its
 * action_hash, and source trust; Approve / Reject / Edit (re-hash +
 * re-evaluate). The differentiator surface Grafana/Kibana cannot show.
 */
export default function ApprovalCard({ data }: PanelProps) {
  const { gatewayUrl, bearerToken, activeTenant } = useAppStore();
  const { role, operatorId } = useEffectiveRole();
  const canAct = canApprove(role) && Boolean(operatorId);
  const denyReason = canApprove(role)
    ? operatorId ? undefined : "Authenticated session did not provide an operator identity"
    : "Requires the approver or admin role (separation of duties)";
  const apiOpts = { gatewayUrl, bearerToken, tenantId: activeTenant };
  const queryClient = useQueryClient();

  const [editingId, setEditingId] = useState<string | null>(null);
  const [editParamsJson, setEditParamsJson] = useState("");
  const [editError, setEditError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<PendingAction | null>(null);
  const [auditReason, setAuditReason] = useState("");
  const [actionResult, setActionResult] = useState<{ ok: boolean; message: string } | null>(null);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["panel"] });
    queryClient.invalidateQueries({ queryKey: ["approvals"] });
    queryClient.invalidateQueries({ queryKey: ["socSummary"] });
  };

  const onActionSuccess = (message: string) => {
    setPendingAction(null);
    setAuditReason("");
    setEditingId(null);
    setActionResult({ ok: true, message });
    invalidate();
  };
  const onActionError = (error: unknown) => {
    setActionResult({ ok: false, message: errorMessage(error) });
  };

  const approveMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      approveApproval(apiOpts, id, operatorId!, reason),
    onSuccess: () => onActionSuccess("Approval recorded and bound to the frozen action hash."),
    onError: onActionError,
  });
  const rejectMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      rejectApproval(apiOpts, id, operatorId!, reason),
    onSuccess: () => onActionSuccess("Action rejected and the decision was recorded for audit."),
    onError: onActionError,
  });
  const editMutation = useMutation({
    mutationFn: ({ id, editedToolCall, reason }: { id: string; editedToolCall: AuthorizeToolCall; reason: string }) =>
      editApproval(apiOpts, id, operatorId!, editedToolCall, reason),
    onSuccess: () => onActionSuccess("Edited action submitted. The gateway computed a new hash and re-evaluated policy."),
    onError: onActionError,
  });

  const startEditing = (a: ApprovalRow) => {
    setEditingId(approvalId(a));
    setEditParamsJson(JSON.stringify(currentToolCall(a)?.parameters ?? {}, null, 2));
    setEditError(null);
  };

  const requestEdit = (a: ApprovalRow) => {
    const parsed = parseEditedToolCall(a, editParamsJson);
    if (!parsed.ok) {
      setEditError(parsed.error);
      return;
    }
    setAuditReason("");
    setPendingAction({ kind: "edit", approval: a, editedToolCall: parsed.editedToolCall });
  };

  const requestDecision = (kind: "approve" | "reject", approval: ApprovalRow) => {
    setAuditReason("");
    setActionResult(null);
    setPendingAction({ kind, approval });
  };

  const confirmAction = () => {
    if (!pendingAction || !auditReason.trim()) return;
    const id = approvalId(pendingAction.approval);
    if (pendingAction.kind === "approve") approveMutation.mutate({ id, reason: auditReason.trim() });
    else if (pendingAction.kind === "reject") rejectMutation.mutate({ id, reason: auditReason.trim() });
    else editMutation.mutate({ id, editedToolCall: pendingAction.editedToolCall, reason: auditReason.trim() });
  };

  const approvals = frameRows(data) as ApprovalRow[];

  return (
    <div className="flex flex-col h-full">
      {!canAct ? (
        <p
          className="text-[11px] mb-2 px-2 py-1 rounded border"
          style={{
            color: "var(--text-secondary)",
            borderColor: "var(--border-default)",
            backgroundColor: "var(--surface-app)",
          }}
        >
          Read-only as <strong>{role}</strong>: {denyReason}. The gateway also enforces this server-side.
        </p>
      ) : null}
      {actionResult ? (
        <p className={`mb-2 rounded border px-2 py-1 text-[11px] ${actionResult.ok ? "border-emerald-500/30 text-[var(--state-verified)]" : "border-rose-500/30 text-[var(--state-failed)]"}`} role="status">
          {actionResult.message}
        </p>
      ) : null}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 overflow-auto custom-scrollbar flex-1 pr-1">
        {approvals.map((a) => {
        const id = approvalId(a);
        const isEditing = editingId === id;
        const busy = approveMutation.isPending || rejectMutation.isPending || editMutation.isPending;
        const actionContext = { busy, canAct, denyReason };
        const actionTitle = approvalActionDisabledReason(a, actionContext);
        const actionDisabled = Boolean(actionTitle);
        const editTitle = editDisabledReason(a, actionContext);
        const editDisabled = Boolean(editTitle);
        const metadataRows = approvalMetadataRows(a);
        return (
          <div
            key={id}
            className="bg-[var(--surface-app)]/40 border border-[var(--border-default)] rounded-xl p-4 space-y-3 flex flex-col"
          >
            <div className="flex justify-between items-start gap-3">
              <div>
                <span className="text-[9px] text-[var(--state-pending)] uppercase tracking-wider font-extrabold block">
                  Action authorization request
                </span>
                <h4 className="font-bold text-sm font-mono mt-0.5 text-[var(--brand)]">
                  {actionLabel(a)}
                </h4>
              </div>
              <span className="text-[10px] text-[var(--text-muted)] font-mono whitespace-nowrap">
                expires {a.expires_in ?? a.expires_at ?? "N/A"}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[11px] py-2 border-y border-[var(--border-default)]">
              {metadataRows.map((row) => (
                <div key={row.label} className={row.label === "Policy reason" || row.label === "Policies" ? "col-span-2" : undefined}>
                  <span className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)]">{row.label}</span>
                  {row.kind === "trust" ? (
                    <div className="mt-0.5"><TrustBadge trust={row.value} /></div>
                  ) : row.monospace ? (
                    <code className="text-[var(--text-primary)] font-mono break-all">{row.value}</code>
                  ) : (
                    <span className="text-[var(--text-primary)]">{row.value}</span>
                  )}
                </div>
              ))}
            </div>

            {editDisabled && !actionDisabled ? (
              <div className="rounded border border-[var(--border-default)] bg-[var(--surface-app)] px-2 py-1 text-[10px] text-[var(--text-muted)]">
                Edit disabled: {editTitle}.
              </div>
            ) : null}

            <div className="text-[10px]">
              <span className="block uppercase tracking-wider text-[var(--text-muted)] font-semibold text-[9px] mb-1">
                {a.is_edited ? "Effective action hash (edited + re-evaluated)" : "Action hash (frozen — you approve exactly these bytes)"}
              </span>
              <HashChip hash={effectiveActionHash(a)} kind="action" head={20} tail={8} />
              {a.is_edited && a.original_action_hash ? (
                <div className="mt-1 flex items-center gap-2 text-[9px] text-[var(--text-muted)]">
                  <span>Original</span>
                  <HashChip hash={a.original_action_hash} kind="action" head={12} tail={6} />
                </div>
              ) : null}
            </div>

            <div className="space-y-1 flex-1">
              <span className="block uppercase tracking-wider text-[var(--text-muted)] font-semibold text-[9px]">
                Canonical action bytes · aegis-jcs-1
              </span>
              {isEditing ? (
                <textarea
                  value={editParamsJson}
                  onChange={(e) => setEditParamsJson(e.target.value)}
                  rows={6}
                  className="w-full bg-[var(--surface-app)] border border-[var(--border-default)] rounded-lg p-2 font-mono text-xs text-[var(--brand)] focus:outline-none focus:border-[var(--border-active)]"
                />
              ) : (
                <pre className="bg-[var(--surface-app)] border border-[var(--border-default)] rounded-lg p-2.5 text-[11px] text-[var(--brand)] font-mono overflow-auto max-h-32 custom-scrollbar whitespace-pre-wrap break-all">
                  {canonicalActionBytes(a) ?? "Unavailable from gateway"}
                </pre>
              )}
              {isEditing ? (
                <p className="text-[10px] text-[var(--state-pending)]">
                  Editing re-hashes and re-evaluates — you will be approving the new bytes.
                </p>
              ) : null}
              {editError && isEditing ? (
                <p className="text-[10px] text-[var(--state-failed)]">{editError}</p>
              ) : null}
            </div>

            <div className="flex gap-2 pt-3 border-t border-[var(--border-default)]">
              {isEditing ? (
                <>
                  <button
                    onClick={() => requestEdit(a)}
                    disabled={actionDisabled}
                    title={actionTitle}
                    className="flex-1 flex items-center justify-center gap-1.5 bg-[var(--brand)] hover:bg-[var(--brand-emphasis)] text-[var(--text-on-brand)] font-medium text-xs rounded-lg py-1.5 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Save size={13} /> Save &amp; re-evaluate
                  </button>
                  <button
                    onClick={() => setEditingId(null)}
                    className="bg-[var(--interactive-bg)] hover:bg-[var(--interactive-bg-hover)] text-[var(--text-primary)] text-xs rounded-lg px-3 py-1.5 cursor-pointer border border-[var(--border-default)]"
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <>
                  <button
                    onClick={() => requestDecision("approve", a)}
                    disabled={actionDisabled}
                    title={actionTitle}
                    className="flex-1 flex items-center justify-center gap-1 text-[var(--text-on-brand)] font-medium text-xs rounded-lg py-1.5 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{ backgroundColor: "var(--decision-allow)" }}
                  >
                    <Check size={13} /> Approve
                  </button>
                  <button
                    onClick={() => startEditing(a)}
                    disabled={editDisabled}
                    title={editTitle ?? "Edit parameters (re-hash + re-evaluate)"}
                    className="bg-[var(--interactive-bg)] hover:bg-[var(--interactive-bg-hover)] text-[var(--text-primary)] border border-[var(--border-default)] text-xs rounded-lg px-2.5 py-1.5 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Edit3 size={13} />
                  </button>
                  <button
                    disabled
                    title="Escalation routing not configured"
                    className="bg-[var(--interactive-bg)] text-[var(--text-muted)] border border-[var(--border-default)] text-xs rounded-lg px-2.5 py-1.5 cursor-not-allowed"
                  >
                    <ArrowUpRight size={13} />
                  </button>
                  <button
                    onClick={() => requestDecision("reject", a)}
                    disabled={actionDisabled}
                    title={actionTitle}
                    className="flex-1 flex items-center justify-center gap-1 text-[var(--text-on-brand)] font-medium text-xs rounded-lg py-1.5 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{ backgroundColor: "var(--decision-deny)" }}
                  >
                    <X size={13} /> Reject
                  </button>
                </>
              )}
            </div>
          </div>
        );
        })}
      </div>
      <ConfirmDialog
        open={pendingAction !== null}
        title={pendingAction?.kind === "approve" ? "Approve this frozen action?" : pendingAction?.kind === "reject" ? "Reject this action?" : "Submit edited action for re-evaluation?"}
        impact={pendingAction?.kind === "edit"
          ? "Editing creates a new canonical action and action hash. The old approval cannot authorize the edited bytes; policy is evaluated again."
          : pendingAction?.kind === "approve"
            ? "Your identity and reason will be bound to this action hash. The gateway remains the source of truth and rejects expired or changed actions."
            : "The agent action will remain blocked and your reason will be written to the audit trail."}
        target={pendingAction ? approvalConfirmationTarget(pendingAction.approval) : ""}
        reason={auditReason}
        onReasonChange={setAuditReason}
        confirmLabel={pendingAction?.kind === "approve" ? "Approve exact action" : pendingAction?.kind === "reject" ? "Reject action" : "Create new hash & re-evaluate"}
        confirmDisabled={!auditReason.trim() || approveMutation.isPending || rejectMutation.isPending || editMutation.isPending}
        onConfirm={confirmAction}
        onCancel={() => { setPendingAction(null); setAuditReason(""); }}
      />
    </div>
  );
}
