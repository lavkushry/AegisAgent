"use client";

import React, { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, X, Edit3, Save, ArrowUpRight } from "lucide-react";
import { useAppStore, canApprove } from "@/app/store";
import { useEffectiveRole } from "@/hooks/useSessionRole";
import { approveApproval, editApproval, rejectApproval, type AuthorizeToolCall } from "@/app/api";
import { frameRows } from "@/datasources/frame";
import { errorMessage } from "@/lib/format";
import { canonicalizeJson } from "@/lib/canonicalJson";
import TrustBadge from "@/components/security/TrustBadge";
import HashChip from "@/components/security/HashChip";
import { ConfirmDialog } from "@/components/primitives";
import type { PanelProps } from "../types";

interface ApprovalRow {
  id?: string;
  approval_id?: string;
  agent_id?: string;
  source_trust?: string;
  action_hash?: string;
  original_action_hash?: string;
  edited_action_hash?: string;
  effective_action_hash?: string;
  is_edited?: boolean;
  expires_in?: string;
  expires_at?: string;
  status?: string;
  tool_name?: string;
  tool_call?: AuthorizeToolCall;
  edited_tool_call?: AuthorizeToolCall;
}

type PendingAction =
  | { kind: "approve"; approval: ApprovalRow }
  | { kind: "reject"; approval: ApprovalRow }
  | { kind: "edit"; approval: ApprovalRow; editedToolCall: AuthorizeToolCall };

function approvalId(a: ApprovalRow): string {
  return a.id ?? a.approval_id ?? "";
}

function effectiveActionHash(a: ApprovalRow): string | undefined {
  return a.effective_action_hash ?? a.action_hash;
}

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
    setEditParamsJson(JSON.stringify((a.edited_tool_call ?? a.tool_call)?.parameters ?? {}, null, 2));
    setEditError(null);
  };

  const requestEdit = (a: ApprovalRow) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(editParamsJson);
    } catch {
      setEditError("Parameters must be valid JSON.");
      return;
    }
    const currentToolCall = a.edited_tool_call ?? a.tool_call;
    if (!currentToolCall) {
      setEditError("The gateway did not return the frozen tool call; editing is disabled.");
      return;
    }
    setAuditReason("");
    setPendingAction({ kind: "edit", approval: a, editedToolCall: { ...currentToolCall, parameters: parsed } });
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
        const expired = a.status?.toUpperCase() === "EXPIRED";
        const actionDisabled = busy || !canAct || !id || expired;
        const actionTitle = expired ? "Approval expired; the gateway will fail closed" : denyReason;
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
                  {(a.edited_tool_call ?? a.tool_call)?.tool ?? a.tool_name ?? "tool"}.
                  {(a.edited_tool_call ?? a.tool_call)?.action ?? "action"}
                </h4>
              </div>
              <span className="text-[10px] text-[var(--text-muted)] font-mono whitespace-nowrap">
                expires {a.expires_in ?? "N/A"}
              </span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-[11px] py-2 border-y border-[var(--border-default)]">
              <div>
                <span className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)]">Agent</span>
                <code className="text-[var(--text-primary)] font-mono">{a.agent_id ?? "N/A"}</code>
              </div>
              <div>
                <span className="block text-[9px] uppercase tracking-wider text-[var(--text-muted)]">Source trust</span>
                <div className="mt-0.5"><TrustBadge trust={a.source_trust ?? "unknown"} /></div>
              </div>
            </div>

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
                  {(a.edited_tool_call ?? a.tool_call) ? canonicalizeJson(a.edited_tool_call ?? a.tool_call) : "Unavailable from gateway"}
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
                    disabled={actionDisabled || !(a.edited_tool_call ?? a.tool_call)}
                    title={actionTitle ?? ((a.edited_tool_call ?? a.tool_call) ? "Edit parameters (re-hash + re-evaluate)" : "Frozen tool call unavailable")}
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
        target={pendingAction ? `${approvalId(pendingAction.approval)} · ${effectiveActionHash(pendingAction.approval) ?? "hash unavailable"}` : ""}
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
