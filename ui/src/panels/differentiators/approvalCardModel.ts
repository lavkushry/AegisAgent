import type { AuthorizeToolCall } from "../../app/api";
import { canonicalizeJson } from "../../lib/canonicalJson";

export interface ApprovalRow {
  id?: string;
  approval_id?: string;
  decision_id?: string;
  agent_id?: string;
  run_id?: string | null;
  trace_id?: string | null;
  parent_run_id?: string | null;
  source_trust?: string;
  root_trust_level?: string;
  action_hash?: string;
  original_action_hash?: string;
  edited_action_hash?: string;
  effective_action_hash?: string;
  is_edited?: boolean;
  expires_in?: string;
  expires_at?: string | null;
  status?: string;
  approver_group?: string | null;
  approver_user_id?: string | null;
  reason?: string | null;
  decision_reason?: string | null;
  matched_policies?: string[];
  risk_score?: number | null;
  risk_level?: string | null;
  composite_risk_score?: number | null;
  tool_name?: string;
  tool_call?: AuthorizeToolCall;
  edited_tool_call?: AuthorizeToolCall;
}

export interface ApprovalActionContext {
  busy: boolean;
  canAct: boolean;
  denyReason?: string;
  now?: Date;
}

export interface ApprovalMetadataRow {
  label: string;
  value: string;
  kind?: "trust";
  monospace?: boolean;
}

export type ParseEditedToolCallResult =
  | { ok: true; editedToolCall: AuthorizeToolCall }
  | { ok: false; error: string };

export function approvalId(approval: ApprovalRow): string {
  return approval.id ?? approval.approval_id ?? "";
}

export function currentToolCall(approval: ApprovalRow): AuthorizeToolCall | undefined {
  return approval.edited_tool_call ?? approval.tool_call;
}

export function actionLabel(approval: ApprovalRow): string {
  const call = currentToolCall(approval);
  return `${call?.tool ?? approval.tool_name ?? "tool"}.${call?.action ?? "action"}`;
}

export function effectiveActionHash(approval: ApprovalRow): string | undefined {
  return approval.effective_action_hash ?? approval.action_hash ?? approval.edited_action_hash ?? approval.original_action_hash;
}

export function canonicalActionBytes(approval: ApprovalRow): string | undefined {
  const call = currentToolCall(approval);
  return call ? canonicalizeJson(call) : undefined;
}

export function approvalIsExpired(approval: ApprovalRow, now = new Date()): boolean {
  if (approval.status?.toUpperCase() === "EXPIRED") {
    return true;
  }
  if (!approval.expires_at) {
    return false;
  }
  const expiresAt = Date.parse(approval.expires_at);
  return Number.isFinite(expiresAt) && expiresAt <= now.getTime();
}

export function approvalActionDisabledReason(
  approval: ApprovalRow,
  context: ApprovalActionContext,
): string | undefined {
  if (context.busy) {
    return "Approval mutation already in progress";
  }
  if (!context.canAct) {
    return context.denyReason ?? "Requires the approver or admin role (separation of duties)";
  }
  if (!approvalId(approval)) {
    return "Approval ID missing from gateway response";
  }
  if (approvalIsExpired(approval, context.now)) {
    return "Approval expired; the gateway will fail closed";
  }
  const status = approval.status?.toLowerCase();
  if (status && status !== "created" && status !== "pending") {
    return `Approval is ${approval.status}; only pending approvals can be changed`;
  }
  return undefined;
}

export function editDisabledReason(
  approval: ApprovalRow,
  context: ApprovalActionContext,
): string | undefined {
  return approvalActionDisabledReason(approval, context) ?? (currentToolCall(approval) ? undefined : "Frozen tool call unavailable");
}

export function parseEditedToolCall(
  approval: ApprovalRow,
  parametersJson: string,
): ParseEditedToolCallResult {
  let parsedParameters: unknown;
  try {
    parsedParameters = JSON.parse(parametersJson);
  } catch {
    return { ok: false, error: "Parameters must be valid JSON." };
  }

  const call = currentToolCall(approval);
  if (!call) {
    return { ok: false, error: "The gateway did not return the frozen tool call; editing is disabled." };
  }

  return { ok: true, editedToolCall: { ...call, parameters: parsedParameters } };
}

export function approvalConfirmationTarget(approval: ApprovalRow): string {
  const expiry = approval.expires_at ? `expires ${approval.expires_at}` : approval.expires_in ? `expires ${approval.expires_in}` : "expiry unavailable";
  return [
    approvalId(approval) || "approval-id unavailable",
    actionLabel(approval),
    effectiveActionHash(approval) ?? "hash unavailable",
    expiry,
  ].join(" · ");
}

export function approvalMetadataRows(approval: ApprovalRow): ApprovalMetadataRow[] {
  const call = currentToolCall(approval);
  const runTrace = [approval.run_id, approval.trace_id].filter(Boolean).join(" / ") || "N/A";
  const sourceTrust = approval.source_trust ?? approval.root_trust_level ?? "unknown";
  const policies = approval.matched_policies?.length ? approval.matched_policies.join(", ") : "N/A";
  const risk = [
    approval.risk_level ?? undefined,
    approval.risk_score !== null && approval.risk_score !== undefined ? `${approval.risk_score}/100` : undefined,
    approval.composite_risk_score !== null && approval.composite_risk_score !== undefined ? `composite ${approval.composite_risk_score}/100` : undefined,
  ].filter(Boolean).join(" · ") || "N/A";

  return [
    { label: "Approval ID", value: approvalId(approval) || "N/A", monospace: true },
    { label: "Status", value: approval.status ?? "N/A" },
    { label: "Agent", value: approval.agent_id ?? "N/A", monospace: true },
    { label: "Run / trace", value: runTrace, monospace: true },
    { label: "Source trust", value: sourceTrust, kind: "trust" },
    { label: "Resource", value: call?.resource ?? approval.tool_call?.resource ?? "N/A", monospace: true },
    { label: "Risk", value: risk },
    { label: "Approver group", value: approval.approver_group ?? "N/A" },
    { label: "Policy reason", value: approval.decision_reason ?? approval.reason ?? "N/A" },
    { label: "Policies", value: policies, monospace: true },
  ];
}
