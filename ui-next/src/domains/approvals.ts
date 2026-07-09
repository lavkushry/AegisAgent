import {
  fetchFromGateway,
  type FetchOptions,
} from "@/lib/http/client";
import { asRecordArray } from "@/lib/format";

export interface AuthorizeToolCall {
  tool: string;
  action: string;
  resource?: string | null;
  mutates_state: boolean;
  parameters: unknown;
}

export interface ApprovalRecord {
  id?: string;
  approval_id?: string;
  decision_id?: string;
  tool_name?: string;
  tool_call?: AuthorizeToolCall;
  edited_tool_call?: AuthorizeToolCall;
  agent_id?: string;
  source_trust?: string;
  root_trust_level?: string;
  action_hash?: string;
  original_action_hash?: string;
  edited_action_hash?: string;
  effective_action_hash?: string;
  is_edited?: boolean;
  expires_at?: string | null;
  status?: string;
  reason?: string | null;
  decision_reason?: string | null;
  risk_score?: number | null;
  risk_level?: string | null;
  composite_risk_score?: number | null;
}

export function approvalId(approval: ApprovalRecord): string {
  return approval.id ?? approval.approval_id ?? "";
}

export function currentToolCall(
  approval: ApprovalRecord,
): AuthorizeToolCall | undefined {
  return approval.edited_tool_call ?? approval.tool_call;
}

export function actionLabel(approval: ApprovalRecord): string {
  const call = currentToolCall(approval);
  return `${call?.tool ?? approval.tool_name ?? "tool"}.${call?.action ?? "action"}`;
}

export function effectiveActionHash(
  approval: ApprovalRecord,
): string | undefined {
  return (
    approval.effective_action_hash ??
    approval.action_hash ??
    approval.edited_action_hash ??
    approval.original_action_hash
  );
}

export function approvalIsExpired(
  approval: ApprovalRecord,
  now = new Date(),
): boolean {
  if (approval.status?.toUpperCase() === "EXPIRED") return true;
  if (!approval.expires_at) return false;
  const expiresAt = Date.parse(approval.expires_at);
  return Number.isFinite(expiresAt) && expiresAt <= now.getTime();
}

export function approvalActionDisabledReason(
  approval: ApprovalRecord,
  context: { busy: boolean; canAct: boolean; denyReason?: string; now?: Date },
): string | undefined {
  if (context.busy) return "Approval mutation already in progress";
  if (!context.canAct) {
    return (
      context.denyReason ??
      "Requires operator identity (set in Settings)"
    );
  }
  if (!approvalId(approval)) return "Approval ID missing from gateway response";
  if (approvalIsExpired(approval, context.now)) {
    return "Approval expired; the gateway will fail closed";
  }
  const status = approval.status?.toLowerCase();
  if (status && status !== "created" && status !== "pending") {
    return `Approval is ${approval.status}; only pending approvals can be changed`;
  }
  return undefined;
}

function mapApproval(row: Record<string, unknown>): ApprovalRecord {
  return row as unknown as ApprovalRecord;
}

export async function listApprovals(
  opts: FetchOptions,
): Promise<ApprovalRecord[]> {
  const raw = await fetchFromGateway<unknown>(opts, "/v1/approvals");
  return asRecordArray(raw).map(mapApproval);
}

export function approveApproval(
  opts: FetchOptions,
  id: string,
  approverUserId: string,
  reason: string,
) {
  return fetchFromGateway<Record<string, unknown>>(
    opts,
    `/v1/approvals/${encodeURIComponent(id)}/approve`,
    "POST",
    { approver_user_id: approverUserId, reason },
  );
}

export function rejectApproval(
  opts: FetchOptions,
  id: string,
  approverUserId: string,
  reason: string,
) {
  return fetchFromGateway<Record<string, unknown>>(
    opts,
    `/v1/approvals/${encodeURIComponent(id)}/reject`,
    "POST",
    { approver_user_id: approverUserId, reason },
  );
}

export function editApproval(
  opts: FetchOptions,
  id: string,
  approverUserId: string,
  editedToolCall: AuthorizeToolCall,
  reason: string,
) {
  return fetchFromGateway<Record<string, unknown>>(
    opts,
    `/v1/approvals/${encodeURIComponent(id)}/edit`,
    "POST",
    {
      approver_user_id: approverUserId,
      edited_tool_call: editedToolCall,
      reason,
    },
  );
}

export type ParseEditedToolCallResult =
  | { ok: true; editedToolCall: AuthorizeToolCall }
  | { ok: false; error: string };

/** Edit re-hashes + re-evaluates on the gateway (parameters JSON only). */
export function parseEditedToolCall(
  approval: ApprovalRecord,
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
    return {
      ok: false,
      error:
        "The gateway did not return the frozen tool call; editing is disabled.",
    };
  }
  return {
    ok: true,
    editedToolCall: { ...call, parameters: parsedParameters },
  };
}
