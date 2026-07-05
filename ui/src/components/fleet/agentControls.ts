import type { Role } from "@/app/store";
import { canRespond, canRevokeAgent } from "@/app/store";

export type AgentControlKind = "freeze" | "unfreeze" | "restore" | "revoke";

const TERMINAL_STATUSES = new Set(["revoked", "deleted"]);

export function controlDisabledReason(
  kind: AgentControlKind,
  status: string,
  role: Role,
): string | null {
  const normalized = String(status).toLowerCase();

  if (kind === "revoke") {
    if (!canRevokeAgent(role)) return "Requires admin role";
    if (TERMINAL_STATUSES.has(normalized)) return "Agent is already permanently revoked or deleted";
    return null;
  }

  if (!canRespond(role)) return "Requires analyst, approver, or admin role";
  if (TERMINAL_STATUSES.has(normalized)) return "Agent is revoked or deleted";

  switch (kind) {
    case "freeze":
      if (normalized === "frozen") return "Agent is already frozen";
      if (normalized === "quarantined") return "Quarantined agents must be restored first";
      if (normalized !== "active") return `Cannot freeze agent in ${normalized} status`;
      return null;
    case "unfreeze":
      if (normalized !== "frozen") return "Only frozen agents can be restored via unfreeze";
      return null;
    case "restore":
      if (normalized !== "quarantined") return "Only quarantined agents can be restored";
      return null;
    default:
      return "Unsupported control";
  }
}

export function controlImpact(kind: AgentControlKind): string {
  switch (kind) {
    case "freeze":
      return "Future authorize calls for this agent fail closed until an operator unfreezes it. The reason is recorded in frozen_reason and the audit trail.";
    case "unfreeze":
      return "The agent returns to active status and authorize calls resolve normally again.";
    case "restore":
      return "Clears quarantined status so authorize calls resolve the agent normally. Cedar-triggered quarantines require explicit operator recovery.";
    case "revoke":
      return "Permanently revokes the agent. This is not reversible via API; existing receipts remain as evidence.";
    default:
      return "";
  }
}

export function controlTitle(kind: AgentControlKind): string {
  switch (kind) {
    case "freeze":
      return "Freeze this agent?";
    case "unfreeze":
      return "Restore this frozen agent?";
    case "restore":
      return "Restore this quarantined agent?";
    case "revoke":
      return "Permanently revoke this agent?";
    default:
      return "Confirm agent control";
  }
}

export function controlConfirmLabel(kind: AgentControlKind): string {
  switch (kind) {
    case "freeze":
      return "Freeze agent";
    case "unfreeze":
      return "Restore agent";
    case "restore":
      return "Restore quarantined agent";
    case "revoke":
      return "Revoke agent";
    default:
      return "Confirm";
  }
}