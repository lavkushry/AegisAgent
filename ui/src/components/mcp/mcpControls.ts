import type { Role } from "@/app/store";
import { canRespond } from "@/app/store";

export type McpControlKind = "quarantine" | "restore";

export function mcpControlDisabledReason(
  kind: McpControlKind,
  status: string,
  role: Role,
): string | null {
  const normalized = String(status).toLowerCase();

  if (!canRespond(role)) {
    return "Requires analyst, approver, or admin role";
  }

  if (kind === "quarantine") {
    if (normalized === "quarantined") return "Server is already quarantined";
    return null;
  }

  if (normalized !== "quarantined") {
    return "Only quarantined servers can be restored";
  }
  return null;
}

export function mcpControlImpact(kind: McpControlKind): string {
  return kind === "quarantine"
    ? "All tool calls routed through this MCP server will be denied until it is restored. Use this for manifest drift or suspected compromise."
    : "This restores the MCP server to active status. Only continue if manifest drift has been investigated and the server is trusted.";
}

export function mcpControlTitle(kind: McpControlKind): string {
  return kind === "quarantine" ? "Quarantine this MCP server?" : "Restore this MCP server?";
}

export function mcpControlConfirmLabel(kind: McpControlKind): string {
  return kind === "quarantine" ? "Quarantine server" : "Restore server";
}