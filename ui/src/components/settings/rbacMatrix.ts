import type { Role } from "@/app/store";
import { canApprove, canRespond, canRevokeAgent } from "@/app/store";

export interface RbacCapabilityRow {
  capability: string;
  viewer: boolean;
  analyst: boolean;
  approver: boolean;
  admin: boolean;
}

export const RBAC_MATRIX: RbacCapabilityRow[] = [
  {
    capability: "Read SOC evidence (decisions, receipts, incidents)",
    viewer: true,
    analyst: true,
    approver: true,
    admin: true,
  },
  {
    capability: "Active response (freeze/restore/quarantine)",
    viewer: false,
    analyst: true,
    approver: true,
    admin: true,
  },
  {
    capability: "Approval queue decisions",
    viewer: false,
    analyst: false,
    approver: true,
    admin: true,
  },
  {
    capability: "Permanent agent revoke",
    viewer: false,
    analyst: false,
    approver: false,
    admin: true,
  },
  {
    capability: "Tenant risk-weight overrides",
    viewer: false,
    analyst: false,
    approver: false,
    admin: true,
  },
];

export function roleCapabilitySummary(role: Role): string {
  const caps: string[] = ["Read SOC evidence"];
  if (canRespond(role)) caps.push("Active response");
  if (canApprove(role)) caps.push("Approvals");
  if (canRevokeAgent(role)) caps.push("Permanent revoke");
  return caps.join(" · ");
}

export function roleOverrideDisabledReason(demoMode: boolean): string | null {
  return demoMode ? null : "Production role is supplied by the authenticated gateway session";
}