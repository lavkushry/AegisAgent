"use client";

import { useQuery } from "@tanstack/react-query";
import { useAppStore, type Role } from "@/app/store";
import { fetchFromGateway } from "@/app/api";

const VALID_ROLES: ReadonlyArray<Role> = ["viewer", "analyst", "approver", "admin"];

export interface EffectiveRole {
  role: Role;
  /** "session" when the gateway supplied it; "override" when using the local selector. */
  source: "session" | "override";
}

interface SessionResponse {
  role?: string;
  tenant_id?: string;
}

/**
 * Resolve the operator's role, session-first: if the gateway exposes a
 * session/identity endpoint with a role, that wins; otherwise fall back to
 * the local role selector (a dev/preview override).
 *
 * NOTE: the gateway currently has no user/role model — auth is tenant-scoped
 * (bearer / mTLS). Until a real identity model lands, this resolves to the
 * local override. The wiring is in place so real RBAC works automatically
 * once GET /v1/session returns a role.
 */
export function useEffectiveRole(): EffectiveRole {
  const gatewayUrl = useAppStore((s) => s.gatewayUrl);
  const bearerToken = useAppStore((s) => s.bearerToken);
  const override = useAppStore((s) => s.role);

  const { data } = useQuery({
    queryKey: ["session", gatewayUrl, bearerToken],
    queryFn: () => fetchFromGateway<SessionResponse>({ gatewayUrl, bearerToken }, "/v1/session"),
    retry: false,
    staleTime: 60_000,
    // A missing endpoint (404) is expected today; do not surface it as an error.
    throwOnError: false,
  });

  const sessionRole =
    data?.role && VALID_ROLES.includes(data.role as Role) ? (data.role as Role) : null;

  return sessionRole
    ? { role: sessionRole, source: "session" }
    : { role: override, source: "override" };
}
