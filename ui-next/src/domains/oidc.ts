import { fetchFromGateway, type FetchOptions } from "@/lib/http/client";

interface OidcLinkStartResponse {
  login_url: string;
}

/**
 * `POST /v1/oidc/link/start` -- authenticated. Returns the IdP authorization
 * URL to navigate the browser to; the caller's existing bearer token (sent
 * via `opts`) determines which tenant the resulting identity link applies
 * to, since a browser navigation can't carry a custom Authorization header.
 */
export async function startOidcLink(opts: FetchOptions): Promise<string> {
  const response = await fetchFromGateway<OidcLinkStartResponse>(
    opts,
    "/v1/oidc/link/start",
    "POST",
    {},
  );
  return response.login_url;
}

/** `GET /v1/auth/oidc/login` -- plain login against an already-linked identity. */
export function oidcLoginUrl(gatewayUrl: string): string {
  return `${gatewayUrl.replace(/\/+$/, "")}/v1/auth/oidc/login`;
}

interface OidcCallbackFragment {
  accessToken?: string;
  tenantId?: string;
  error?: string;
}

/**
 * Decodes the tenant a JWT claims, without verifying its signature -- the
 * gateway is the only party that ever needs to trust this token; here it
 * only saves the operator from re-typing the tenant ID the IdP-linked
 * identity already resolved to.
 */
function decodeJwtTenantId(token: string): string | undefined {
  try {
    const payload = token.split(".")[1];
    if (!payload) return undefined;
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const json = atob(base64);
    const claims: unknown = JSON.parse(json);
    if (
      typeof claims === "object" &&
      claims !== null &&
      "tenant_id" in claims &&
      typeof (claims as { tenant_id: unknown }).tenant_id === "string"
    ) {
      return (claims as { tenant_id: string }).tenant_id;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * Parses the `#access_token=`/`#error=` fragment `GET /v1/auth/oidc/callback`
 * redirects the browser back with. Returns `null` if the current URL has no
 * OIDC fragment at all (the overwhelmingly common case -- this runs on every
 * page load).
 */
export function parseOidcCallbackFragment(
  hash: string,
): OidcCallbackFragment | null {
  const trimmed = hash.startsWith("#") ? hash.slice(1) : hash;
  if (!trimmed) return null;
  const params = new URLSearchParams(trimmed);
  const accessToken = params.get("access_token") ?? undefined;
  const error = params.get("error") ?? undefined;
  if (!accessToken && !error) return null;
  return {
    accessToken,
    tenantId: accessToken ? decodeJwtTenantId(accessToken) : undefined,
    error,
  };
}
