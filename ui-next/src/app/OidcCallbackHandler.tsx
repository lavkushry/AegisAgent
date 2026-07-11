import { useEffect, useState, type ReactNode } from "react";
import { parseOidcCallbackFragment } from "@/domains/oidc";
import { useAppStore } from "./store";

const OIDC_ERROR_MESSAGES: Record<string, string> = {
  identity_not_linked:
    "This SSO identity isn't linked to a tenant yet. Sign in with a bearer token first, then link SSO from Settings.",
  identity_already_linked: "That SSO identity is already linked to a different tenant.",
  state_mismatch: "SSO login failed a security check (state mismatch). Please try again.",
  missing_or_expired_state: "SSO login session expired. Please try again.",
  verification_failed: "SSO login could not be verified. Please try again.",
  idp_error: "The identity provider reported an error during SSO login.",
};

/**
 * Runs once on app boot: picks up the `#access_token=`/`#error=` fragment
 * `GET /v1/auth/oidc/callback` redirects the browser back with, applies it
 * to the store, and strips the fragment from the URL so a page refresh
 * doesn't re-process a stale (and by then likely expired) token.
 */
export function OidcCallbackHandler({ children }: { children: ReactNode }) {
  const setBearerToken = useAppStore((s) => s.setBearerToken);
  const setActiveTenant = useAppStore((s) => s.setActiveTenant);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const parsed = parseOidcCallbackFragment(window.location.hash);
    if (!parsed) return;

    if (parsed.accessToken) {
      setBearerToken(parsed.accessToken);
      if (parsed.tenantId) {
        setActiveTenant(parsed.tenantId);
      }
    } else if (parsed.error) {
      setError(OIDC_ERROR_MESSAGES[parsed.error] ?? `SSO login failed: ${parsed.error}`);
    }

    const cleanUrl = window.location.pathname + window.location.search;
    window.history.replaceState(null, "", cleanUrl);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <>
      {error ? (
        <div
          role="alert"
          className="border-b border-[var(--sev-high)]/30 bg-[var(--sev-high)]/10 px-4 py-2 text-[11px] text-[var(--sev-high)]"
        >
          {error}{" "}
          <button
            type="button"
            className="underline"
            onClick={() => setError(null)}
          >
            Dismiss
          </button>
        </div>
      ) : null}
      {children}
    </>
  );
}
