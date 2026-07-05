import { DEMO_MODE } from "@/app/runtimeConfig";

/** Display label for bearer token field — never echoes stored secrets in production. */
export function bearerTokenDisplayLabel(hasToken: boolean): string {
  if (!hasToken) return "Not configured";
  return DEMO_MODE ? "Configured (demo mode)" : "Configured (in-memory only)";
}

export function bearerTokenPlaceholder(): string {
  return DEMO_MODE
    ? "Bearer token (persisted in demo mode only)"
    : "Enter bearer token (in-memory only — never persisted)";
}

export function connectionChangeImpact(): string {
  return "Changing gateway connection settings invalidates cached queries and may interrupt the live SOC stream. Credentials remain write-only and are never listed after apply.";
}