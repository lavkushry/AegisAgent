/**
 * Double-submit CSRF: gateway injects <meta name="csrf-token"> + HttpOnly
 * cookie in GET /dashboard/ (src/src/routes/dashboard.rs).
 */
export function getCsrfToken(): string | undefined {
  if (typeof document === "undefined") return undefined;
  return (
    document
      .querySelector('meta[name="csrf-token"]')
      ?.getAttribute("content") ?? undefined
  );
}
