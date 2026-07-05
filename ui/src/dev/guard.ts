/**
 * Dev-only panel harness gate. Production static exports must never expose the
 * in-app fixture browser unless an operator explicitly opts in at build time.
 */
export const DEV_HARNESS_ENABLED =
  process.env.NODE_ENV !== "production" ||
  process.env.NEXT_PUBLIC_AEGIS_DEV_HARNESS === "true";

export const DEV_HARNESS_VIEW = "dev-harness" as const;

export function isDevHarnessView(view: string | undefined): view is typeof DEV_HARNESS_VIEW {
  return DEV_HARNESS_ENABLED && view === DEV_HARNESS_VIEW;
}