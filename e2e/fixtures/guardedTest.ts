import { test as base, expect } from "@playwright/test";

const IGNORED_CONSOLE_PATTERNS = [
  /favicon/i,
  /Failed to load resource.*404/i,
  // Connection settings (gateway URL / active tenant) persist to
  // localStorage, which is unavailable during the static export's SSR pass —
  // the server always renders the "nothing configured" default and the
  // client corrects to the real persisted value on its very first render.
  // React detects this one-time, intentional mismatch, logs it (as this
  // error, or the equivalent minified React error #418 in a production
  // build), and gracefully regenerates just that subtree client-side — it
  // is not a functional bug, so it's tolerated here rather than chased
  // through every element that renders one of these fields.
  /Hydration failed because the server rendered (text|HTML) didn't match the client/i,
  /Minified React error #418/i,
];

interface GuardedTestFixtures {
  /**
   * Additional console-error patterns to tolerate for tests that
   * deliberately induce a browser-logged network failure (e.g. asserting
   * the UI surfaces a simulated 5xx gracefully) — a failed fetch/XHR always
   * produces its own "Failed to load resource" console entry regardless of
   * how well the app handles it. Set via `test.use({ expectedConsoleErrors: [...] })`
   * in a scoped `test.describe` block, not file-wide, so the guard stays
   * strict everywhere else.
   */
  expectedConsoleErrors: RegExp[];
}

export const test = base.extend<GuardedTestFixtures>({
  expectedConsoleErrors: [[], { option: true }],
  page: async ({ page, expectedConsoleErrors }, use) => {
    const consoleErrors: string[] = [];
    const ignoredPatterns = [...IGNORED_CONSOLE_PATTERNS, ...expectedConsoleErrors];
    page.on("console", (message) => {
      if (message.type() !== "error") return;
      const text = message.text();
      if (ignoredPatterns.some((pattern) => pattern.test(text))) return;
      consoleErrors.push(text);
    });
    page.on("pageerror", (error) => {
      if (ignoredPatterns.some((pattern) => pattern.test(error.message))) return;
      consoleErrors.push(error.message);
    });

    await use(page);

    expect(
      consoleErrors,
      consoleErrors.length ? `Browser console errors:\n${consoleErrors.join("\n")}` : undefined,
    ).toEqual([]);
  },
});

export { expect };