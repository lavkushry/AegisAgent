import { test as base, expect } from "@playwright/test";

const IGNORED_CONSOLE_PATTERNS = [
  /favicon/i,
  /Failed to load resource.*404/i,
];

export const test = base.extend({
  page: async ({ page }, use) => {
    const consoleErrors: string[] = [];
    page.on("console", (message) => {
      if (message.type() !== "error") return;
      const text = message.text();
      if (IGNORED_CONSOLE_PATTERNS.some((pattern) => pattern.test(text))) return;
      consoleErrors.push(text);
    });
    page.on("pageerror", (error) => {
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