import { test, expect } from "@playwright/test";
import { openConfiguredConsole, registerTestAgent } from "./helpers";

test.describe("evidence-linked fleet surface", () => {
  test("agent inventory is reachable from URL-synced navigation", async ({ page, request, baseURL }) => {
    const agent = await registerTestAgent(request, baseURL!, `console-e2e-evidence-${Date.now()}`);
    await openConfiguredConsole(page);
    await page.getByRole("button", { name: "Agents Fleet" }).click();
    await expect(page).toHaveURL(/[?&]view=agents(?:&|$)/);
    await expect(page.getByRole("row").filter({ hasText: agent.id })).toBeVisible({ timeout: 10_000 });
  });
});
