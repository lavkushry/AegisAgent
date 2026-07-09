import { test, expect } from "../fixtures/guardedTest";
import { openConfiguredConsole, openNav, registerTestAgent } from "./helpers";

/**
 * Fleet inventory + agent detail deep-nav smoke (ui-next).
 * Legacy Next evidence-graph panel harness is retired with the dual-tree cutover.
 */
test.describe("fleet inventory navigation (ui-next)", () => {
  test("Agents page lists registered fleet members", async ({
    page,
    request,
    baseURL,
  }) => {
    const agent = await registerTestAgent(
      request,
      baseURL!,
      `console-e2e-fleet-${Date.now()}`,
    );
    await openConfiguredConsole(page);
    await openNav(page, "Agents");
    await expect(
      page.getByRole("row").filter({ hasText: agent.agentKey }),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("agent detail is reachable via in-app fleet link (no full reload)", async ({
    page,
    request,
    baseURL,
  }) => {
    const agent = await registerTestAgent(
      request,
      baseURL!,
      `console-e2e-bookmark-${Date.now()}`,
    );
    // Bearer is memory-only in production — use SPA navigation so zustand state survives.
    await openConfiguredConsole(page);
    await openNav(page, "Agents");
    const row = page.getByRole("row").filter({ hasText: agent.agentKey });
    await expect(row).toBeVisible({ timeout: 15_000 });
    await row.getByRole("link").first().click();
    await expect(page).toHaveURL(new RegExp(`/dashboard/agents/${agent.id}`));
    await expect(page.getByText(agent.agentKey).first()).toBeVisible({
      timeout: 15_000,
    });
  });
});
