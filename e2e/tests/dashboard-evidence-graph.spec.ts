import { test, expect } from "../fixtures/guardedTest";
import { openConfiguredConsole, openNav, registerTestAgent } from "./helpers";

/**
 * Legacy Next evidence-graph deep nav is not yet ported to ui-next.
 * Keep a light fleet inventory smoke so the file remains green under cutover.
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
});
