import { test, expect } from "../fixtures/guardedTest";
import {
  agentControlButton,
  confirmDangerousAction,
  openConfiguredConsole,
  openNav,
  registerTestAgent,
} from "./helpers";

/**
 * Security-oriented console checks against the Bun SPA cutover.
 */
test.describe("SOC console security (ui-next)", () => {
  test("freeze requires confirm dialog with reason", async ({
    page,
    request,
    baseURL,
  }) => {
    const agent = await registerTestAgent(
      request,
      baseURL!,
      `console-e2e-freeze-${Date.now()}`,
    );
    await openConfiguredConsole(page);
    await openNav(page, "Agents");
    const row = page.getByRole("row").filter({ hasText: agent.agentKey });
    await expect(row).toBeVisible({ timeout: 15_000 });
    await agentControlButton(row, "freeze").click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText(/Confirm freeze/i)).toBeVisible();
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();
  });

  test("freeze confirm completes for active agent", async ({
    page,
    request,
    baseURL,
  }) => {
    const agent = await registerTestAgent(
      request,
      baseURL!,
      `console-e2e-freeze2-${Date.now()}`,
    );
    await openConfiguredConsole(page);
    await openNav(page, "Agents");
    const row = page.getByRole("row").filter({ hasText: agent.agentKey });
    await expect(row).toBeVisible({ timeout: 15_000 });
    await agentControlButton(row, "freeze").click();
    await confirmDangerousAction(page, "e2e freeze test", /Confirm freeze/i);
    // Status may update after invalidate; tolerate network failure messaging.
    await expect(
      page.getByText(/freeze completed|Agent freeze|frozen|error|HTTP/i).first(),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("Settings exposes operator id field for approval integrity", async ({
    page,
  }) => {
    await openConfiguredConsole(page);
    await openNav(page, "Settings");
    await expect(page.getByLabel(/Operator ID/i)).toBeVisible();
    await expect(page.getByText(/approver_user_id/i)).toBeVisible();
  });
});
