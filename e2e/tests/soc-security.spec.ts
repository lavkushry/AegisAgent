import { test, expect } from "../fixtures/guardedTest";
import { AGENT_KEY, FAKE_SECRET } from "../fixtures/gatewayFixtures";
import { installMockGateway, openMockedConsole } from "../fixtures/installMockGateway";
import { assertNoSecrets } from "./helpers";

test.describe("mocked SOC security controls (#1638)", () => {
  test("viewer role disables active response controls with reason", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Agents Fleet" }).click();
    await page.getByRole("row").filter({ hasText: AGENT_KEY }).click();
    const freeze = page.getByRole("button", { name: "Freeze" });
    await expect(freeze).toBeDisabled();
    await expect(freeze).toHaveAttribute("title", /Requires analyst/i);
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("viewer cannot approve pending actions", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Approvals" }).click();
    await expect(page.getByText(/Read-only as viewer/i)).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve" }).first()).toBeDisabled();
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("dangerous action dialog blocks confirm without audit reason", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "analyst" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Agents Fleet" }).click();
    await page.getByRole("row").filter({ hasText: AGENT_KEY }).click();
    await page.getByRole("button", { name: "Freeze" }).click();
    const dialog = page.getByRole("alertdialog");
    await expect(dialog).toBeVisible();
    const confirm = dialog.getByRole("button", { name: /Freeze agent/i });
    await expect(confirm).toBeDisabled();
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("API failure surfaces operator-visible error without leaking secrets", async ({ page }) => {
    const mock = await installMockGateway(page, {
      role: "analyst",
      failingPaths: ["/v1/agents"],
    });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Agents Fleet" }).click();
    await expect(page.getByText(/Failed to load agents|Simulated gateway failure/i)).toBeVisible({
      timeout: 10_000,
    });
    await assertNoSecrets(page, [FAKE_SECRET]);
    await mock.dispose();
  });

  test("settings and config surfaces never render raw bearer secrets", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page);
    await page.getByRole("button", { name: "Settings" }).click();
    await expect(page.getByText("Role-Based Access Control (RBAC)")).toBeVisible();
    const tokenInput = page.getByLabel("Bearer Token");
    await expect(tokenInput).toHaveAttribute("type", "password");
    await assertNoSecrets(page, [FAKE_SECRET]);
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });
});