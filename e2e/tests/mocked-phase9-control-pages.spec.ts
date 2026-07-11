import { test, expect } from "../fixtures/guardedTest";
import {
  AGENT_KEY,
  RUN_ID,
  RUN_KEY,
} from "../fixtures/gatewayFixtures";
import {
  installMockGateway,
  openMockedConsole,
} from "../fixtures/installMockGateway";
import { openNav } from "./helpers";

/**
 * Phase 9.2/9.3 console pages (#1845): Agent Cage Runs, Ban Center,
 * Quarantine Center, Egress Events, Evidence Graph, Policy Center.
 * Mock-gateway-backed, same pattern as mocked-soc-workflows.spec.ts.
 */
test.describe("mocked Phase 9 control pages", () => {
  test("Agent Cage Runs lists a run and issues a pause command", async ({
    page,
  }) => {
    const mock = await installMockGateway(page, { role: "analyst" });
    await openMockedConsole(page);
    await openNav(page, "Cage Runs");
    const row = page.getByRole("row").filter({ hasText: RUN_KEY });
    await expect(row).toBeVisible({ timeout: 10_000 });
    await row.getByRole("button", { name: "pause", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await dialog.getByLabel(/Actor/i).fill("e2e-operator");
    await dialog.getByRole("button", { name: /Confirm pause/i }).click();
    await expect(page.getByText(/pause command issued/i)).toBeVisible({
      timeout: 10_000,
    });
    expect(mock.runtime.runStatus).toBe("paused");
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Run detail shows decision timeline, runtime events, prompt timeline, and model calls", async ({
    page,
  }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page);
    await page.goto(`/dashboard/runs/${RUN_ID}`);
    await expect(
      page.getByRole("heading", { name: "Decision timeline" }),
    ).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("authorize_decision")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Runtime events" }),
    ).toBeVisible();
    await expect(page.getByText("sandbox_started")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Prompt timeline" }),
    ).toBeVisible();
    await expect(
      page.getByText("Summarize the attached [REDACTED] file"),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "Model calls" }),
    ).toBeVisible();
    await expect(page.getByText("openai/gpt-5")).toBeVisible();
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Ban Center creates and revokes a ban", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "analyst" });
    await openMockedConsole(page);
    await openNav(page, "Bans");
    await expect(page.getByText(AGENT_KEY).first()).toBeVisible({
      timeout: 10_000,
    });

    await page.getByPlaceholder(/agent_key \/ run id/i).fill("evil-agent");
    await page.getByPlaceholder("you@team").fill("e2e-operator");
    await page.getByRole("button", { name: "Record ban" }).click();
    await expect(page.getByText("Ban recorded.")).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByText("evil-agent")).toBeVisible();

    const row = page.getByRole("row").filter({ hasText: AGENT_KEY });
    await row.getByRole("button", { name: "Revoke" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel(/Revoked by/i).fill("e2e-operator");
    await dialog.getByRole("button", { name: "Confirm revoke" }).click();
    await expect(page.getByText("Ban revoked.")).toBeVisible({
      timeout: 10_000,
    });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Quarantine Center creates and releases a quarantine", async ({
    page,
  }) => {
    const mock = await installMockGateway(page, { role: "analyst" });
    await openMockedConsole(page);
    await openNav(page, "Quarantine");
    await expect(page.getByText(AGENT_KEY).first()).toBeVisible({
      timeout: 10_000,
    });

    await page
      .getByPlaceholder(/agent_key \/ run id \/ file path/i)
      .fill("suspicious-workspace");
    await page.getByPlaceholder("you@team").fill("e2e-operator");
    await page.getByRole("button", { name: "Record quarantine" }).click();
    await expect(page.getByText("Quarantine recorded.")).toBeVisible({
      timeout: 10_000,
    });

    const row = page.getByRole("row").filter({ hasText: AGENT_KEY });
    await row.getByRole("button", { name: "Release" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel(/Released by/i).fill("e2e-operator");
    await dialog.getByRole("button", { name: "Confirm release" }).click();
    await expect(page.getByText("Quarantine released.")).toBeVisible({
      timeout: 10_000,
    });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Egress Events lists an event and blocks a destination", async ({
    page,
  }) => {
    const mock = await installMockGateway(page, { role: "analyst" });
    await openMockedConsole(page);
    await openNav(page, "Egress");
    await expect(page.getByText("egress_check")).toBeVisible({
      timeout: 10_000,
    });

    await page
      .getByPlaceholder("evil.example.com")
      .fill("blocked-destination.example");
    const actorInputs = page.getByPlaceholder("you@team");
    await actorInputs.first().fill("e2e-operator");
    await page
      .getByRole("button", { name: "Block destination", exact: true })
      .click();
    await expect(page.getByText(/Blocked blocked-destination.example/i)).toBeVisible({
      timeout: 10_000,
    });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Evidence Graph loads a run-scoped graph", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "viewer" });
    await openMockedConsole(page);
    await openNav(page, "Evidence Graph");
    await page.getByLabel("Scope").selectOption("run");
    await page
      .getByPlaceholder(/incident \/ agent \/ run id/i)
      .fill(RUN_ID);
    await page.getByRole("button", { name: "Load graph" }).click();
    await expect(page.getByRole("img", { name: /Evidence graph for/i })).toBeVisible({
      timeout: 10_000,
    });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });

  test("Policy Center edits a policy and rolls it back", async ({ page }) => {
    const mock = await installMockGateway(page, { role: "admin" });
    await openMockedConsole(page);
    await openNav(page, "Policies");
    await page.getByText("E2E Fixture Policy").click();
    // The create-form Cedar textarea and the edit-panel Cedar textarea share
    // a class; the edit panel is the one that renders after selection, last
    // in DOM order.
    const textarea = page.locator("textarea.font-mono").last();
    await textarea.fill(
      'forbid(principal, action, resource) when { context.trust_level == "malicious_suspected" };',
    );
    await page.getByRole("button", { name: /Save \(new version\)/i }).click();
    await expect(page.getByText(/Policy updated \(new version\)/i)).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByText("v2", { exact: true })).toBeVisible();

    await page
      .getByRole("button", { name: /Rollback to previous version/i })
      .click();
    await expect(page.getByText(/Rolled back to version/i)).toBeVisible({
      timeout: 10_000,
    });
    await mock.dispose();
    expect(mock.unhandled).toEqual([]);
  });
});
