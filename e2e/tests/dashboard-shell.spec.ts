import { test, expect } from "@playwright/test";

test.describe("dashboard shell", () => {
  test("loads the overview page with the AegisAgent title", async ({ page }) => {
    await page.goto("/dashboard/");
    await expect(page).toHaveTitle(/AegisAgent SOC Console/);
    await expect(page.locator(".brand-name h1")).toHaveText("AegisAgent");
    await expect(page.locator("#view-overview")).toBeVisible();
  });

  test("serves a restrictive Content-Security-Policy header (#1309)", async ({ page }) => {
    const response = await page.goto("/dashboard/");
    expect(response).not.toBeNull();
    const csp = response!.headers()["content-security-policy"];
    expect(csp).toBeTruthy();
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  test("sets a SameSite=Strict CSRF cookie and injects the csrf-token meta tag (#1308)", async ({
    page,
    context,
  }) => {
    await page.goto("/dashboard/");
    const cookies = await context.cookies();
    const csrfCookie = cookies.find((c) => c.name === "aegis_csrf");
    expect(csrfCookie).toBeTruthy();
    expect(csrfCookie!.sameSite).toBe("Strict");
    expect(csrfCookie!.httpOnly).toBe(true);

    const metaContent = await page
      .locator('meta[name="csrf-token"]')
      .getAttribute("content");
    expect(metaContent).toBeTruthy();
  });

  test("global status indicator reports Connected once seeded data loads", async ({ page }) => {
    await page.goto("/dashboard/");
    await expect(page.locator("#global-status-text")).toHaveText("Connected", {
      timeout: 10_000,
    });
    await expect(page.locator("#global-status-dot")).toHaveClass(/green/);
  });

  test("connection config panel toggles open and persists settings on save", async ({
    page,
  }) => {
    await page.goto("/dashboard/");
    await expect(page.locator("#connection-config-panel")).toBeHidden();

    await page.locator("#config-toggle").click();
    await expect(page.locator("#connection-config-panel")).toBeVisible();

    await page.locator("#auth-token-input").fill("tenant_123");
    await page.locator("#save-config-btn").click();
    await expect(page.locator("#connection-config-panel")).toBeHidden();

    const storedToken = await page.evaluate(() =>
      window.localStorage.getItem("aegis_token"),
    );
    expect(storedToken).toBe("tenant_123");
  });

  const navCases: Array<[view: string, menuLabel: string, panelId: string]> = [
    ["explore", "Explore", "#view-explore"],
    ["alerts", "Alerts", "#view-alerts"],
    ["incidents", "Incidents", "#view-incidents"],
    ["approvals", "Approvals", "#view-approvals"],
    ["agents", "Agents Fleet", "#view-agents"],
    ["risk-scoreboard", "Risk Scoreboard", "#view-risk-scoreboard"],
    ["mcp", "MCP Servers", "#view-mcp"],
    ["receipts", "Integrity Logs", "#view-receipts"],
  ];

  for (const [view, menuLabel, panelId] of navCases) {
    test(`sidebar navigation switches to the ${menuLabel} view`, async ({ page }) => {
      await page.goto("/dashboard/");
      await page.locator(`.menu-item[data-view="${view}"]`).click();
      await expect(page.locator(panelId)).toBeVisible();
      await expect(page.locator(`.menu-item[data-view="${view}"]`)).toHaveClass(/active/);
      // Every other view panel must be hidden — the router is exclusive.
      for (const [otherView, , otherPanelId] of navCases) {
        if (otherView !== view) {
          await expect(page.locator(otherPanelId)).toBeHidden();
        }
      }
      await expect(page.locator("#view-overview")).toBeHidden();
    });
  }
});
