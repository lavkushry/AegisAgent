import { test, expect } from "@playwright/test";
import { openConfiguredConsole, TENANT_ID } from "./helpers";

test.describe("production SOC console shell", () => {
  test("loads the AegisAgent SOC Console", async ({ page }) => {
    await page.goto("/dashboard/");
    await expect(page).toHaveTitle(/AegisAgent SOC Console/);
    await expect(page.getByRole("heading", { name: "AegisAgent" })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "SOC console" })).toBeVisible();
  });

  test("serves a restrictive Content-Security-Policy header (#1309)", async ({ page }) => {
    const response = await page.goto("/dashboard/");
    expect(response).not.toBeNull();
    const csp = response!.headers()["content-security-policy"];
    expect(csp).toBeTruthy();
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  test("sets a SameSite=Strict CSRF cookie and csrf meta tag (#1308)", async ({ page, context }) => {
    await page.goto("/dashboard/");
    const csrfCookie = (await context.cookies()).find((cookie) => cookie.name === "aegis_csrf");
    expect(csrfCookie).toBeTruthy();
    expect(csrfCookie!.sameSite).toBe("Strict");
    expect(csrfCookie!.httpOnly).toBe(true);
    await expect(page.locator('meta[name="csrf-token"]')).toHaveAttribute("content", /.+/);
  });

  test("keeps production bearer credentials in memory only", async ({ page }) => {
    await openConfiguredConsole(page);
    await expect(page.getByText("Tenant context").locator("..")).toContainText(TENANT_ID);
    expect(await page.evaluate(() => localStorage.getItem("aegis_active_tenant"))).toBe(TENANT_ID);
    expect(await page.evaluate(() => localStorage.getItem("aegis_bearer_token"))).toBeNull();
  });

  const navCases = [
    ["overview", "Overview"], ["dashboards", "Dashboards"],
    ["integrity", "Integrity Console"], ["explore", "Explore"],
    ["incidents", "Incidents"], ["detections", "Detections & Rules"],
    ["approvals", "Approvals"], ["agents", "Agents Fleet"],
    ["mcp", "MCP Servers"], ["receipts", "Receipts Log"],
    ["settings", "Settings"],
  ] as const;

  for (const [view, label] of navCases) {
    test(`navigation opens ${label} with URL-synced state`, async ({ page }) => {
      await openConfiguredConsole(page);
      const navButton = page.getByRole("navigation", { name: "SOC console" }).getByRole("button", { name: label });
      await navButton.click();
      await expect(page).toHaveURL(new RegExp(`[?&]view=${view}(?:&|$)`));
      await expect(navButton).toHaveClass(/bg-\[var\(--brand\)\]/);
    });
  }
});
