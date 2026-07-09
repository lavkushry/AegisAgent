import { test, expect } from "../fixtures/guardedTest";
import { openConfiguredConsole, openNav, TENANT_ID } from "./helpers";

/**
 * Phase 4 — Bun SPA (ui-next) shell contracts.
 * Gateway injects CSRF meta + cookie; SPA is served at /dashboard/.
 */
test.describe("production SOC console shell (ui-next)", () => {
  test("loads the AegisAgent SOC Console", async ({ page }) => {
    await page.goto("/dashboard/");
    await expect(page).toHaveTitle(/AegisAgent SOC Console/);
    await expect(page.getByRole("heading", { name: "AegisAgent" })).toBeVisible();
    await expect(
      page.getByRole("navigation", { name: "SOC console" }),
    ).toBeVisible();
  });

  test("serves a restrictive Content-Security-Policy header (#1309)", async ({
    page,
  }) => {
    const response = await page.goto("/dashboard/");
    expect(response).not.toBeNull();
    const csp = response!.headers()["content-security-policy"];
    expect(csp).toBeTruthy();
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  test("sets a SameSite=Strict CSRF cookie and csrf meta tag (#1308)", async ({
    page,
    context,
  }) => {
    await page.goto("/dashboard/");
    const csrfCookie = (await context.cookies()).find(
      (cookie) => cookie.name === "aegis_csrf",
    );
    expect(csrfCookie).toBeTruthy();
    expect(csrfCookie!.sameSite).toBe("Strict");
    expect(csrfCookie!.httpOnly).toBe(true);
    await expect(page.locator('meta[name="csrf-token"]')).toHaveAttribute(
      "content",
      /.+/,
    );
  });

  test("keeps production bearer credentials in memory only", async ({
    page,
  }) => {
    await openConfiguredConsole(page);
    await expect(page.getByText("Tenant context").locator("..")).toContainText(
      TENANT_ID,
    );
    expect(
      await page.evaluate(() => localStorage.getItem("aegis_active_tenant")),
    ).toBe(TENANT_ID);
    expect(
      await page.evaluate(() => localStorage.getItem("aegis_bearer_token")),
    ).toBeNull();
  });

  const navCases = [
    ["/", "Overview"],
    ["/approvals", "Approvals"],
    ["/detections", "Detections"],
    ["/rules", "Rules"],
    ["/alerting", "Alerting"],
    ["/integrity", "Integrity"],
    ["/explore", "Explore"],
    ["/incidents", "Incidents"],
    ["/agents", "Agents"],
    ["/mcp", "MCP"],
    ["/dashboards", "Dashboards"],
    ["/settings", "Settings"],
  ] as const;

  for (const [path, label] of navCases) {
    test(`navigation opens ${label}`, async ({ page }) => {
      await openConfiguredConsole(page);
      await openNav(page, label);
      const expected =
        path === "/"
          ? /\/dashboard\/?$/
          : new RegExp(`/dashboard${path.replace("/", "\\/")}\\/?$`);
      await expect(page).toHaveURL(expected);
      const navLink = page
        .getByRole("navigation", { name: "SOC console" })
        .getByRole("link", { name: label });
      await expect(navLink).toHaveClass(/bg-\[var\(--brand-subtle\)\]/);
    });
  }

  test("ControlsBar exposes time range and live toggle", async ({ page }) => {
    await openConfiguredConsole(page);
    await openNav(page, "Overview");
    const rangeGroup = page.getByRole("group", { name: "Time range" });
    await expect(rangeGroup).toBeVisible();
    await expect(rangeGroup.getByRole("button", { name: "24h" })).toBeVisible();
    await rangeGroup.getByRole("button", { name: "7d" }).click();
    await expect(rangeGroup.getByRole("button", { name: "7d" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    const live = page.getByRole("button", { name: /Live( off)?/ });
    await expect(live).toBeVisible();
    await live.click();
    await expect(page.getByRole("button", { name: /Live( off)?/ })).toBeVisible();
  });

  test("exposes skip-to-main-content target", async ({ page }) => {
    await page.goto("/dashboard/");
    await expect(page.locator("#main-content")).toHaveCount(1);
    await expect(
      page.getByRole("link", { name: "Skip to main content" }),
    ).toHaveAttribute("href", "#main-content");
  });
});
