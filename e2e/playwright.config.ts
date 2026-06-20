import { defineConfig, devices } from "@playwright/test";

// AEGIS_DASHBOARD_URL lets CI/local runs point at a gateway that isn't on
// the default loopback port (e.g. a docker-compose mapping or a remote dev
// instance) without editing this file.
const baseURL = process.env.AEGIS_DASHBOARD_URL || "http://127.0.0.1:8080";

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  // Chromium only: this is an internal SOC admin console, not a public
  // surface, so we trade cross-browser coverage for a faster CI loop.
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
