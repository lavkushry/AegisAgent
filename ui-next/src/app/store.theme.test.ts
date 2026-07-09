import { describe, expect, test } from "bun:test";

/**
 * Theme contract tests (no DOM store mount — pure validation of allowed values).
 * Runtime application is covered via AppShell / providers integration later.
 */
const VALID_THEMES = ["dark-soc", "light", "oled"] as const;
const VALID_DENSITIES = ["compact", "cozy"] as const;

function resolveTheme(stored: string | null): (typeof VALID_THEMES)[number] {
  return VALID_THEMES.includes(stored as (typeof VALID_THEMES)[number])
    ? (stored as (typeof VALID_THEMES)[number])
    : "dark-soc";
}

function resolveDensity(
  stored: string | null,
): (typeof VALID_DENSITIES)[number] {
  return VALID_DENSITIES.includes(stored as (typeof VALID_DENSITIES)[number])
    ? (stored as (typeof VALID_DENSITIES)[number])
    : "compact";
}

describe("theme contract", () => {
  test("defaults to dark-soc when missing or invalid", () => {
    expect(resolveTheme(null)).toBe("dark-soc");
    expect(resolveTheme("neon-cyber")).toBe("dark-soc");
    expect(resolveTheme("dark-soc")).toBe("dark-soc");
    expect(resolveTheme("light")).toBe("light");
    expect(resolveTheme("oled")).toBe("oled");
  });

  test("defaults density to compact", () => {
    expect(resolveDensity(null)).toBe("compact");
    expect(resolveDensity("spacious")).toBe("compact");
    expect(resolveDensity("cozy")).toBe("cozy");
  });
});
