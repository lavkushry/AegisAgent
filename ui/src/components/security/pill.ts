import type { CSSProperties } from "react";

/**
 * Build a token-driven pill style (text + hairline border + subtle fill)
 * from a single CSS custom property, so badges follow the active theme.
 * `color-mix` keeps the fill/border translucent without hardcoding alpha
 * hexes per theme.
 */
export function pillStyle(colorVar: string, bold = false): CSSProperties {
  return {
    color: `var(${colorVar})`,
    borderColor: `color-mix(in oklab, var(${colorVar}) 40%, transparent)`,
    backgroundColor: `color-mix(in oklab, var(${colorVar}) 16%, transparent)`,
    fontWeight: bold ? 700 : 600,
  };
}
