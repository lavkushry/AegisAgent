import type { CSSProperties } from "react";

/** Token-driven pill: text + hairline border + subtle fill from one CSS var. */
export function pillStyle(colorVar: string, bold = false): CSSProperties {
  return {
    color: `var(${colorVar})`,
    borderColor: `color-mix(in oklab, var(${colorVar}) 40%, transparent)`,
    backgroundColor: `color-mix(in oklab, var(${colorVar}) 16%, transparent)`,
    fontWeight: bold ? 700 : 600,
  };
}
