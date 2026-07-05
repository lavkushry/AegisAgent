import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import SeverityBadge from "./SeverityBadge";

describe("SeverityBadge", () => {
  it("renders known severities with distinct tint classes", () => {
    const high = renderToStaticMarkup(<SeverityBadge severity="high" />);
    const medium = renderToStaticMarkup(<SeverityBadge severity="medium" />);
    expect(high.toLowerCase()).toContain("high");
    expect(medium.toLowerCase()).toContain("medium");
    expect(high).not.toEqual(medium);
  });

  it("falls back to neutral styling for unknown severities", () => {
    const html = renderToStaticMarkup(<SeverityBadge severity="unknown" />);
    expect(html.toLowerCase()).toContain("unknown");
    expect(html).not.toContain("text-green");
  });
});