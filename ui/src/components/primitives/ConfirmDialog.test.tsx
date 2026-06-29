import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import ConfirmDialog from "./ConfirmDialog";

describe("ConfirmDialog", () => {
  it("requires an audit reason before a dangerous action can be confirmed", () => {
    const html = renderToStaticMarkup(
      <ConfirmDialog
        open
        title="Approve action?"
        impact="This binds the operator to the frozen action hash."
        target="approval-1 · hash-1"
        reason=""
        onReasonChange={vi.fn()}
        confirmDisabled
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />,
    );

    expect(html).toContain("Audit reason");
    expect(html).toContain("required");
    expect(html).toMatch(/<button[^>]*disabled/);
  });
});
