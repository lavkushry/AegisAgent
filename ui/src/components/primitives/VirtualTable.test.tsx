// @vitest-environment happy-dom

import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import VirtualTable, { DEFAULT_VIRTUAL_OVERSCAN } from "./VirtualTable";

type Row = { id: string; value: string };

function buildRows(count: number): Row[] {
  return Array.from({ length: count }, (_, index) => ({
    id: `row-${index}`,
    value: `value-${index}`,
  }));
}

describe("VirtualTable", () => {
  it("renders only a window of rows for large datasets", () => {
    const rows = buildRows(10_000);
    const { container } = render(
      <VirtualTable
        rows={rows}
        maxHeight={200}
        rowHeight={28}
        getRowKey={(row) => row.id}
        columns={[
          { key: "id", header: "ID", cell: (row) => row.id },
          { key: "value", header: "Value", cell: (row) => row.value },
        ]}
      />,
    );

    const mountedRows = container.querySelectorAll("tbody tr[data-index]");
    const viewportRows = Math.ceil(200 / 28) + DEFAULT_VIRTUAL_OVERSCAN * 2;

    expect(mountedRows.length).toBeGreaterThan(0);
    expect(mountedRows.length).toBeLessThan(viewportRows + 4);
    expect(mountedRows.length).toBeLessThan(200);
    expect(container.querySelector("[data-virtual-table]")?.getAttribute("data-row-count")).toBe(
      "10000",
    );
  });

  it("renders all rows when the dataset is small", () => {
    const rows = buildRows(12);
    const { container } = render(
      <VirtualTable
        rows={rows}
        maxHeight={480}
        getRowKey={(row) => row.id}
        columns={[{ key: "id", header: "ID", cell: (row) => row.id }]}
      />,
    );

    expect(container.querySelectorAll("tbody tr[data-index]").length).toBe(12);
  });
});