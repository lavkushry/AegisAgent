import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";

import NotePanel from "./NotePanel";
import type { PanelDefinition } from "../types";

const EMPTY_FRAME = { fields: [], length: 0, meta: { total: 0 } };

describe("NotePanel", () => {
  it("renders static metric copy without requiring data rows", () => {
    const definition: PanelDefinition = {
      id: "note-1",
      type: "note",
      title: "Metric",
      datasourceId: "gateway-entity",
      options: { body: "Deny rate = denies / decisions over 24h.", variant: "info" },
    };
    const html = renderToStaticMarkup(
      <NotePanel
        definition={definition}
        data={EMPTY_FRAME}
        timeRange={{ from: "now-24h", to: "now" }}
        variables={{}}
        onDrilldown={() => {}}
      />,
    );
    expect(html).toContain("Deny rate = denies");
  });

  it("labels advisory metrics explicitly", () => {
    const definition: PanelDefinition = {
      id: "note-2",
      type: "note",
      title: "Risk",
      datasourceId: "gateway-entity",
      options: { body: "Rolling 24h composite risk score.", variant: "advisory" },
    };
    const html = renderToStaticMarkup(
      <NotePanel
        definition={definition}
        data={EMPTY_FRAME}
        timeRange={{ from: "now-24h", to: "now" }}
        variables={{}}
        onDrilldown={() => {}}
      />,
    );
    expect(html).toContain("Advisory only");
  });
});