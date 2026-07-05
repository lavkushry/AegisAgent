import { describe, expect, it } from "vitest";

import { fieldsForEntity } from "../fieldCatalog";
import { aqlAutocomplete } from "./autocomplete";

describe("AQL autocomplete", () => {
  it("suggests catalog fields while typing a new term", () => {
    const suggestions = aqlAutocomplete("agent_", 6, fieldsForEntity("decision"));
    expect(suggestions.map((item) => item.label)).toContain("agent_id");
  });

  it("suggests field example values after a colon", () => {
    const input = "decision:";
    const suggestions = aqlAutocomplete(input, input.length, fieldsForEntity("decision"));
    expect(suggestions.map((item) => item.label)).toEqual(expect.arrayContaining(["allow", "deny"]));
  });

  it("suggests boolean operators between terms", () => {
    const input = "agent_id:agent-1 ";
    const suggestions = aqlAutocomplete(input, input.length, fieldsForEntity("decision"));
    expect(suggestions.map((item) => item.label)).toEqual(expect.arrayContaining(["AND", "OR"]));
  });
});