import { describe, expect, it } from "vitest";

import { fieldsForEntity } from "../../datasources/fieldCatalog";
import { descriptorFacets } from "./FieldSidebar";

describe("FieldSidebar descriptor facets", () => {
  it("derives decision facets from typed descriptors", () => {
    expect(descriptorFacets(fieldsForEntity("decision"))).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: "decision", type: "decision" }),
        expect.objectContaining({ key: "source_trust", type: "trust", altKeys: ["root_trust_level"] }),
        expect.objectContaining({ key: "tool", type: "string", altKeys: ["skill", "tool_name"] }),
        expect.objectContaining({ key: "agent_id", type: "string" }),
      ]),
    );
  });

  it("does not expose non-facetable hashes or JSON fields as facets", () => {
    const facetKeys = descriptorFacets(fieldsForEntity("decision")).map((field) => field.key);

    expect(facetKeys).not.toContain("action_hash");
    expect(facetKeys).not.toContain("receipt_hash");
    expect(facetKeys).not.toContain("matched_policy_ids");
  });
});
