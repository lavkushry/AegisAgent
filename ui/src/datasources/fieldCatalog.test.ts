import { describe, expect, it } from "vitest";

import { ALL_ENTITY_KINDS, fieldsForEntity } from "./fieldCatalog";

describe("field catalogs", () => {
  it("covers every datasource entity with non-empty descriptors", () => {
    expect(ALL_ENTITY_KINDS).toEqual([
      "ase",
      "decision",
      "incident",
      "alert",
      "approval",
      "agent",
      "mcp_server",
      "receipt",
      "rule",
    ]);

    for (const entity of ALL_ENTITY_KINDS) {
      expect(fieldsForEntity(entity).length, `${entity} should have descriptors`).toBeGreaterThan(0);
    }
  });

  it("does not define duplicate field names per entity", () => {
    for (const entity of ALL_ENTITY_KINDS) {
      const names = fieldsForEntity(entity).map((field) => field.name);
      expect(new Set(names).size, `${entity} should not duplicate field names`).toBe(names.length);
    }
  });

  it("keeps integrity proof fields typed as non-facetable hashes", () => {
    for (const entity of ["ase", "decision", "approval", "mcp_server", "receipt"] as const) {
      const hashFields = fieldsForEntity(entity).filter((field) => field.name.endsWith("_hash"));
      expect(hashFields.length, `${entity} should expose hash proof fields`).toBeGreaterThan(0);
      for (const field of hashFields) {
        expect(field.type, `${entity}.${field.name}`).toBe("hash");
        expect(field.facetable, `${entity}.${field.name}`).toBe(false);
      }
    }
  });

  it("does not mark JSON payload fields as facetable", () => {
    for (const entity of ALL_ENTITY_KINDS) {
      const jsonFields = fieldsForEntity(entity).filter((field) => field.type === "json");
      for (const field of jsonFields) {
        expect(field.facetable, `${entity}.${field.name}`).toBe(false);
      }
    }
  });
});
