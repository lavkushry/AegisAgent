# Architecture Decision Records

**Issue:** [#1197](https://github.com/lavkushry/AegisAgent/issues/1197)

> **Status:** ADR-0001 through ADR-0005 are Accepted. ADR-0006 through ADR-0008
> are Proposed and permit only unwired prototypes until accepted. A changed
> decision requires a new ADR and a supersedes link; do not silently rewrite
> historical rationale.

## Why ADRs Exist

Records of significant architectural decisions and the reasoning behind them
— not a design spec (see [Technical design](../AegisAgent_Technical_Design.md)
for that) but the *why*, so a later reader doesn't have to re-derive a
decision from scratch or accidentally re-litigate one that was already made
deliberately. New ADRs are required for future architectural changes — see
[`blueprint.md`](https://github.com/lavkushry/AegisAgent/blob/main/.claude/rules/blueprint.md) for when a change needs a
blueprint/plan before code, which is a related but distinct requirement.

Use [`template.md`](template.md) for new entries. Number sequentially; never
edit a published ADR's decision after the fact — if a decision changes, write
a new ADR and mark the old one "Superseded by ADR-NNNN."

| ADR | Decision |
|---|---|
| [0001](0001-cedar-policy-engine.md) | Cedar as the policy engine |
| [0002](0002-sqlite-first-storage.md) | SQLite as the default storage backend (Postgres at scale) |
| [0003](0003-aegis-jcs-1-canonicalization.md) | `aegis-jcs-1` canonicalization scheme for `action_hash` |
| [0004](0004-ed25519-receipt-signing.md) | Ed25519 for optional receipt signing |
| [0005](0005-fail-closed-defaults.md) | Fail-closed defaults for unknown/ambiguous state |
| [0006](0006-cache-padded-spsc-event-fabric.md) | Cache-padded SPSC descriptor fabric (Proposed) |
| [0007](0007-sealed-generation-tagged-slab-pages.md) | Sealed generation-tagged slab-page ownership oracle (Proposed) |
| [0008](0008-append-only-published-prefix-slab-pages.md) | Append-only published-prefix slab pages (Proposed) |

## Security and Review

An ADR affecting identity, tenant isolation, canonicalization, approvals, receipts, policy authority, cryptography, runtime isolation, storage consistency, or fail-closed behavior requires security review and negative acceptance tests. Record residual risk and operational consequences, not only architectural elegance.

## Creating an ADR

```bash
cp docs/adr/template.md docs/adr/NNNN-short-decision-name.md
```

Replace every placeholder, link the issue/design, compare alternatives, name verification, and add the new record here and to MkDocs navigation.

## References

[Architecture Patterns](../architecture.md) · [Technical Design](../AegisAgent_Technical_Design.md) · [Threat Model](../AegisAgent_Threat_Model.md) · [Documentation Standard](../contributing/documentation-standard.md)
