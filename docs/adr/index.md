# Architecture Decision Records

**Issue:** [#1197](https://github.com/lavkushry/AegisAgent/issues/1197)

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
