# ADR-0001: Cedar as the policy engine

**Status:** Accepted
**Date:** 2026-01 (retroactive — recorded 2026-06)
**Issue:** [#1197](https://github.com/lavkushry/AegisAgent/issues/1197)

## Context

The gateway needs an authorization decision engine for `/v1/authorize`: given
an agent, a tool action, and dynamic context (trust level, mutation flag,
risk tier, MCP manifest hash, …), decide `allow` / `deny` / `require_approval`
/ `quarantine` / `redact` in well under the gateway's own latency budget
(`action_hash` compute + policy decision target: sub-5ms, see
[`AegisAgent_Technical_Design.md`](../AegisAgent_Technical_Design.md)).

The realistic options for a Rust service in 2026 were embedding
[Cedar](https://www.cedarpolicy.com/) (AWS's open-source ABAC engine, native
Rust crate), embedding OPA/Rego via a WASM or process boundary, or hand-rolling
a rule matcher.

## Decision

Embed Cedar (`cedar-policy` crate) directly in the gateway process. Policies
live in `policies.cedar` (root) / `gateway/policies.cedar` (kept identical),
authored against `Agent`/`Action`/`ToolAction` entities with a `context` map
carrying `trust_level`, `mutates_state`, `agent_risk_tier`, `manifest_hash`,
etc. A non-standard third state (`require_approval`, plus later `quarantine`
and `redact`) is layered on top via Cedar policy **annotations**
(`@decision("require_approval")`) read by the gateway after Cedar's native
permit/forbid evaluation — see
[`cedar_policy_authoring.md`](https://github.com/lavkushry/AegisAgent/blob/main/.claude/rules/cedar_policy_authoring.md).

## Consequences

- Sub-millisecond in-process decisions — no RPC/WASM hop, no sidecar to
  operate or version-skew against.
- Policy authors get a real type-checked language (entities, `when` clauses)
  instead of a hand-rolled DSL, and Cedar's own test/validation tooling
  applies directly.
- The `require_approval`/`quarantine`/`redact` states are an AegisAgent-specific
  layer on top of Cedar's native binary permit/forbid — anyone porting
  policies from a pure-Cedar context needs to learn this annotation
  convention; it isn't portable to another Cedar consumer as-is.
- Coupled to the `cedar-policy` crate's release cadence and any breaking
  changes to its entity/schema model land directly on the gateway.

## Alternatives considered

- **OPA/Rego** — mature, language-agnostic, used widely outside Rust shops.
  Rejected for v1 because it means either a WASM runtime embed (immature
  Rust↔Rego data marshaling at the time) or an out-of-process sidecar, both
  adding latency and an operational moving part to the sub-5ms target. Kept
  as a documented "optional adapter later" rather than ruled out permanently
  (see `AegisAgent_Technical_Design.md` §4.6: "OPA/Rego adapter optional
  later").
- **Hand-rolled rule matcher** — fastest to embed, but reinvents policy
  validation, entity modeling, and conflict resolution that Cedar already
  solved; would also forfeit the "native Cedar" positioning called out
  against the free Microsoft toolkit that made the same Cedar+Rust+MCP bet
  (`AegisAgent_Gap_Reassessment_2026-06.md`).

## Revisit when

A customer requires Rego policy portability (e.g., migrating from an
existing OPA-based control plane) at a scale where an adapter is worth
building, or Cedar's roadmap diverges from AegisAgent's annotation-based
extension needs.
