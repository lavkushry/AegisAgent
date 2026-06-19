# ADR-0005: Fail-closed defaults for unknown/ambiguous state

**Status:** Accepted
**Date:** 2026-01 (retroactive — recorded 2026-06)
**Issue:** [#1197](https://github.com/lavkushry/AegisAgent/issues/1197)

## Context

An authorization gateway sits on the critical path of every tool call an
agent makes. Every component on that path will eventually see a case its
author didn't anticipate: an unregistered agent, an unrecognized MCP tool, a
gateway the SDK can't reach, an approval that's expired or already consumed,
a hash that doesn't match what was approved. The product's core promise —
"the SDK fails closed if a different/edited/expired action would execute"
(`CLAUDE.md` §"What AegisAgent is") — only holds if every one of these
ambiguous cases is decided in the same direction.

## Decision

Default every unknown, ambiguous, or unreachable state to deny/refuse, never
to allow:

- Unknown agent, unknown tool, unknown MCP server/tool → deny.
- Critical-risk action → deny by default; high-risk → require approval by
  default.
- The SDK refuses to execute the protected tool on `action_hash` mismatch,
  on approval expiry, or when the gateway is unreachable for a
  mutating/high-risk action — it does not "fail open" to keep the agent
  unblocked.
- Approvals are single-use, atomically consumed before execution — a second
  attempt to use the same approval is rejected, not silently re-decided.
- Trust-provenance classification only ever *tightens*, never loosens
  (`trust_chain::propagate` for multi-hop agent chains): a downstream agent's
  effective trust can't exceed the most restrictive level seen anywhere
  upstream, even if it self-reports a more trusting context.

This is enforced as a standing invariant (`CLAUDE.md` §"Critical invariants
(do not weaken)") checked in code review (`security_scan.md` §"Secure
Defaults Audit") rather than left as an implicit convention.

## Consequences

- An attacker (or a bug) that produces an unrecognized or malformed request
  is denied by construction, without needing a matching policy rule to catch
  every possible malformed shape — the default *is* the safety net.
- This trades availability for safety: a gateway outage, a network blip, or
  an unreachable approval store blocks mutating/high-risk actions rather
  than letting them through. For a security control, this is the correct
  trade — but it means gateway/SDK reliability work (timeouts, retries,
  graceful degradation for read-only/low-risk paths) carries more weight
  than it would for a typical CRUD service, since "the security control was
  briefly down" must never become "actions executed unchecked."
- Every new feature that introduces a new kind of "unknown" state (a new
  resource type, a new trust level, a new agent-chain hop) has to be audited
  against this rule explicitly — fail-closed isn't self-enforcing across new
  code paths; it has to be re-applied deliberately each time.
- Single-use approval consumption and tighten-only trust propagation are
  themselves *consequences* of taking fail-closed seriously at the protocol
  level, not just the individual-request level — they close replay and
  confused-deputy classes of attack that a request-by-request fail-closed
  check alone wouldn't catch.

## Alternatives considered

- **Fail open on gateway unreachability, log and alert instead** — keeps the
  agent unblocked during an outage, but defeats the entire point of an
  authorization gateway: an attacker who can induce an outage (or simply
  waits for one) gets unchecked execution exactly when they want it most.
- **Default-allow with an explicit deny-list** — lower friction for new tool
  onboarding (nothing needs registering before it works), but means every
  unregistered tool is implicitly trusted, which is the opposite of the
  product's confused-deputy and provenance-gating thesis.

## Revisit when

No planned revisit — this is a foundational invariant of the product, not a
tradeoff expected to flip with scale or a new deployment tier. A change here
would need to be a deliberate, reviewed decision, not an incidental side
effect of unrelated work.
