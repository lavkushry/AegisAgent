# Mission

> **Make autonomous agent actions *provably* safe — not just decided-upon — and
> give security teams a SOC that operates on that proof.**
>
> **Make the approval trustworthy. Trust the source, not the text. Run the SOC
> on the proof.**

## Product vision

The 2026 gateway market solved the easy half of the problem: a crowded field
of free and commercial tools can now **decide** whether an agent action is
allowed (intercept → policy → allow/deny/approve → audit). AegisAgent exists
to make those decisions **trustworthy** and the resulting record **provable**:

> Every high-risk agent action carries cryptographic proof that the exact
> action a human approved is the action that executed, a deterministic record
> of whether its trigger was trusted, and a tamper-evident receipt that a SOC
> can detect on, correlate over, and an auditor can verify.

```text
Agent wants to act
→ classify the trigger's source trust (deterministic, 6 levels)
→ evaluate policy with source_trust + action_hash as inputs
→ if approval needed: freeze the EXACT action, hash it, bind the human
  decision to that hash
→ SDK executes only if about-to-run hash == approved hash, else FAIL CLOSED
→ emit a verifiable, hash-chained action receipt (evidence)
→ the Agent SOC detects, correlates, and responds on that evidence
```

## Category definition

**AegisAgent is an integrity-anchored Agent SOC** — an *AI runtime defense
platform* for agentic systems, positioned as:

- An **AI Guard System** for the action path: it sits between an agent
  runtime and the outside world and enforces deterministic, fail-closed
  policy on every tool call.
- An **Agentic SOC Platform** for the monitoring/response path: it turns the
  receipt + provenance stream into alerts, correlated incidents, RCA
  narratives, and active response (freeze/revoke/quarantine).
- An **AI Runtime Defense Platform** end to end: the same integrity primitives
  (approval binding, provenance gating, verifiable receipts) drive both the
  inline decision and the SOC built on top of it.

It is **not** a prompt-injection scanner, a generic SIEM, or "the everything AI
security platform." See [What AegisAgent should NOT
become](AegisAgent_Vision.md#10-what-aegisagent-should-not-become) for the
line we hold.

### How AegisAgent differs from adjacent categories

| Category | What it does | What it can't do |
|---|---|---|
| **Prompt guardrails / LLM scanners** | Score input/output text for injection, toxicity, or PII | Operate on *text*, not on the *action* — they can't bind a human approval to the exact tool call that executes, and they can't tell you whether the instruction came from a trusted source |
| **Generic SIEM / SOC** | Ingest arbitrary logs, score events, raise alerts after the fact | No provenance model, no approval-integrity awareness, no provable timeline — "the log says X happened" is not "we can prove X happened and was authorized exactly as approved" |
| **Runtime gateways (commodity, 2026)** | Decide allow/deny/require_approval for a tool call | Decide, but don't *prove the decision held* — an edited or swapped action can still execute between approval and execution unless the approval is hash-bound |
| **AegisAgent** | Binds approvals to a frozen `action_hash`, gates authorization on a deterministic 6-level trust-provenance label, and emits a hash-chained receipt for every decision — then runs a SOC on that evidence | Does not replace the gateway, identity system, or egress firewall you already run — it layers onto them |

## The Five Dimensions

AegisAgent is evaluated against five dimensions. Every feature decision is
weighed against which of these it strengthens — and a feature that
strengthens none of them, or strengthens "coverage" at the cost of the
others, is out of scope.

1. **Speed** — the inline decision path never slows the agent down. Cedar
   policy evaluation stays under 75ms; `/v1/authorize` targets p50 < 10ms,
   p95 < 50ms, p99 < 100ms (see
   [`runtime-authorization-api.md`](runtime-authorization-api.md#latency-expectations)
   and `performance-baseline.md`). The SOC's detection/correlation/response
   plane is asynchronous by construction and can never add latency to that
   path.

2. **Robustness** — every dependency failure (database, policy engine, audit
   pipeline, approval service, MCP registry, gateway itself) has a defined,
   tested **fail-closed** behavior; see
   [`fail-closed-behavior.md`](fail-closed-behavior.md). The `aegis-jcs-1`
   canonicalization scheme is byte-identical across the Python, Go, and
   TypeScript SDKs and the Rust gateway, locked by a shared corpus and
   verified in CI.

3. **Intelligence** — detection and correlation are **deterministic rules**,
   not LLM judgment, so they are explainable and reproducible. One sandboxed
   LLM is used only to *narrate* already-closed incidents from verified
   evidence — it never gates, scores, or reads untrusted instructions.

4. **Coverage** — full-parity SDKs for Python, Go, and TypeScript; an MCP
   Gateway Lite for MCP server/tool governance; agentless ingestion for
   GitHub webhooks and OpenAI traces; and the ability to run standalone or
   layered onto an existing gateway (Microsoft Agent Governance Toolkit,
   MintMCP, Pipelock, etc.).

5. **Trust** — authorization is gated on the deterministic, 6-level
   trust-provenance of the *triggering content* (not a text score), every
   approval is bound to a SHA-256 hash of the frozen exact action, and every
   decision emits a verifiable, hash-chained action receipt suitable as
   SOC 2 / EU AI Act Article 14 evidence.

## The Six Laws

These laws are the non-negotiable constraints that keep AegisAgent from
drifting into "a slightly different generic SIEM." A proposed feature that
violates one of these is out of scope, regardless of how useful it sounds in
isolation.

1. **Deterministic enforcement.** Authorization decisions (`allow` / `deny` /
   `require_approval`) are made by Cedar policy evaluating `source_trust`,
   `mutates_state`, risk tier, and resource — never by an LLM or a similarity
   score. Risk scores and anomaly signals are advisory display data only; see
   [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md#2-the-non-negotiable-design-laws-read-first)
   (Law 1).

2. **Explainable decisions.** Every `/v1/authorize` response carries a
   human-readable `reason` and the list of `matched_policies` that produced
   it; every action receipt records the decision and its inputs, so "why was
   this allowed/denied?" always has a concrete, reproducible answer — see
   [`runtime-authorization-api.md`](runtime-authorization-api.md).

3. **Unknown = deny.** An unrecognized agent, tool, MCP server, or MCP tool is
   denied by default; an action with `trust_level: unknown` triggering a
   mutating call requires approval rather than executing — see the [Fail-closed
   behavior guide](fail-closed-behavior.md).

4. **Audit = product.** The hash-chained action receipt is not a side-effect
   log — it is the evidence spine the SOC, compliance evidence packs, and
   `aegis-verify-receipts` are built on; see
   [`action-receipt-spec.md`](action-receipt-spec.md).

5. **Design for failure.** Every component's failure mode is enumerated and
   tested: database errors, policy-file parse failures, an unreachable
   gateway, an expired or single-use-consumed approval, a full SOC event
   channel. None of these failure modes can turn a `deny` into an `allow` —
   see the [Fail-closed behavior guide](fail-closed-behavior.md).

6. **Safe path > unsafe path.** The default, easiest-to-reach path is the
   secure one: the SDK decorator fails closed with no configuration, the
   Docker Compose quickstart ships with approval integrity and provenance
   gating already enabled, and bypassing any integrity check requires a
   deliberate, visible configuration change — never a silent fallback.

## Further reading

- [`AegisAgent_Vision.md`](AegisAgent_Vision.md) — full vision document and
  category strategy (internal, source of truth for the framing above).
- [`AegisAgent_Gap_Reassessment_2026-06.md`](AegisAgent_Gap_Reassessment_2026-06.md)
  — why the moat is approval integrity + provenance, not the gateway loop.
- [`AegisAgent_Agent_SOC_Design.md`](AegisAgent_Agent_SOC_Design.md) — the Agent
  SOC architecture and its four non-negotiable design laws.
- [Fail-closed behavior guide](fail-closed-behavior.md) — the concrete,
  test-backed behavior behind Laws 3 and 5.
