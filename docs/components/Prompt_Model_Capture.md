# Prompt & Model Call Capture

**Status: 🟡 Partial** — untrusted-content ingestion with trust labeling is ✅ implemented; full prompt/model-call capture (the LLM-interaction choke point) is 📐 planned (Phase 7).

## 1. One-sentence summary

This choke point captures what *entered* an agent's context (prompts, external content) and what the model *proposed*, so every executed action has a provable lineage back to its trigger — today the trigger side is implemented via trust-labeled ingestion; capturing the model-call side is roadmap.

## 2. Why it exists

When an incident happens, "which prompt caused this?" is the first question. Without captured lineage you can prove *what* the agent did (receipts) but not *why*. And without source labels at ingestion, trust-provenance gating would have nothing deterministic to gate on.

## 3. What exists today (✅)

- **`POST /v1/ingest`** — external content events (GitHub webhooks with HMAC verification via `AEGIS_GITHUB_WEBHOOK_SECRET`, tickets, generic sources) enter with a **channel-derived trust label** (the 6 levels). Handler in `src/src/routes/mod.rs`; webhook path in `routes/webhooks.rs`.
- **Trust chain propagation** — `lib/policy/src/trust_chain.rs`: the most restrictive upstream label gates downstream actions; classifiers may only tighten.
- **Context in authorize** — SDK calls carry `run_id`/`trace_id`/trust context, so decisions and receipts already link to the triggering run.
- **Evidence graph** — `GET /v1/graph/run/:run_id` links ingested content → decisions → approvals → receipts → alerts.
- **Runtime-event ingest** (`POST /v1/ingest/runtime-events`, #1681) — the transport that prompt/model events will ride.

## 4. What is planned (📐 Phase 7)

- **Prompt event capture:** SDK/sensor-side recording of prompt boundaries (hashed/redacted, never raw secrets) as first-class events.
- **Model call capture:** provider request/response metadata (model, token counts, tool-call proposals) as events — the "model proposed tool X with args hash H" link.
- **Tool-proposal lineage:** binding a proposal hash to the eventual `action_hash`, closing the prompt → proposal → approval → execution → receipt chain end-to-end.
- Roadmap: [AegisAgent_Phased_PR_Plan.md](../AegisAgent_Phased_PR_Plan.md) §Phase 7 ("Prompt/model/tool capture").

## 5. Design principles (binding for the implementation)

1. **Capture is evidence, not authorization.** Decisions stay deterministic; captured text never *loosens* anything.
2. **Redaction by default.** Store hashes/metadata; raw prompt bodies only with explicit tenant opt-in.
3. **Labels at the edge.** Trust comes from the channel at ingestion — a prompt can't launder its own provenance.

## 6. Failure behavior

Ingestion with a bad/missing HMAC (when configured) is rejected. Unlabeled content is `unknown` — which policies treat as requiring approval for mutating actions, not as trusted.

## 7. Related code & docs

Code: `src/src/routes/mod.rs` (`ingest_event`), `src/src/routes/webhooks.rs`, `lib/policy/src/trust_chain.rs`, `lib/soc/src/ingest.rs`.
Docs: [flows/Prompt_To_Action_Lineage.md](../flows/Prompt_To_Action_Lineage.md) · [event-schema.md](../event-schema.md) · [evidence-graph.md](../evidence-graph.md) · [Implementation_Status.md](../Implementation_Status.md)
