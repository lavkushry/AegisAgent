//! `aegis-llm-gateway` — Phase 7.3 (`docs/AegisAgent_Phased_PR_Plan.md` §9):
//! the LLM gateway adapter / prompt–model-call choke point.
//!
//! An OpenAI-compatible reverse proxy that sits between an agent and an
//! upstream model provider. For every proxied completion request it:
//!
//! 1. Emits a local `model_call_started` event (hashes + model metadata only).
//! 2. Forwards the request to the configured upstream.
//! 3. Emits `model_call_finished` with response hash, token counts, and status.
//! 4. Ships a lineage record to the gateway's `POST /v1/ingest/model-calls`
//!    (Phase 7.1) when a gateway URL is configured.
//!
//! **Redaction by construction:** raw request/response bodies never leave this
//! process toward the control plane — only SHA-256 hashes and (optionally) a
//! secret-scrubbed, length-bounded prompt preview. Failures are scrubbed with
//! the same secret markers the gateway rejects on ingest
//! (`src/src/routes/prompt_capture.rs` `UNREDACTED_MARKERS`).

pub mod capture;
pub mod error;
pub mod events;
pub mod gateway_client;
pub mod proxy;
pub mod redact;
