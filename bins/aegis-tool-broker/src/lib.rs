//! `aegis-tool-broker` — Phase 1 extraction of the in-gateway tool broker
//! into a standalone binary (roadmap: "Tool broker | Partial | In-gateway
//! execute path; no standalone broker service").
//!
//! **Scope of this phase**: the gateway process no longer links
//! `aegis-tool-broker-connectors` and never resolves a real provider
//! credential or executes a shell command. The gateway still owns tool
//! CRUD, `action_hash` computation, and atomic approval consumption — it
//! sends this binary a fully-resolved request (an already-consumed
//! approval, if any) and this binary does only: tool-active check,
//! connector-registry lookup, credential resolution, connector execution,
//! and output sanitization (all via the unmodified
//! `aegis_tool_broker_connectors::BrokerExecutor`).
//!
//! This is deliberately *not* the full docs-aspirational topology (this
//! binary does not call the gateway's `/v1/authorize` itself, and there is
//! no scoped per-run agent token — see `docs/components/Tool_Broker.md`).

pub mod auth;
pub mod dto;
pub mod error;
pub mod executor_config;
pub mod handlers;
