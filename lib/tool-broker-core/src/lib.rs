//! `aegis-tool-broker-core` — Phase 6.1 (`docs/AegisAgent_Phased_PR_Plan.md`,
//! section 8): the tool broker abstractions. The broker is the credential
//! and tool/API execution choke point: agents describe actions, the broker
//! authorizes them (via the gateway, Phase 6.2), resolves credentials
//! itself, executes through a [`connector::Connector`], and returns
//! sanitized output. **An agent never sees a raw credential.**
//!
//! This crate is the pure core: no I/O toward the gateway, no storage.
//!
//! - [`action`]: [`action::BrokerAction`] mirrors the gateway's
//!   `AuthorizeToolCall` field-for-field and hashes through the shared
//!   `aegis-canon` crate, so the broker-computed `action_hash` is
//!   byte-identical with what the gateway and SDKs compute — the same
//!   hash an approval binds to (`aegis-jcs-1`, locked by test vectors).
//! - [`credential`]: opaque [`credential::CredentialRef`]s resolved by a
//!   [`credential::CredentialResolver`] into [`credential::Secret`]s whose
//!   `Debug`/`Display`/`Serialize` are all redacted.
//! - [`redact`]: key- and value-based scrubbing applied to connector
//!   output and event payloads before anything leaves the broker.
//! - [`connector`]: the plug-in seam ([`connector::Connector`]) real
//!   connectors (Phase 6.3) implement.

pub mod action;
pub mod connector;
pub mod credential;
pub mod redact;

pub use action::{action_hash, canonical_action_string, BrokerAction, CANON_VERSION};
pub use connector::{Connector, ConnectorError, ConnectorOutput};
pub use credential::{
    CredentialRef, CredentialResolver, EnvCredentialResolver, ResolveError, Secret,
    StaticCredentialResolver,
};
pub use redact::{redact_secrets, redact_sensitive_keys, REDACTED};
