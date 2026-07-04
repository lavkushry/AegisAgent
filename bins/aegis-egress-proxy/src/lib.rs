//! `aegis-egress-proxy` — Phase 5.3 (`docs/AegisAgent_Phased_PR_Plan.md`,
//! section 7): the proxy binary skeleton. An explicit HTTP proxy (CONNECT
//! tunneling plus absolute-form HTTP forwarding) that gates every outbound
//! connection on an [`decider::EgressDecider`] verdict before a single
//! byte reaches the destination.
//!
//! Two decision backends exist: [`decider::GatewayDecider`] asks the
//! gateway's `POST /v1/egress/check` (Phase 5.2), which layers ban and
//! quarantine state on top of the rules and durably evidences the outcome;
//! [`decider::PolicyDecider`] evaluates an in-process
//! `aegis_egress::EgressPolicy` for standalone/dev use. Both fail closed:
//! an unreachable gateway is a deny, never a pass-through.
//!
//! Metadata capture is best-effort per the plan ("DNS/HTTP/SNI metadata
//! where possible"): the CONNECT target and absolute-form URI give the
//! destination host directly, and the first bytes of a CONNECT tunnel are
//! inspected for a TLS ClientHello SNI, which must match the CONNECT host
//! (a mismatch is a domain-fronting/exfil signature and closes the
//! tunnel). Transparent-mode interception and DNS proxying are later
//! phases, not this skeleton.

pub mod decider;
pub mod error;
pub mod events;
pub mod metadata;
pub mod proxy;
