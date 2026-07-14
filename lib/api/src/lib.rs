//! aegis-api library.
pub mod dashboard_schema;
pub mod graph;
pub mod models;
pub mod records;

#[cfg(test)]
mod wire_v2_tests;

pub mod grpc {
    pub mod aegis {
        tonic::include_proto!("aegis");
    }

    /// Unwired v2 wire-contract skeleton (Proposed ADR-0011, docs/LLD.md §22).
    ///
    /// Generated types compile but are not served or dialed by any production
    /// path. They exist so the v2 control contract can be reviewed, fuzzed, and
    /// converted against the current REST model before any `shadow` wiring.
    pub mod aegis_v2 {
        tonic::include_proto!("aegis.v2");
    }
}
