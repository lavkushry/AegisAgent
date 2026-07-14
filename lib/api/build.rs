fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Wired v1 control/SOC/admin surfaces. Kept in a dedicated configure call so
    // generation stays byte-identical as the v2 skeleton is introduced beside it.
    tonic_build::configure().compile_protos(
        &["proto/aegis.proto", "proto/soc.proto", "proto/admin.proto"],
        &["proto"],
    )?;

    // Unwired v2 wire-contract skeleton (Proposed ADR-0011, docs/LLD.md §22).
    // Opaque telemetry/analytics payloads map to `bytes::Bytes` so ingest and
    // query streaming avoid a forced `Vec<u8>` clone (LLD §22 requirement).
    tonic_build::configure()
        .bytes([
            ".aegis.v2.IngestFrame.flatbuffer_frame",
            ".aegis.v2.ArrowChunk.ipc_message",
        ])
        .compile_protos(&["proto/aegis_v2.proto"], &["proto"])?;

    Ok(())
}
