fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile_protos(
        &["proto/aegis.proto", "proto/soc.proto", "proto/admin.proto"],
        &["proto"],
    )?;
    Ok(())
}
