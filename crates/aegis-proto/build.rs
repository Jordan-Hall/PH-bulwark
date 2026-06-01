//! Compiles the Aegis protobuf contract into Rust with tonic-build.
//!
//! Generates both the gRPC **server** and **client** stubs so the same crate
//! serves client (aegis-client / aegis-infer), server (aegis-server), and
//! cluster (aegis-cluster) consumers from one contract. Output lands in
//! `OUT_DIR` and is pulled in via `tonic::include_proto!("aegis.v1")`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/aegis.proto";

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        // Derive serde on the wire types so aegis-store / aegis-ui can persist
        // and render verdicts/alerts without a parallel DTO layer.
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .compile_protos(&[proto], &["proto"])?;

    // Only re-run codegen when the contract itself changes.
    println!("cargo:rerun-if-changed={proto}");
    Ok(())
}
