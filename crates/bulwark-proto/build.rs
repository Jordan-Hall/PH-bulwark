//! Compiles the Bulwark protobuf contract into Rust — hermetically, with no system
//! `protoc`.
//!
//! tonic 0.14 split prost codegen out of `tonic-build` into `tonic-prost-build`,
//! and `compile_protos` otherwise shells out to a system `protoc`. We avoid that
//! dependency by parsing the `.proto` with the pure-Rust `protox` into a
//! `FileDescriptorSet`, writing it to `OUT_DIR`, and feeding it to
//! `tonic-prost-build` with `skip_protoc_run()`. Generates both server + client
//! stubs (one contract for bulwark-client/-infer, bulwark-server, bulwark-cluster).
//! Output is pulled in via `tonic::include_proto!("bulwark.v1")`.

use std::path::PathBuf;

// protox re-exports the exact prost it built the FileDescriptorSet with
// (`pub use {prost, prost_reflect}`). Encode through THAT prost so the
// `Message` trait matches the descriptor type; the bytes are standard protobuf
// that tonic-prost-build reads back with its own prost.
use protox::prost::Message as _;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/bulwark.proto";
    let include = "proto";

    // Pure-Rust parse → FileDescriptorSet (no system protoc required).
    let descriptors = protox::compile([proto], [include])?;
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let fds_path = out_dir.join("bulwark_fds.bin");
    std::fs::write(&fds_path, descriptors.encode_to_vec())?;

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        // Derive serde on the wire types so bulwark-store / bulwark-ui can persist
        // and render verdicts/alerts without a parallel DTO layer.
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .file_descriptor_set_path(&fds_path)
        .skip_protoc_run()
        .compile_protos(&[proto], &[include])?;

    // Only re-run codegen when the contract itself changes.
    println!("cargo:rerun-if-changed={proto}");
    Ok(())
}
