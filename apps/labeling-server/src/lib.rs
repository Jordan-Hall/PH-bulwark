//! PH Bulwark labeling service library.
//!
//! The `store` module is the pure-Rust core (loads tasks, serves them in
//! active-learning order, records human labels as `corrections.jsonl`). The
//! `server` feature adds the axum HTTP/JSON transport (see `src/main.rs`).
pub mod store;
