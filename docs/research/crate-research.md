# Wave A — A1 Crate & Clustering Research

> Findings from research agent A1 (2026-06). Crate **selections and licenses** are the durable
> output; exact patch versions are the agent's best reading and **must be confirmed against the
> live registry at build time** (`cargo add` / `cargo update`). See staged set in root `Cargo.toml`.

## Recommended crates by subsystem

| Subsystem | Crate | Version | License | Notes |
|---|---|---|---|---|
| TUN (Windows) | `wintun` | 0.5 | MIT | native WinTun driver bindings |
| TUN (Linux/macOS) | `tun-rs` | 2.8 | Apache-2.0 | async, multi-queue |
| Android FFI | `jni` | 0.22 | MIT/Apache-2.0 | VpnService shim |
| TLS-inspecting proxy | `hudsucker` | 0.24 | Apache-2.0/MIT | HTTP/S + WebSocket |
| TLS | `rustls` | 0.23 | Apache/MIT/ISC | 0.24 (breaking) coming — stay on 0.23 |
| Async TLS | `tokio-rustls` | 0.26 | MIT | mTLS via features |
| Cert gen | `rcgen` | 0.14 | MIT/Apache-2.0 | per-install CA + leaf certs |
| OS trust store / Win OCR | `windows` | 0.60+ | MIT/Apache-2.0 | Win32 + `Windows.Media.Ocr` |
| ONNX inference | `ort` | 2.0.0-rc.12 | Apache-2.0 | EPs: CPU/CUDA/TensorRT/DirectML/CoreML/NNAPI/QNN; ordered fallback to CPU |
| Video (ffmpeg) | `ffmpeg-sidecar` | 0.5 | Apache-2.0 | **spawn binary — license isolation** |
| gRPC | `tonic` / `tonic-build` | 0.14 | MIT | HTTP/2 + rustls mTLS |
| Protobuf | `prost` | 0.14 | Apache-2.0 | |
| Cluster membership | `foca` | 0.13 | permissive | SWIM; fallback `chitchat` 0.10 (MIT) |
| Postgres (server) | `sqlx` | 0.8 | Apache/MIT | compile-time checked |
| SQLite (client) | `rusqlite` | 0.40 | MIT | `bundled`; SQLCipher via `rusqlcipher`/bundled |
| At-rest crypto | `age` / `ring` | 0.11 / 0.17 | Apache (+ISC) | app-level encryption |
| Email | `lettre` | 0.11 | MIT | SMTP + TLS; Gmail API optional |
| Web | `axum` | 0.8 | MIT | dashboard API |
| Desktop UI | `tauri` | 2.4 | MIT/Apache-2.0 | optional admin dashboard |
| OCR (cross-platform) | `leptess` | 0.14 | MIT | Tesseract — conventional, not vision-LLM |
| Plumbing | `tokio`/`serde`/`figment`/`tracing`/`thiserror`/`anyhow`/`async-trait` | — | MIT/Apache | standard |
| Supply chain | `cargo-deny`, `cargo-audit` | — | MIT/Apache | CI gates (not workspace deps) |

## License red flags / must-isolate

- **ffmpeg binary** → use **only** `ffmpeg-sidecar` (spawned process, not linked). **Forbid `ffmpeg-next`** (FFI = links GPL/LGPL) in the `cargo-deny` allowlist.
- **chitchat** is independently **MIT**, even though parent project Quickwit is AGPLv3 — safe to use the standalone crate.
- **OpenSSL** (pulled by `rusqlcipher`) is system-level, not linked into our binary; `rusqlite` bundled SQLite is public-domain. Prefer app-level `age`/`sqlcipher`.
- Everything else: MIT / Apache-2.0 / ISC / WTFPL — clean.

## SWIM membership decision: `foca` (fallback `chitchat`)

Pure SWIM + Infect/Suspect, `no_std + alloc`, transport-agnostic (rides our mTLS gRPC), no external
daemon, small footprint, proven. Pivot to `chitchat` 0.10 if we need stronger anti-entropy state
sync for nodes rejoining after long outages.

## Maturity risks & fallbacks

- `ort` 2.0-rc — maintainers call it production-ready (used by Google Magika, SurrealDB); fallback `candle`.
- `leptess` stable but ~3y old API; fallback = spawn `tesseract` binary or use `Windows.Media.Ocr`.
- `rustls` 0.24 will require an explicit crypto provider (breaking) — pin 0.23 for now.
- `hudsucker` low churn; fallback = hand-rolled `hyper` + `rustls` TLS inspection (more maintenance).

## ONNX execution-provider note
`SessionBuilder::execution_providers([...])` tries providers in order, **silently falling back to
CPU**. Lets `bulwark-infer` request GPU/NNAPI/CoreML and degrade gracefully per device tier.
