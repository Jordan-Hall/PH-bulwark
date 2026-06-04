# Aegis — Integration TODO (Wave D)

All crates are implemented. **Build status — verified on the Windows dev host
(`cargo build`, network on):** the **15 non-SQLite crates compile cleanly** —
`aegis-proto` (tonic/protox codegen), `aegis-core`, `aegis-net` (Wintun + MITM +
DPAPI FFI), `flow`, `vision`, `audio`, `video`, `text`, `policy`, `alert`, `infer`,
`cluster`, `server`, `supervision`. The 3 SQLite-backed crates (`aegis-store`,
`aegis-client`, `aegis-ui`) could NOT be built **on this host**: Windows Application
Control blocks executing the `libsqlite3-sys` build-script binary (os error 4551) —
an environmental policy, not our code (the `cfg_select`/version issues were resolved).
They build on CI / Linux (`.github/workflows/ci.yml`). The drift items below are now
**DONE** except where noted; this is the record of what was fixed.

## 1. Hoist shared types into `aegis-core` (biggest item)
Several types were defined independently by multiple crates and must become one:
- ✅ **DONE** — `CapturedFlow`, `FlowPayload`, `HttpHead`, `Header`, `InterceptDecision`, and
  `AnalysisUnit` now live canonically in **`aegis-core::flow`**; `aegis-net` and `aegis-flow`
  re-export them (the SAME type), and the `aegis-client` adapter was deleted. `aegis-net::convert`
  builds `FlowPayload::Http` from its flat proxy flow.
  - ✅ **DONE** — `aegis-net`'s proxy now captures the response **Content-Type**
    (`proxy.rs::content_type_of` → `ProxyFlow.content_type`) and `interceptor.rs`
    plumbs it into the canonical `HttpHead.content_type`, so `aegis-flow`'s
    content-type fast-path engages (`classify.rs` uses explicit Content-Type before
    falling back to manifest/magic/extension sniffing). Covered by
    `interceptor.rs` tests (`convert_surfaces_full_image_body_and_content_type`,
    `convert_*_video_mp2t`).
  - **Divergence found (reconcile, don't just rename):** `aegis-net::FlowPayload` is a flat
    struct `{method, uri, bytes, is_response}`; `aegis-flow::FlowPayload` is an enum
    `Http(HttpHead{method,path,status,headers,body_peek}) | StreamChunk{data,mime_type,url}`.
    **Adopt flow's richer model as canonical.** `aegis-client::convert_payload` now builds an
    `Http` head from net's fields, BUT net does not yet surface response **Content-Type/headers**
    — `aegis-net`'s proxy `ProxyFlow` must capture them so `aegis-flow`'s content-type fast-path
    works (today it falls back to magic-byte + URL-extension sniffing on `body_peek`). Note
    `aegis-flow::AnalysisUnit::VideoSegment` also carries a `segment_id` field used to apply the
    verdict back to the buffered bytes — preserve it through the router.
- ✅ **DONE** — `AnalysisUnit` is canonical in `aegis-core::flow` (re-exported by `aegis-flow`).
- ✅ **DONE** — `Analyzer` trait is canonical in `aegis-core::analyze` (handles + analyze +
  default analyze_batch); all six crates (server/vision/audio/video/text/infer) implement that one.
  Text's streaming moved to an inherent `analyze_stream` (the canonical trait is non-streaming).
- ✅ `AgeProfile` (policy) now impls `Default` (= Teen) + `Clone` for the client. `Route` stays
  local to `aegis-infer` (only it uses it) — fine as-is.

## 2. Confirm cross-crate public APIs the wiring assumes
- `aegis_text::TextAnalyzer::analyze_span(&str, &TextSpan, i64) -> Verdict` (used by
  `aegis-server` `TextAnalyzerAdapter` and `aegis-client`).
- `aegis_net::NetInterceptor::new(NetConfig)` + `CapturedFlow`/`FlowPayload` field names
  (used by `aegis-client::adapt_flow`; `FlowPayload::from_net` is a placeholder).
- `aegis_policy::{Policy::default(), PolicyContext{device,source_channel,age_profile}, AgeProfile::default()}`.
- `aegis_store::SqliteStore::open_in_memory() -> Arc<dyn Store>` (used by `aegis-ui` main) — implement or rename.
- `aegis_core::DeviceId` path (prelude) vs `aegis_core::ids::DeviceId` (used by `aegis-agent`).
- `aegis_alert::AlertSink` object-safety + `EmailAlertSink` construction from config.

## 3. tonic codegen specifics — ✅ MOSTLY DONE
- ✅ tonic 0.14 codegen split handled: added `tonic-prost` (runtime) + `tonic-prost-build`/`protox`
  (build); `aegis-proto/build.rs` now compiles hermetically (no system `protoc`) via protox +
  `skip_protoc_run`. ✅ assoc-type names verified correct (`AnalyzeStreamStream`, `WatchHealthStream`).
- REMAINING: confirm `tonic::include_proto!` still resolves in 0.14 vs `tonic_prost::include_proto!`
  at the first online build.

### (original notes, now resolved)
- Generated server trait method/assoc-type names: `Analysis::AnalyzeStreamStream`,
  `ClusterControl::WatchHealthStream` — match the names in `aegis-cluster/src/service.rs`
  and `aegis-server/src/service.rs`.
- Streaming trait methods use `futures_core::stream::BoxStream`; reconcile with
  `tonic::Streaming<T>` on the server side (interfaces.md note).
- Confirm `tonic = features=["tls-ring"]` resolves (was the `tls` bug aegis-alert caught).

## 4. Workspace / tooling
- Add to `[workspace.dependencies]` + a new `deny.toml` allowlist: `sysinfo`, `aho-corasick`,
  `regex`, `toml`, `bytes`, `futures-core`, `futures-util`, `windows`, `ring`, `age`, `rusqlite`,
  `sqlx`, `leptess`, `ort`, `ffmpeg-sidecar`, `foca`, `tempfile`. Run `cargo deny check` (license + advisory gate).
- `rusqlite` feature is `bundled-sqlcipher` workspace-wide (already aligned) — ensure no crate pulls plain `bundled`.

## 5. First green build sequence (on a networked machine)
```
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace -- -D warnings
cargo deny check
```
Then enable features incrementally: `-p aegis-text --features classifier`,
`-p aegis-vision/-audio --features onnx`, `-p aegis-video --features ffmpeg`,
`-p aegis-ui --features llm-explain`.

## 6. Runtime prerequisites
- **ffmpeg** binary installed (aegis-video). `winget install Gyan.FFmpeg`.
- **Model artifacts** downloaded + SHA256-pinned in config (NSFW image, audio head, text classifier).
- **Per-install CA**: first run generates it (aegis-net) and installs to the Windows trust store (admin/UAC).

## 7. Security + verification gates (before any real deployment)
- `/security-review` pass, with focus on `aegis-net` (CA key handling, the 3 unsafe FFI modules, trust-store install).
- Re-read `docs/security/threat-model.md` §residual-risk and `legal-consent.md` (per-jurisdiction legal review — wiretap/two-party consent for on-device OCR of E2E plaintext).
- Tune grooming + NSFW thresholds against a labeled eval set to control false positives.
