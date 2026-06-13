# `platform/android/rust` — the Android JNI bridge

This directory holds the Rust side of `co.predatorhunters.bulwark.core.RustBridge`.

## What's here

```
platform/android/rust/
├── README.md            ← this file
└── bulwark-android/       ← the JNI bridge crate
    ├── Cargo.toml       ← cdylib, detached [workspace], path-deps on the analyzers
    └── src/lib.rs       ← Java_co_predatorhunters_bulwark_core_RustBridge_* exports
```

`bulwark-android` is a **detached** cargo crate (its own empty `[workspace]` table,
like `apps/parent/Cargo.toml`) so it never perturbs the root
`cargo build --workspace`. It builds the C-ABI shared library the app loads with
`System.loadLibrary("bulwark_client")` — i.e. `libbulwark_client.so` (the `[lib]`
name is `bulwark_client`).

It depends, by relative path, on the **legitimate on-device analyzers** only:

| Crate          | Role |
|----------------|------|
| `bulwark-text`   | rules-first deterministic grooming / adult-text detector (`TextAnalyzer`) |
| `bulwark-policy` | `Verdict → Action` policy engine (`Policy`) |
| `bulwark-core`   | shared `Analyzer` trait + flow vocabulary (transitive) |
| `bulwark-proto`  | the wire types (`TextSpan`, `Verdict`, `Category`, …) |

It deliberately does **not** depend on `bulwark-store` / `rusqlite` (which fails to
build on the Windows host, os error 4551 — environmental) — the bridge needs only
the pure analyzers, which have no DB dependency.

This is a TRANSPARENT content-safety bridge: it analyses on-device-rendered text
with the same deterministic pipeline the network path uses and returns a
content-free verdict. It implements **no** device-control / surveillance surface.

## Exported JNI symbols (the `RustBridge.kt` contract)

Symbol convention: `Java_<package '.'→'_'>_<Class>_<method>`, here
`Java_co_predatorhunters_bulwark_core_RustBridge_<method>`.

| Kotlin `external fun`                                                   | JNI symbol |
|------------------------------------------------------------------------|------------|
| `startVpn(tunFd: Int, configJson: String): Long`                       | `Java_co_predatorhunters_bulwark_core_RustBridge_startVpn` |
| `stopVpn(handle: Long)`                                                 | `Java_co_predatorhunters_bulwark_core_RustBridge_stopVpn` |
| `analyzeText(app: String, threadId: String, text: String): String`     | `Java_co_predatorhunters_bulwark_core_RustBridge_analyzeText` |
| `nextAlert(): String?`                                                  | `Java_co_predatorhunters_bulwark_core_RustBridge_nextAlert` |
| `submitReviewDecision(alertId: String, approve: Boolean)`              | `Java_co_predatorhunters_bulwark_core_RustBridge_submitReviewDecision` |
| `registerParentPushToken(token: String)`                               | `Java_co_predatorhunters_bulwark_core_RustBridge_registerParentPushToken` |

`analyzeText` is the fully-implemented path: it runs `TextAnalyzer::analyze_span`
+ `Policy::evaluate` and returns a content-free `Verdict` JSON, e.g.

```json
{"category":"CSAM_SUSPECTED","action":"BLOCK","score":1.0,"report":true,
 "reason":"CSAM suspected: blocked and flagged for legal reporting (report-never-archive)",
 "fired_categories":["image_request"],"redacted_context":"…content-free reason…"}
```

`category` is the stable UPPERCASE string the Kotlin accessibility service
substring-matches on (`"GROOMING"`, `"CSAM"`). The `redacted_context` body is the
**content-free policy reason** — the bridge never forwards raw captured text.
`startVpn` boxes a session and returns its pointer as the opaque `jlong` handle;
`stopVpn` frees it. The intercept loop, alert queue, allowlist persistence and
self-hosted UnifiedPush delivery (FOSS; no Google/Apple) are owned by other crates
(bulwark-net / bulwark-alert / bulwark-store /
bulwark-server); those four exports validate input and no-op safely until that
wiring lands. Every call fails **open** (SAFE / ALLOW or no-op) on bad input.

## Cross-building the `.so` for Android (cargo-ndk)

You need the Android NDK + `cargo-ndk` (`cargo install cargo-ndk`) and the
Android Rust targets:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi
```

Then, from this `bulwark-android` crate directory, build straight into the app's
`jniLibs` (the ABIs match `app/build.gradle.kts` `abiFilters`):

```sh
cd platform/android/rust/bulwark-android
cargo ndk -t arm64-v8a -t armeabi-v7a -o ../../app/src/main/jniLibs build --release
```

This produces:

```
platform/android/app/src/main/jniLibs/arm64-v8a/libbulwark_client.so
platform/android/app/src/main/jniLibs/armeabi-v7a/libbulwark_client.so
```

`app/build.gradle.kts` already wires
`sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")`, so Gradle bundles those
`.so`s into the APK automatically — no Gradle change is required.

> The `-o` path is relative to the crate dir: `../../app/src/main/jniLibs`
> (`bulwark-android` → `rust` → `android`, then `app/src/main/jniLibs`).

## Host build (verification on a machine without the NDK)

You cannot cross-compile to Android without the NDK, but the crate builds for the
**host** target, which type-checks every JNI signature against `RustBridge.kt`:

```sh
cd platform/android/rust/bulwark-android
cargo build          # builds the cdylib for the host
cargo test           # runs the analysis/serialization unit tests
```
