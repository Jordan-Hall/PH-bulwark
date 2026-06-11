# Bulwark — the app suite (child app + parent app, four OSes)

Two apps over one shared Rust core, native on **Android / iOS / Windows / macOS**.

```
                         ┌──────────────────────────────┐
   shared Rust core ───► │ crates/bulwark-*  (engine)      │ ◄─── one codebase, all platforms
   (already built)       │ proto · net · flow · vision · │
                         │ audio · video · text · policy │
                         │ alert · infer · cluster · store│
                         └──────────────┬───────────────┘
            ┌───────────────────────────┴───────────────────────────┐
            ▼                                                         ▼
   CHILD app (per-OS native, wraps the core)              PARENT app (one Dioxus codebase)
   — must be native for traffic capture —                 apps/parent  (all-Rust, no FFI)
                                                          alerts · approve/deny · coverage
```

## Parent app — `apps/parent` (Dioxus, all-Rust)
- One Rust crate, RSX UI, **directly uses `bulwark-proto`'s gRPC clients** (`AlertRelay`,
  `Review`) over mTLS — no FFI bridge, no JS. `desktop` feature → Windows + macOS;
  `mobile` (experimental) → Android/iOS; bumps to the **native Blitz renderer** (no
  webview) at 0.7/0.8.
- Scope: review alerts, **approve / keep-blocked**, honest coverage matrix. **No**
  device-control / screen / location / remote-command surface (that's out — see below).
- Server/account plan: choose UK/London, US, or self-hosted server; log in as a
  guardian; create short-lived pairing codes for child devices. See
  [`app-pairing-and-regions.md`](app-pairing-and-regions.md).

## Child app — native per OS, same core
The on-device filter must be native because traffic capture is a kernel/OS feature:

| OS | Capture mechanism | Status / notes |
|---|---|---|
| **Windows** | Wintun TUN + TLS inspection (`bulwark-net`) | built |
| **Android** | `VpnService` + accessibility (`platform/android`) | built (transparent) |
| **macOS** | Network Extension — `NEFilterDataProvider` / Packet Tunnel + Rust core | to build (Swift shell) |
| **iOS** | Network Extension content filter + Rust core | to build; **content-filtering + alerts only** |

Each is a thin native shell (Kotlin / Swift / Rust) hosting the **same** Rust core
(`cargo-ndk` for Android, a static lib + Swift for Apple, native on Windows).
The child shell has enrollment UI only: choose the same server as the guardian,
redeem a pair code, persist `device_id`/`child_id`/`family_id`, then run filtering.

## Honest platform limits
- **iOS/macOS**: Apple's Network Extension content filter is the sanctioned path
  (same API Screen Time/MDM use). Apple **forbids** third-party apps from reading
  other apps' messages, capturing the screen, or blocking their own uninstall — so
  the Apple child app is **filter + alerts**, nothing more.
- **Dioxus mobile** is experimental; the parent UI on phones may use the native
  shell until it stabilises. Desktop (Win/Mac) is solid today.

## Explicitly OUT of scope (policy line)
Covert device takeover — **anti-uninstall lockdown, screen-mirror-anytime, reading
all messages, remote control/wipe, hidden location** — is **not** built. That
combination is the stalkerware profile and is restricted regardless of intent
(an implementation agent was blocked by Anthropic's usage policy). For
tamper-resistance / app-blocking / location done the sanctioned way, use the
platforms' own family tooling (**Android Family Link / Android Enterprise**,
**Apple Screen Time**) — official, consented, auditable — alongside Bulwark's
content filtering. Bulwark stays transparent: the child can see it's running.

## Build
- Parent: `cd apps/parent && cargo run` (detached from the core workspace so it
  doesn't pull the Dioxus tree into the engine's `cargo build --workspace`).
- Child (Windows): the `bulwark-client` + `bulwark-net` path. Android: `platform/android`
  + `cargo-ndk`. Apple: Network Extension shell + the core as a static lib (to build).
