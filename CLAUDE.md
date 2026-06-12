# PH Bulwark — project instructions (read by every session and every subagent)

Consensual, guardian-installed **child-safety content-filtering VPN** for a child's
own device. Child app = **PH Bulwark**; guardian console = **PH Bulwark Manager**;
`bulwark`/`bulwark-*` is the internal codename (never rename crates/env/package/paths).

## Framing (mandatory)

This is a **child-protection / parental-control product** — never describe it in
offensive-security or biology terms. Use the glossary in [docs/FRAMING.md](docs/FRAMING.md):
"TLS inspection" not MITM, "protection-status alert" not tamper, CSAM is
**detect/block/report — never store**. The `MitmProxy` type name is grandfathered;
prose/comments use the protective terms.

## Hard constraints (non-negotiable)

- **Licensing:** MIT/Apache/permissive only — **no GPL** anywhere (tun2proxy was removed for this).
- **CSAM:** never stored, never remediated/served — always blocked + reported (NCMEC path).
- **No raw grooming dataset or live model weights in public releases.**
- **No crowd-sourced public accusations** — private per-child block + law-enforcement escalation only.
- **Never paste secrets/credentials into chat**; never use root AWS keys.
- Engine invariants: `#![forbid(unsafe_code)]` except audited FFI, mTLS between nodes,
  no explicit-media persistence (hashes/redacted snippets only), rules-first minimal AI
  (no LLM in any hot path), conventional OCR only.

## Layout

- `crates/bulwark-*` — 18-crate Cargo workspace (engine). `bulwark-net` is security-critical.
- `apps/parent` — Dioxus 0.8.0-alpha.0 (detached workspace) — **the SHIPPED guardian console**
  (PH Bulwark Manager): desktop (Win/macOS/Linux) + Android (experimental via `dx`).
- **`apps/child` is a Dioxus DESIGN PREVIEW only** (desktop/web — design iteration + the
  `tools/ui-tests` web journey). It is **NOT the shipped child app**. The child app SHIPS
  **native** as `platform/android` — VpnService / AccessibilityService / DeviceAdminReceiver
  cannot be a webview, so the child must be native + the Rust core over JNI.
- `platform/android` — **the SHIPPED child app**: native Android shell (Kotlin/Compose UI) +
  `rust/bulwark-android` JNI cdylib (detached workspace). `platform/apple` = Rust-FFI + Swift
  scaffold for a future iOS Network Extension (no installable app yet).
- `tools/ui-tests` — Midscene UI-test harness (web + android).
- `PLAN.md` §6 = product workflows A–D; `docs/finish-plan.md` = per-step tasks;
  `docs/agent-workflow.md` = orchestration + persistent agent roster.

## Build / verify commands (Windows host)

| What | Command |
|---|---|
| Engine check | `cargo check -p <crate>` / `cargo test -p <crate>` from repo root |
| SAC 4551 workaround | `touch crates/bulwark-proto/build.rs` to force a fresh build-script binary |
| Android .so | from `platform/android/rust/bulwark-android`: `cargo ndk -t arm64-v8a -t armeabi-v7a -o ../../app/src/main/jniLibs build --release` |
| APK | from `platform/android`: `./gradlew assembleDebug` with `JAVA_HOME=C:/Users/Jordan/AppData/Local/Programs/Microsoft/jdk-17.0.10.7-hotspot` |
| NDK | `C:/Android/sdk/ndk/26.3.11579264` (`ANDROID_NDK_HOME`) |
| adb | `C:/Android/sdk/platform-tools/adb.exe` — Pixel serial `32161FDH20039M` |
| Dioxus | `dx build --platform web` (wasm) / `dx build --platform android --device <id>` |
| Manager desktop | from `apps/parent`: `cargo build --release` (Win/macOS/Linux console exe) |
| Manager on Android | from `apps/parent`: `dx build --platform android --device 32161FDH20039M` — **MUST pass `--device`** or dx builds x86_64-only (→ `INSTALL_FAILED_NO_MATCHING_ABIS` on the arm64 Pixel). Export the NDK `CC_/AR_/CARGO_TARGET_*_LINKER` vars first (ring needs `cc`). App id `co.predatorhunters.bulwark.manager` coexists with the child. |
| gh CLI | `C:\tools\gh\bin\gh.exe` |

**Pitfalls:** piping (`cmd | tail`) masks exit codes — capture `$LASTEXITCODE` and grep
the log file instead. rusqlite/`bulwark-store` does not build on this host (SAC, os
error 4551) — it builds on CI/Linux; keep it out of android/local-only dep trees.
- **Stale build artifacts:** cargo hardlinks outputs, so an artifact's mtime can read
  *older* than the source change that should have rebuilt it (a Jun-11 `.so`/`.exe`
  after a Jun-12 edit). When the VPN data path matters, rebuild the `.so` FIRST
  (`touch crates/bulwark-net/src/vpn/netstack.rs` then `cargo ndk … build --release`),
  confirm the jniLibs `.so` date updated, THEN `gradlew assembleDebug`. Verify on-device
  with a fresh install — don't trust a "BUILD SUCCESSFUL" that may have packaged an old `.so`.
- **SMTP ↔ alert coupling (prod-crash class):** `BULWARK_SMTP_HOST` is shared by the
  password-reset mailer AND the guardian-alert mailer. The alert mailer turns on with
  `BULWARK_ALERT_FROM`+`BULWARK_ALERT_RECIPIENTS` and errors at boot if only one is set —
  set BOTH or NEITHER. Reset email needs only `BULWARK_SMTP_HOST`+`BULWARK_RESET_FROM`
  (+`_USERNAME`/`_PASSWORD`); do NOT set `BULWARK_ALERT_FROM` alone.

## Deployment & infra (live, 2026-06)

- **Server:** single EC2 `i-0a3aa9dc27f8e1c91` (eu-west-2, IP `35.179.110.106`), gRPC+TLS
  on `:8443`, `--features onnx,whisper,ffmpeg`, fail-CLOSED. CI builds the image → SSM
  `docker pull` redeploy (`deploy.yml`, no SSH). The `default` AWS profile is the scoped
  `ph-bulwark-deployer` (ssm:SendCommand ONLY) — it CAN recover a downed box directly via
  `aws ssm send-command` (image must be on the box or re-pulled with a GHCR login).
- **Domain/CA:** moving clients off the raw EC2 hostname to `api.`/`vpn.predatorhunters.co.uk`
  (DNS-only A records on Cloudflare → the box) + a real Let's Encrypt cert, which REMOVES
  the self-signed cluster-CA pinning (no `cluster_ca` in the pairing payload). In progress.
- **Email:** `predatorhunters.co.uk` — SES (eu-west-2, domain DKIM-verified, transactional
  reset codes; prod-access pending) + Tuta (human mailboxes). DNS on Cloudflare (token in
  `~/.cf-token.txt`, rotate when idle). SES SMTP user = `ph-bulwark-smtp`.
- Per-PR **user authorization is required to merge** (master push auto-deploys to prod).

## Workflow rules

- **Subagents cannot write files here** — use them read-only; they return exact
  edits (path + old→new) and the main session applies them. Un-HTML-escape any
  `&amp;`/`&lt;`/`&gt;` in agent-returned code before applying.
- Review gate: run the `code-review` agent on the diff BEFORE committing and
  again on the branch-vs-master diff before merging; fix until it returns
  APPROVE. PR loop: comment what changed on every push, then `@codex review`
  (when account credits allow), iterate until clean.
- Commits end with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Keep PLAN.md §6 + the matching `docs/design/*.md` updated when a step ships (mark DONE with date).
- Chat style: terse — edit/create files rather than narrating.
