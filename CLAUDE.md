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
- `apps/child`, `apps/parent` — Dioxus 0.8.0-alpha.0 apps (detached workspaces). **The main UI.**
- `platform/android` — native Android shell + `rust/bulwark-android` JNI cdylib (detached workspace).
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
| gh CLI | `C:\tools\gh\bin\gh.exe` |

**Pitfalls:** piping (`cmd | tail`) masks exit codes — capture `$LASTEXITCODE` and grep
the log file instead. rusqlite/`bulwark-store` does not build on this host (SAC, os
error 4551) — it builds on CI/Linux; keep it out of android/local-only dep trees.

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
