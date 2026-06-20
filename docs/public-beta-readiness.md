# PH Bulwark — public-beta readiness (GO / NO-GO gate)

The **live gate** for opening public (stranger) beta testing over the FOSS channels.
Pairs with [`production-readiness.md`](production-readiness.md) (engine/feature gap
map) and [`TESTING.md`](TESTING.md) (the tester-facing guide). This file gates **real
families testing a child-safety product** — over-claiming readiness is a safety risk,
so status is deliberately conservative: **absence of device-test evidence is 🧪, not
✅.**

Legend: ✅ ready now (CI/test evidence) · 🧪 implemented but needs real-device /
credential / model validation · ❌ not functional / not built · ⛔ won't-do for FOSS.

---

## Verdict (2026-06-14): **NO-GO for stranger beta.**

PH Bulwark is **ready for an internal / trusted-tester cohort that can build from
source and accept unsigned APKs**, but **NOT** for inviting the general public.

The two hard blockers, both **owner-supplied**, are:

1. **No signed release channel.** The child APK on GitHub Releases is
   **debug/unsigned**; release signing is gated on owner secrets
   (`ANDROID_KEYSTORE_*`) that are not set, and the **Camera app + Android Manager
   are not attached to Releases at all**. No F-Droid repo / Accrescent listing
   exists (both require a signing key). → *minimum bar item #1 is unmet.*
2. **The core protective loop is not validated on a real device end-to-end.**
   Pairing, transparent HTTPS filtering, protection-status alerts, and SOS-reaches-
   guardian are implemented and CI/host-tested but carry **no device sign-off**
   (`production-readiness.md` marks the VPN pump and on-device agent 🧪). The apps
   *launch* on a Pixel 7; that is not the same as the flows *working* on a device.

When both are cleared, re-evaluate against the **minimum bar** at the bottom.

---

## Shippable surfaces

### A. Child app — `co.predatorhunters.bulwark`

| Capability | Status | Evidence |
|---|---|---|
| App builds + launches on a real Pixel 7 (arm64) | ✅ | `docs/finish-plan.md` snapshot ("child + manager built for arm64, installed and running on a real Pixel 7"). |
| Android baseline Android 8+ (API 26) | ✅ | `platform/android/app/build.gradle.kts` `minSdk = 26`. |
| CI builds the child APK (Linux runner, JNI core + `assembleDebug`) | ✅ | `.github/workflows/android.yml` (uploads `bulwark-child-debug-apk`). |
| **Signed release APK** | ❌ owner-blocked | `app/build.gradle.kts` release signing is conditional on `ANDROID_KEYSTORE_BASE64` (+3 siblings); unset → release stays unsigned. `release.md` §3. |
| Pairing (mint code/QR → child redeem) | 🧪 | Server primitives + payload v2 shipped (PR #104; seeded config PR #125); gRPC e2e in `crates/bulwark-server/tests/e2e_accounts_pairing.rs` + `e2e_app_workflow_harness.rs`. **Not device-signed-off end-to-end.** |
| Transparent VPN per-flow filtering (intercept→classify→verdict→block/blur/mute) | 🧪 Device-Owner-gated | `run_netstack` / `run_android_data_path` implemented + host-tested 2026-06-10. As of #182 the VPN is **fail-CLOSED on the inspection CA**: the tunnel comes up only on a confirmed system-store CA install (Device Owner) — on a non-managed device it stays **off by design** (won't brick HTTPS), and the accessibility+OCR path is the active content filter instead. Needs a **managed / Device-Owner device** to validate end-to-end (`production-readiness.md` P0 + the CA-install row). |
| Protection-status / anti-removal alert | 🧪 | Tamper heartbeat → `PROTECTION_DISABLED` alert wired (`bulwark-server::tamper`, `RustBridge.reportTamper`; `docs/design/tamper-protection.md`); device round-trip unverified. |
| Child SOS → guardian | 🧪 | `FamilySafety.RaiseSos` / `CHILD_SOS` server-side + `e2e_family_safety.rs`; child UI `platform/android/app/.../Sos.kt` (two-tap, content-free, honest "no guardian took it" path). Device delivery unverified. |
| On-device accessibility + OCR content filter (E2E / pinned apps, no Device Owner) | 🧪 | The native Android accessibility path now reads the screen device-wide — surface-bound NSFW cover (#174) + reliable photo-path OCR (#187), fixes from on-device validation — feeding the grooming/NSFW pipeline. This is the **content filter that needs no Device Owner** and the only path that can read cert-pinned / E2E apps. Cross-platform `bulwark-agent` capture/overlay (Win/macOS/Linux) still in progress (`docs/design/on-device-scanning.md`). |
| HTTPS CA trust on a normal (un-managed) device | ❌ (by OS) | Android 7+ forbids a user CA being trusted by other apps; the per-flow VPN filter (TLS inspection) needs Device-Owner (`installCaCert`, shipped 2026-06-12). As of #182 the VPN is **fail-CLOSED on this**: without a trusted system-store CA the tunnel does not come up, so an un-managed device runs the **accessibility+OCR filter** rather than a partially-broken VPN. `production-readiness.md` P1 CA-install row. |

### B. Camera app — `co.predatorhunters.bulwark.camera`

| Capability | Status | Evidence |
|---|---|---|
| On-device NSFW capture gate (block + drop, no store/hash/send) | 🧪 | `platform/android/camera/.../NsfwGate.kt` runs the engine's bundled ViT (Apache-2.0) via ONNX Runtime, parity with `bulwark-vision` pre/post-process, fail-closed; threshold 0.7. **On-device accuracy/accelerator path not device-validated.** |
| No-network guarantee (OS-enforced) | ✅ | `platform/android/camera/AndroidManifest.xml` declares **zero** network permissions; comment + manifest enforce it. |
| Module builds in CI | ✅ (compiled) | `settings.gradle.kts` includes `:camera`; `android.yml`'s `assembleDebug` compiles it. |
| **Camera APK shipped on any channel** | ✅ | **Signed:** `android-release.yml` already builds + attaches `camera-release.apk` (`:camera:assembleRelease`, self-gated signingConfig) to the GitHub Release + the FOSS channels (F-Droid mirror / Accrescent / Obtainium) on `v*` tags. **Debug (quick sideload):** this PR adds `android.yml`'s per-run `bulwark-camera-debug-apk` artifact + `release.yml`'s `camera-android-attach` (`ph-bulwark-camera-android.apk` + SHA256), mirroring the child APK's debug+signed double — so testers can grab a build off any CI run, not just a tag. |

### C. Manager (guardian console) — `co.predatorhunters.bulwark.manager`

| Capability | Status | Evidence |
|---|---|---|
| Desktop console (Win/macOS/Linux) builds + runs | ✅ | `apps/parent` `cargo build --release`; modular split + router shipped (`finish-plan.md` Workflow A, 2026-06-10; 12/12 tests). |
| Account / server-choice / add-child / mint pair code UI | ✅ | `docs/design/app-pairing-and-regions.md` "Current Status"; setup dashboard + create-pair-code flow. |
| Setup-code panel (code + QR + copy payload v2) | ✅ | PR #104 (`finish-plan.md` Workflow C). |
| Echo desired config + seed console drafts | ✅ | PR #125 (`GetChildStatus`). |
| Review stream (guardian-scoped alerts, approve/deny) | ✅ | Accounts/Review services + guardian scoping; `e2e_accounts_pairing.rs` decision-auth coverage. |
| Built on Android | 🧪 | `dx build --platform android --device <id>` runs on Pixel 7 (`finish-plan.md`); **not** attached to Releases; experimental renderer. |
| **Push delivery of alerts to a guardian device (UnifiedPush)** | ❌ in-progress | No FOSS push connector wired; UnifiedPush connector is a planned increment. Alerts reach the Manager via the Review stream while the console is open; background push is not yet a FOSS path. |
| Desktop signing (Win code-sign / macOS notarize) | ❌ owner-blocked | `release.md` §3 — needs EV cert / Apple Developer ID. |

### D. Server / regions

| Capability | Status | Evidence |
|---|---|---|
| Cluster live (London EC2, fail-CLOSED, `onnx,whisper,ffmpeg`) | ✅ | `production-readiness.md` TL;DR; `CLAUDE.md` deployment section. |
| Image / audio / video detect + video remediation | ✅ live | `production-readiness.md` P0 table. |
| Public TLS on `api.`/`vpn.predatorhunters.co.uk` (Let's Encrypt) | ✅ live (2026-06-12) | `production-readiness.md` P1 "Cluster TLS"; public-trust-by-default, pin-optional. |
| Fail-closed on uncovered media | ✅ | `production-readiness.md` ("fail_closed_uncovered → Block+alert"). |
| Guardian-scoped alert relay + SOS broadcast | ✅ | `crates/bulwark-server` AlertRelay / FamilySafety + e2e tests. |
| Email (SES transactional) | 🧪 | DKIM-verified; **SES prod-access pending** (`CLAUDE.md` infra) — reset/alert mail capped until granted. |
| US region | ❌ not deployed | Single London box today (`CLAUDE.md`). |
| CD pipeline (CI image → SSM redeploy, no SSH) | ✅ | `release.md` §5; `deploy.yml`. |

---

## Buckets

### Ready now (✅ — safe for build-from-source / trusted testers)
- Server cluster: live, fail-closed, public TLS, image/audio/video detect+remediate.
- Manager desktop: account, server choice, add child, mint pair code/QR, scoped
  review stream.
- Child app + Camera app: build and launch on a real Pixel 7; CI builds the child
  APK; Camera no-network guarantee is OS-enforced.
- Pairing server primitives + payload v2 (gRPC e2e green).

### Needs the owner (🧪 / ❌ — cannot be cleared from this repo session)
- **Release-signing keystore** → set `ANDROID_KEYSTORE_BASE64` / `_PASSWORD` /
  `ANDROID_KEY_ALIAS` / `ANDROID_KEY_PASSWORD` so CI ships **signed** APKs
  (`release.md` §3, `app/build.gradle.kts`). **Blocker #1.**
- **A signed FOSS channel** — stand up the self-hosted F-Droid repo (with
  fingerprint) and/or an Accrescent listing once signing exists.
- **On-device validation on a real Pixel 7** of: pairing end-to-end, transparent
  HTTPS filtering (VPN pump), protection-status alert round-trip, SOS reaching a
  guardian. **Blocker #2.**
- **A managed / Device-Owner test device** to validate full HTTPS CA trust
  (`installCaCert`) vs the honest partial coverage on a normal device.
- **Desktop code-signing** (Windows EV cert, Apple Developer ID) for the Manager.
- **SES production access** for unthrottled reset/alert email.
- ⛔ **Supervision-connector OAuth credentials** — **WON'T-DO for the FOSS beta**;
  the on-device agent subsumes it and the connectors are no-op stubs
  (`production-readiness.md` P0).

### In-progress increments (track, not blockers for a *trusted* cohort)
- **On-device accessibility/screenshot agent** — ✅ the native Android capture + OCR
  + localized NSFW overlay shipped (`ocr/Ocr.kt`, `nsfw/Nsfw.kt::localize`,
  `BulwarkAccessibilityService.kt::showLocalizedOverlay`). The cross-platform
  `bulwark-agent` (Win/macOS/Linux) capture/overlay is still in progress
  (`docs/design/on-device-scanning.md`).
- **Manager UnifiedPush connector** — ✅ shipped (native connector + receive-side
  `PushService`); background receive still wants an on-device distributor to validate.
- Android **Manager** APK in `release.yml` — ✅ shipped: the `manager-apk` job (dx)
  builds + signs + attaches `manager-release.apk` to the Release (now on all 3 FOSS
  channels alongside `app`/`camera`).
- Windows/Linux/macOS desktop transparent VPN path + truststore install (Bucket C).

---

## Minimum bar before inviting strangers

All six must be **true and demonstrated** (not just implemented) before the beta is
opened beyond build-from-source trusted testers:

1. **Signed APKs on a real channel** — child **and** Camera APKs, signed with the
   release keystore, installable from a self-hosted F-Droid repo / Accrescent /
   Obtainium without a debug-build warning. *(unmet — Blocker #1)*
2. **Pairing works on a real device** — mint a code/QR on the Manager, redeem on a
   second physical phone, child comes up protected. *(unmet — 🧪)*
3. **Filtering verifiably blocks** — a known-unsafe fetch is demonstrably
   blocked/blurred on-device, and the Camera app blocks an explicit capture on a
   real camera. *(unmet — 🧪)*
4. **SOS reaches a guardian** — child SOS on a real device produces the URGENT alert
   on the guardian's Manager (and the honest "no guardian took it" path fires when
   none is reachable). *(unmet — 🧪)*
5. **No crash on launch** — both apps cold-start clean on a real device across at
   least two Android versions (the CI emulator boot check is flaky; the real Pixel
   launch must be the evidence — `finish-plan.md` Workflow G). *(child app launches
   on the Pixel; needs a repeatable cross-version pass)*
6. **Clear consent + uninstall path** — first-run discloses what PH Bulwark does and
   that it can be turned off; uninstall/disable works and (on a normal device) fires
   a protection-status alert rather than silently hiding. *(consent copy + tamper
   alert exist; verify the end-to-end uninstall path on a device)*

Until 1–4 are demonstrated on hardware, the answer to "can strangers test this?" is
**no** — ship to trusted, build-capable testers only and gather feedback.
