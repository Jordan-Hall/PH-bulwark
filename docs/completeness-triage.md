# Completeness triage — stubs / WIP / "not yet" across the codebase

Status as of 2026-06-14 (reconciled 2026-06-15: two bucket-A items already
shipped; **reconciled again 2026-06-20: ALL remaining bucket-A items were found
already shipped in `platform/android` + the release CI — Bucket A is now
CODE-COMPLETE.** On-device validation of the Android detection paths remains the
separate, owner-gated step — see the closing section. Every bucket-A row is now
marked **✅ DONE**). A repo-wide scan found **4 hard markers** (`todo!`/
`unimplemented!`/`FIXME`) and ~248 soft markers (`stub`, `for now`, `no-op`,
`not yet`, `placeholder`, `fail-open`, "honest"). The overwhelming majority of
the soft hits are **deliberate design** — fail-open/fail-CLOSED fallbacks,
`cfg`-gated platform paths, feature-gated optional capability, UI form
`placeholder:` attributes, and prose in doc-comments. This file sorts every real
item into four buckets so "is it done?" has an honest answer.

> **Definition of done** for this product = **all of bucket A finished**, bucket
> B left intentional (and documented), bucket C tracked as issues, bucket D
> consciously not-done. It is **not** a diff that touches all 248 marker sites —
> several of those would be regressions if "completed".
>
> **Status (2026-06-20): Bucket A is CODE-COMPLETE.** All five items are shipped
> in `platform/android` / `apps/parent` / the release CI. The remaining gate to
> "ready for strangers" is **on-device validation** of the Android detection +
> pairing paths — owner-gated (a physical managed/Device-Owner run), per the
> closing section. No code item in bucket A is outstanding.

---

## Bucket A — genuine incomplete functionality on a SHIPPED surface → finish

| Item | Where | Plan |
|---|---|---|
| On-device OCR → grooming **✅ DONE** | `platform/android` accessibility agent | Shipped: `ocr/Ocr.kt` runs Tesseract (`tesseract4android`, lazily-init, fail-open) on a `takeScreenshot()` frame; `accessibility/BulwarkAccessibilityService.kt` feeds the recognised text into the SAME `RustBridge.analyzeText` grooming pipeline as network/view-tree chat. In-memory only (no-media), content-free char-count logging. |
| On-device NSFW + localized tiled cover-up **✅ DONE** | same agent | Shipped: `nsfw/Nsfw.kt::localize()` scores an N×N tile grid and returns the flagged region (bounding box + one-tile margin); `BulwarkAccessibilityService.kt::showLocalizedOverlay()` draws a localized `TYPE_ACCESSIBILITY_OVERLAY` cover over just that region (re-scan suppressed while a cover is up). Fail-open (no model → no image scan); tile crops recycled (no-media). |
| Manager native push connector **✅ DONE** | `apps/parent` | Shipped: `api::register_push_target` → `Review.RegisterPushTarget`, endpoint persistence (`servers.rs`), the UnifiedPush settings screen (`screens.rs`), and the receive-side `PushService` (MainActivity.kt) + connector dep — with tests. (End-to-end background receive still wants an on-device distributor to validate.) |
| Manager signed APK on FOSS channels **✅ DONE** | `apps/parent` + release CI | Shipped: `android-release.yml`'s `manager-apk` job (dx build) signs + stages `manager-release.apk` and attaches it to the GitHub Release via `action-gh-release`, alongside `app-release.apk`/`camera-release.apk`. Also mirrored on F-Droid (`fdroid/metadata/co.predatorhunters.bulwark.manager.yml` + README) and offered as an Obtainium source (`docs/distribution.md`). All 3 FOSS channels now carry the Manager. |
| Child app QR pairing scan (native) **✅ DONE** | `platform/android` | Shipped: `Onboarding.kt` uses ZXing (`zxing-android-embedded`, `ScanContract` launcher) to scan the console's setup QR; `parsePairingResult()` decodes it into the enrollment payload → `onEnrollment`. (Only the Dioxus *design preview* still says "scanning coming soon" — preview-only, not shipped, lower priority.) |
| Staff account id for family-safety broadcast **✅ DONE** | `crates/bulwark-server/src/family_safety.rs` | Shipped: `with_staff_store` wired in `service.rs` (when `BULWARK_STAFF=1`); a `SAFETY_OFFICER`/`ADMIN` staff session authorizes `SendSafetyBroadcast` and stamps the real staff account id into `issued_by`; the shared `BULWARK_STAFF_BROADCAST_TOKEN` is the legacy fallback. Both paths unit-tested. |

## Bucket B — deliberate, CORRECT stubs/fallbacks → leave (do NOT "fix")

These are security-core invariants or intended platform behaviour. **Changing
their semantics autonomously is a safety regression risk** (filters-always-active
/ fail-CLOSED). Touch only with on-device validation + explicit sign-off.

- **NSFW `stub-noop` scorer** (`bulwark-vision`, `bulwark-client`): no model →
  emits `Unspecified` → **policy fail-CLOSES**; built without `onnx` → fails
  OPEN with a one-time WARN. This is the designed degradation, not a gap.
- **TUN `stub`** on non-Windows (`bulwark-net/src/tun/stub.rs`): desktop dev
  fallback; Android uses its own `VpnService`/netstack fd path.
- **`bulwark-agent` "stub (alert-only)"**, **`bulwark-audio` "stub-none"**:
  the alert-only / no-audio-model paths are intended defaults.
- UI `placeholder:` attributes in `apps/*/src/screens.rs`: HTML form hints.

## Bucket C — multi-week features → track as issues, do NOT half-build in a loop

- **HSM / StrongBox / Secure Enclave-backed CA keystore** (`bulwark-net/src/ca/`):
  today the CA key is file-based; hardware-backed is "not yet implemented".
- **Desktop OS trust-store install/uninstall** (`bulwark-net/src/truststore.rs`):
  marked "MUST exist before shipping" for desktop; Android trusts via Device
  Owner. Needed before a desktop child build ships.
- **QUIC / UDP-443 downgrade blocking** (`bulwark-net/src/quic.rs`): apps that
  speak QUIC can currently bypass TLS inspection on the network path (the
  on-device agent — and, for browsing, the in-app safe browser #194 — still cover
  rendered content). Real filtering gap. (The #198 host-filter pump also drops
  QUIC/443 on its path.)
- **Transparent VPN mode** (`apps/parent` shows "use Proxy for now"): Phase 3
  `transparent.rs` landed (#128); full transparent capture is being rebuilt on
  the permissive netstack. **Advanced 2026-06-14:** a fail-closed server-egress
  gate (`vpn/transport.rs::decide_egress`, #197 — advances #144, does NOT close
  it) + a no-Device-Owner DNS + TLS-SNI host filter (`vpn/sni_dns.rs`, #198 —
  opt-in, no decryption, fail-SAFE) both landed as code; netstack capture-loop
  wiring + on-device validation remain, so neither is wired as the Android default.
- **Video remediation** (`bulwark-video`): `ffmpeg` feature; default returns
  nothing. Staged per the video-remediation vision.
- **Desktop VpnService `todo!()` packet loops** (`bulwark-net/src/lib.rs`): need
  device testing.

## Bucket D — explicitly NOT doing (by decision)

- **Supervision connectors** (`bulwark-supervision`): poll is a no-op stub.
  Google/Apple supervision OAuth is **off the table** (full-FOSS, no proprietary
  cloud). Stays stubbed by design.
- **`llm-explain` client wiring** (`bulwark-ui`): optional explanation feature;
  no LLM in any hot path by invariant. Low priority, deliberately unwired.

---

## What "ready for general public testing" actually needs

Per [public-beta-readiness.md](public-beta-readiness.md): **GO for trusted /
build-from-source testers; NO-GO for strangers** until (1) signed APKs on a real
channel — **now unblocked**: release keystore + the four `ANDROID_*` Actions
secrets are set, next `v*` tag push ships signed `app-release.apk` /
`camera-release.apk` / `manager-release.apk` (all three FOSS channels); and (2)
**on-device validation** of pairing / transparent
filtering / protection-status / SOS — **blocked on the owner** (a physical
managed/Device-Owner device run). No amount of green CI substitutes for (2).
