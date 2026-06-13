# Completeness triage — stubs / WIP / "not yet" across the codebase

Status as of 2026-06-13. A repo-wide scan found **4 hard markers** (`todo!`/
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

---

## Bucket A — genuine incomplete functionality on a SHIPPED surface → finish

| Item | Where | Plan |
|---|---|---|
| On-device OCR → grooming | `platform/android` accessibility agent; [on-device-agent.md](design/on-device-agent.md) incr. 1 | Tesseract (`tesseract4android`) on a `takeScreenshot()` frame → existing `analyzeText` grooming. Replaces the removed ML Kit (which was never invoked). |
| On-device NSFW + localized tiled cover-up | same agent; incr. 2–3 | ONNX ViT classifier per-tile → `TYPE_ACCESSIBILITY_OVERLAY` over flagged tiles + margin. |
| Manager native push connector | `apps/parent` | Register a UnifiedPush endpoint + receive alerts in background (pairs with #136). Client side of the now-FOSS push path. |
| Manager signed APK on FOSS channels | `apps/parent` + release CI | `dx build --platform android` artifact joins the 3 channels (child + camera already wired in `android-release.yml`). |
| Child app QR pairing scan (native) | `platform/android` | ZXing dep present; wire the scan→setup-payload path (the Dioxus *preview* still says "scanning coming soon" — preview only, lower priority). |
| Staff account id for family-safety broadcast | `crates/bulwark-server/src/family_safety.rs` | Replace the `BULWARK_STAFF_BROADCAST_TOKEN` placeholder with a real staff account id now that StaffAdmin (#133) exists. |

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
  on-device agent still covers rendered content). Real filtering gap.
- **Transparent VPN mode** (`apps/parent` shows "use Proxy for now"): Phase 3
  `transparent.rs` landed (#128); full transparent capture is being rebuilt on
  the permissive netstack.
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
`camera-release.apk`; and (2) **on-device validation** of pairing / transparent
filtering / protection-status / SOS — **blocked on the owner** (a physical
managed/Device-Owner device run). No amount of green CI substitutes for (2).
