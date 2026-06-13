# PH Bulwark is 100% free/open-source

Every shipped component is FOSS, and the apps are distributed through FOSS
channels only — **no Google Play, no proprietary SDKs, no proprietary
third-party cloud** (no Firebase/FCM, no Google APIs). This is a hard policy,
enforced in CI (`foss-guard` → `scripts/check-foss-android.sh`) for the Android
side and `cargo-deny` (licenses + bans) for the Rust workspace.

**Cloud is fine — lock-in is not.** PH Bulwark *does* offer a hosted **PH Bulwark
Cloud** (the filter regions + the gRPC server + optional server-side WireGuard
VPN). But the entire server is FOSS (`bulwark-server` and friends): a family can
run it themselves. The hosted regions are a *convenience instance of the same
open-source software*, never a closed dependency — and the default stays
on-device. "Self-hosted-first, hosted-optional" applies to the server, the VPN
exit, and push (self-host ntfy or use ours).

**Replace, never lose.** Removing a non-free component never drops a capability —
it is REPLACED with a FOSS equivalent of equal function:

| Removed (non-free / GPL) | FOSS replacement | Status |
|---|---|---|
| `tun2proxy` (GPL) | **smoltcp** capture + **boringtun** WireGuard transport | shipped (the live VPN data path) |
| Firebase **FCM** push | **UnifiedPush** (self-hosted ntfy), endpoint-based | in progress |
| **ML Kit** OCR | **Tesseract** (`tesseract4android`, Apache-2.0) | OCR engine wired; on-screen text already comes from the a11y tree |

## The rule

- **Licensing:** MIT / Apache-2.0 / BSD / permissive only — **no GPL** anywhere
  (the reason tun2proxy was removed). The one sanctioned exception is GPL OS
  *tooling* run as a separate process on our own infra (e.g. `wireguard-tools`
  on the region box) — never linked or redistributed in an app.
- **No proprietary Android dependencies** — banned: ML Kit, Firebase/FCM,
  Google Play Services / `play-services-*`, Play Core, AR Core, any closed
  Google SDK. Allowed Google coordinates are the FOSS ones only: `androidx.*`
  and `com.google.android.material` (Material Components, Apache-2.0).
- **No proprietary push.** Notifications use **UnifiedPush** (self-hosted, e.g.
  ntfy) — never FCM, never APNs. The server delivers to a per-device endpoint
  URL; the same endpoint-based path serves the child app, the Camera app, and
  the Manager identically.

## What each capability uses (the FOSS stack)

The **AccessibilityService is the unified on-device agent** — it does it all,
**no VPN required** (see [on-device-agent.md](design/on-device-agent.md)): it
reads the view-tree text, and on API 30+ uses `takeScreenshot()` for image
frames + `TYPE_ACCESSIBILITY_OVERLAY` windows for **localized** cover-ups.

| Capability | FOSS implementation |
|---|---|
| On-screen TEXT (E2E/pinned apps) | Android **accessibility tree** → **`bulwark-text` grooming detector** (the wired path, content-free) |
| TEXT in bitmaps (a11y tree can't expose) | **Tesseract** OCR (`tesseract4android`, Apache-2.0) on a `takeScreenshot()` frame → the **SAME `bulwark-text` grooming detector**. Conventional OCR only — never a vision-LLM, never ML Kit |
| NSFW imagery — **on-device, NO VPN** | **ONNX Runtime** (MIT) + bundled ViT classifier (Apache-2.0) on a `takeScreenshot()` frame. A vision **classifier**, not an LLM. Localized: **tile the frame, score each tile, blur only the high-scoring tiles + a margin** (an accessibility overlay) so the rest of the screen stays visible — never a full-screen block. The Camera app runs the same classifier on captures. |
| NSFW imagery — network path | the same ONNX classifier in the VPN TLS-inspecting proxy (when the VPN is on) |
| Audio transcription | **whisper** (open weights, on-device/CPU) → `bulwark-text` |
| QR pairing scan | **ZXing** (`zxing-android-embedded`, Apache-2.0) |
| Push notifications | **UnifiedPush** (ntfy, self-hosted) — child, Camera, AND Manager |
| WireGuard transport | **boringtun** (BSD-3) |

## Distribution (FOSS, self-hosted-first)

All apps ship the **same way** — see [distribution.md](distribution.md):

1. **Self-hosted F-Droid repo** (`fdroid/`, served at
   `dist.predatorhunters.co.uk/fdroid`) — primary channel, no third-party review.
2. **Obtainium** pointed at the GitHub Releases (signed APKs from
   `android-release.yml`).
3. **Accrescent** (curated, FOSS-only, its own signing flow).

This covers the child app (`co.predatorhunters.bulwark`), the Camera app
(`co.predatorhunters.bulwark.camera`), and the **Manager** — the Manager is a
Dioxus app built with `dx build --platform android`, so its signed APK joins
the same three channels (it has no proprietary dependencies; verified).

Official **F-Droid.org** is deliberately **not** pursued: the parental-protection
category sits in F-Droid's "possible stalkerware" review bucket, and we
self-host anyway, so we keep the FOSS guarantees without their gatekeeping.
