# Child Safety ROM — design

**Status: DECIDED (owner rulings 2026-06-16) — build all three rungs A+B+C.** Increment 1
(Device-Owner on stock) is **code-complete**: PR #217 (DO auto-enable of detection + perms)
+ PR #218 (Manager provisioning-QR builder), both held for on-device validation once the
dedicated 7a is flashed. **Increment 2/3 (B/C):** all 8 open build decisions are RESOLVED
(2026-06-20; PR #219 runbook + PR #221 + the system-wide camera gate §7) and the
`platform/rom/` scaffold has landed (PR #222: `bulwarkd` + `libbulwark_safety` + the
camera-gate patch). **Architecture pivot — Rust core via FFI (PR #223, IN PROGRESS, not
merged):** ROM detection reuses `crates/bulwark-vision` + `crates/bulwark-text` through a
C ABI (`bw_init_once`/`bw_score_nsfw`/`bw_score_text`) instead of a C++ re-implementation,
so detection never drifts from the shipping engine. The remaining blocker for B/C is an
AOSP/Cuttlefish **Linux build host** — the image build cannot run on the Windows dev host.
B/C still need that host + the device.
Date: 2026-06-16 (decided); updated 2026-06-20. Target device: Pixel 7a (codename `lynx`).
Framing: a child-protection build ("Child Safety ROM") — never offensive-security.

## Goal

A **guardian-provisioned** Android build for a **dedicated child device** that runs the
PH Bulwark detection stack — NSFW image classifier, OCR→grooming text, (later) audio —
at the **system layer**: always-on, no AccessibilityService fragility, no per-use prompt,
no Device-Owner prompt, and the child cannot disable or remove it.

Why: today the cross-app filter rides an AccessibilityService (event-driven, per-element,
defeat-able by turning a11y off) plus an optional Device-Owner VPN. Pushing detection into
the OS removes that fragility, gives system-level capture (faster, every surface), and makes
the protection part of the device rather than an app a child can fight.

## Owner decisions (RULED 2026-06-16)

1. **Dedicated device, fresh wipe — CONFIRMED.** A NEW/dedicated Pixel 7a will be wiped/flashed
   once the owner sorts backups — **never** the Pixel 7 with the irreplaceable family voice-notes
   ([[no-factory-reset-constraint]]).
2. **GPL-2 kernel — ACCEPTED (kernel-as-platform).** The ROM ships the Linux kernel (GPL-2) as the
   platform; **our detection code + deps stay MIT/Apache permissive on top** (standard Android
   licensing). This owner ruling relaxes "no-GPL-shipped" **for the kernel only** — nothing of ours
   links GPL. So the ROM path (B/C) is GO.
3. **Grooming weights — guardian-provisioned ONLY.** The image/OTA carrying `grooming_detector.onnx`
   (and the NSFW model) is **signed + enrolled-device-only, never a public download** (or fetched at
   provisioning over mTLS). The **NSFW model + the child shield app are baked into the ROM** (C).
4. **Approach — build ALL THREE (A + B + C), staged.** Ship A (stock Device-Owner) now, then B
   (privileged system app), then C (framework-baked ROM = the end state).

## Approaches

### A — Device-Owner provisioning on STOCK firmware (no ROM) — *executable now; recommended first rung*
Provision the existing child app as **Device Owner** during a fresh-device QR/NFC setup on a
**stock** Pixel 7a. Already ~built: `admin/BulwarkDeviceAdminReceiver` (provisioning callbacks
+ `ACTION_DEVICE_OWNER_CHANGED`), `Lockdown` (`isDeviceOwner`, `enforce()`: lock-task / always-
on VPN), `CaTrust` (silent system-store CA install via `DevicePolicyManager` when Device Owner).
- **Delivers:** silent/undefeatable *provisioning* — child can't remove the app, always-on VPN,
  CA baked, lock-task, no per-use prompt, auto-pairing via the QR extras. Built as #217 + #218.
- **Effort:** weeks (polish provisioning + a clean fresh-device flow). **Needs none of the
  three blocking rulings, no AOSP host.**
- **Limit — one manual step remains on stock:** the detection **AccessibilityService still needs a
  one-time MANUAL enable**. A Device Owner CANNOT silently enable an a11y service on stock firmware
  (`setSecureSetting`'s DO allowlist excludes `ENABLED_ACCESSIBILITY_SERVICES`), so #217 attempts it
  fail-safe but falls back to the existing guided manual toggle. The genuinely-silent, zero-prompt
  enable is what the privileged/system-app rungs (**B/C**) add (platform-signed → writes
  `Settings.Secure` directly). Capture is also still app-level (a11y / MediaProjection), not
  framework-deep, until B/C.

### B — Privileged system app on a custom build
A minimal custom image (AOSP **or** GrapheneOS base for `lynx`) embedding the child app as a
signed `priv-app` with privileged perms (system screenshot, foreground-service exemptions,
non-removable). Detection runs as a privileged background service: periodic system screenshot →
NSFW + OCR→grooming, always-on, no AccessibilityService, faster.
- **Effort:** moderate–high (custom image + signing + OTA basics). **Needs the GPL ruling + an
  AOSP/Graphene build host.**

### C — Framework-baked detection service (the full "Child Safety ROM")
Promote the scanner to a **system service** in the framework (a `system_server` companion or a
dedicated native service): hook the screenshot/compositor pipeline at the OS layer, run NSFW /
OCR / grooming continuously at system priority, enforce block overlays at the WindowManager
layer, add system-level **audio capture** for grooming-over-voice. OTA update channel.
- **Text path:** read **native text directly** at the framework layer (TextView/EditText strings,
  web DOM, IME, the system a11y node tree) — **no OCR for selectable text**; OCR (+ the NSFW vision
  model) stays only for **pixel text** (images/memes/screenshots/Canvas/GPU/game surfaces). The
  **child shield app + all detection are baked into the ROM** as a system service — no separate
  installable app, no AccessibilityService fragility.
- **Effort:** months; deep platform work + sustained AOSP expertise. Build/sign/OTA infra + the
  device required. This is the stated end-state.

## Recommendation

**Stage it, and greenlight Increment 1 now.** A → B → C as increments:
- **Increment 1 (A)** delivers most of the ask (undefeatable, no prompts, always-on, no a11y
  fragility) on stock firmware in **weeks**, is **largely already built**, and needs **none** of
  the blocking rulings — the safe place to start while the ROM questions are decided.
- **Increment 2 (B)** is the first true "baked-in" rung.
- **Increment 3 (C)** is the full vision.

Going straight to C risks months before anything protects the device. Pure-C is viable if the
timeline + rulings are accepted; we can compress, but staging gets protection on the 7a far sooner.

## Detection reuse (not new work)

The models + pipeline already exist and are unchanged by this project: `crates/bulwark-vision`
(NSFW ViT ONNX, NNAPI), `crates/bulwark-text` (grooming ONNX), Tesseract OCR (`tesseract4android`).
The ROM work is about **where** detection runs (app → privileged service → framework service) and
capture/placement — **not new detectors**. Data path unchanged: capture → classify (on-device) →
verdict → action (block overlay + guardian alert via the cluster, **fail-CLOSED**); **no explicit-
media persistence** (hashes/redacted only); CSAM → block + NCMEC report, **never stored**. mTLS to
the cluster; engine invariants (`#![forbid(unsafe_code)]` except audited FFI) hold.

## Buildable now vs needs infra / device / rulings

- **Now (this Windows dev env, existing Gradle):** this design; Increment-1 Device-Owner
  provisioning polish; the detectors are done.
- **Needs a Linux AOSP/Graphene build host + the physical 7a + signing keys:** B and C image
  builds, flashing, OTA, on-device validation. **Not possible in this dev env or by the agent
  autonomously** — needs infra + the device.
- **Needs an owner ruling:** GPL kernel; grooming-weights distribution; dedicated-device confirm;
  approach depth.

## Status / next steps

- **Increment 1 (A) — code-complete:** PR #217 (DO auto-enable of detection + perms) + PR #218
  (Manager provisioning-QR builder + guardian screen). Both **held for on-device validation** on the
  flashed 7a + the owner's merge (master = prod deploy). Remaining A polish: fresh-device onboarding
  UX; device-token-via-extras (needs a small child-app change so the QR can carry the device token).
- **Increment 2 (B) / 3 (C):** design + decisions are DONE — base choice (AOSP-vanilla
  `android-16.0.0_r3`), the system-service design (capture hook, framework text path,
  block-overlay at WindowManager), and all 8 open decisions are RESOLVED in
  [`docs/design/child-safety-rom-build.md`](child-safety-rom-build.md) (PR #219/#221,
  2026-06-20). The **`platform/rom/` scaffold has landed** (PR #222): `bulwarkd` daemon,
  the shared `libbulwark_safety` scoring library, and the `Camera3OutputStream` camera-gate
  patch (the system-wide camera NSFW gate, §7 of the build runbook — still DRAFT, pending
  owner/architect sign-off, unvalidated). **Rust core via FFI is IN PROGRESS** (PR #223,
  branch `feat/rom-rust-ffi`, not merged): `platform/rom/libbulwark_safety/rust/` reuses
  `crates/bulwark-vision` (`onnx`-gated NSFW) + `crates/bulwark-text` (rules-first text)
  behind the `bw_init_once`/`bw_score_nsfw`/`bw_score_text` C ABI, fail-CLOSED throughout —
  host-verified no-onnx (unit tests green), `ort`-on-Android cross-compile confirmed, C++/
  camera-gate wiring to the ABI still to do. The **image build + flashing + OTA + on-device
  validation remain PARKED** on an AOSP/Cuttlefish **Linux build host** (not possible in the
  Windows dev env) + the dedicated 7a.
