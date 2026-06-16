# Child Safety ROM — design (DRAFT)

**Status: DRAFT — pending owner decisions (see "Blocking decisions"). Do NOT implement until resolved.**
Date: 2026-06-16. Target device: Pixel 7a (codename `lynx`). Framing: a child-protection
build ("Child Safety ROM") — never offensive-security.

## Goal

A **guardian-provisioned** Android build for a **dedicated child device** that runs the
PH Bulwark detection stack — NSFW image classifier, OCR→grooming text, (later) audio —
at the **system layer**: always-on, no AccessibilityService fragility, no per-use prompt,
no Device-Owner prompt, and the child cannot disable or remove it.

Why: today the cross-app filter rides an AccessibilityService (event-driven, per-element,
defeat-able by turning a11y off) plus an optional Device-Owner VPN. Pushing detection into
the OS removes that fragility, gives system-level capture (faster, every surface), and makes
the protection part of the device rather than an app a child can fight.

## Blocking decisions (these gate everything — owner's explicit call before any build)

1. **Dedicated device, fresh wipe.** Flashing wipes the phone, so this is a NEW/dedicated
   Pixel 7a — **never** the Pixel 7 holding the irreplaceable family voice-notes
   ([[no-factory-reset-constraint]]). *Confirm a dedicated 7a exists for this.*
2. **GPL-2 kernel vs the "no-GPL-shipped" hard constraint.** Every Android build ships the
   Linux kernel (GPL-2). `CLAUDE.md`'s non-negotiable is "no GPL in anything built, linked,
   or shipped." A ROM **cannot** avoid the GPL kernel. Reading it as *"the kernel is the
   platform; our detection code stays permissive on top"* (Apache userspace on a GPL kernel =
   standard Android) is plausible — but it **relaxes a stated non-negotiable**, so it needs an
   explicit ruling. **If we won't ship a GPL kernel, the ROM path (B/C) is off and we stop at
   Increment 1 (stock-firmware Device-Owner).**
3. **Grooming weights in a distributed image vs "no live model weights in public releases."**
   Baking `grooming_detector.onnx` into a ROM = shipping weights. Acceptable **only** if the
   image/OTA is guardian-provisioned and **never a public download** (signed, enrolled-device-
   only) — or the grooming model is **fetched at provisioning over mTLS**, not baked. *Confirm
   the distribution model.*

## Approaches

### A — Device-Owner provisioning on STOCK firmware (no ROM) — *executable now; recommended first rung*
Provision the existing child app as **Device Owner** during a fresh-device QR/NFC setup on a
**stock** Pixel 7a. Already ~built: `admin/BulwarkDeviceAdminReceiver` (provisioning callbacks
+ `ACTION_DEVICE_OWNER_CHANGED`), `Lockdown` (`isDeviceOwner`, `enforce()`: lock-task / always-
on VPN), `CaTrust` (silent system-store CA install via `DevicePolicyManager` when Device Owner).
- **Delivers:** no per-use prompt, child can't remove the app, always-on VPN, CA baked,
  lock-task — i.e. *undefeatable + silent + always-on* on stock firmware.
- **Effort:** weeks (polish provisioning + a clean fresh-device flow). **Needs none of the
  three blocking rulings, no AOSP host.**
- **Limit:** not "baked into the core" — capture (a11y / MediaProjection) is still app-level
  (Device Owner can auto-grant + suppress the prompt, so it's silent, but not framework-deep).

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
- **Effort:** months; deep platform work + sustained AOSP expertise. **Needs all three rulings
  + build/sign/OTA infra.** This is the stated end-state.

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

## Open items / next step

DRAFT pending: **(1)** confirm a dedicated Pixel 7a; **(2)** GPL-kernel ruling; **(3)** grooming-
weights distribution ruling; **(4)** approach pick — *A now* / *stage B→C (rec)* / *straight to C*.
On those answers, the next step is the `writing-plans` skill to produce the implementation plan for
the chosen rung (Increment 1 is the natural first plan regardless, since it's executable now and
unblocked).
