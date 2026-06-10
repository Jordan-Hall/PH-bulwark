# PH Bulwark — Finish Plan (product completion)

Plan-of-record for finishing the product surface (apps, native integration, features,
model release). The engineering core is built (see [PLAN.md](../PLAN.md) for the
architecture and [integration-todo.md](integration-todo.md) for the crate wiring,
both effectively done). This doc tracks what's left to *ship the experience*.

Branding: child app = **PH Bulwark Shield**, console = **PH Bulwark Manager**, internal
codename stays `bulwark`. Brand palette: navy `#0F3D5C`, green `#57A639`, orange `#EE7B22`,
on white; type = Plus Jakarta Sans; logo = `branding/logo.jpg` (BULWARK SHIELD mark).

Status legend: ✅ done · 🚧 doing · ⏭️ next · ⛔ blocked/needs-decision

---

## Snapshot (what's true today)
- **Detector:** rules-first grooming engine (incl. secrecy-isolation weighting fix) + sklearn TF-IDF (live, AUC 0.977) + **DistilBERT (AUC 0.9925) wired & parity-verified**. deberta-v3-small lost (fp16 fine-tune NaN; fp32 fix landed for a fair re-run). All merged.
- **Apps (Dioxus 0.8):** child + manager + labeling migrated; **child + manager built for arm64, installed and running on a real Pixel 7.**
- **Child app:** rebranded (navy/green/orange, real logo, no emoji, Plus Jakarta Sans), steps 2/3 layout fixed, verified on device.
- **Manager app:** full light brand theme + logo + mobile-responsive + demo data removed. (An earlier `style.rs`/`session.rs` extraction lives only on the unmerged `feat/parent-dioxus-08` branch; superseded 2026-06-10 by the full module split — see Workflow A.)
- **VPN:** flow-policy + QUIC/HTTP-3 block (closes the HTTP/3 filter-bypass) merged.
- **Safety lines held:** no AI decoy, no AI-CSAM, **no public release of the raw grooming dataset or live model weights** (re-victimization / predator-playbook / evasion risk).

---

## Workflow A — Manager get-started flow + modular split  🔴 the big one
Goal: replace the one-page dump with a guided journey, in clean modules.

- ✅ **Full module split shipped (2026-06-10):** main.rs (2974 lines) → `router`/`theme`/
  `state`/`servers`/`api`/`config`/`process`/`media`/`components`/`screens`/`tests`
  (behaviour-preserving; `cargo check` warning-neutral vs baseline; 12/12 tests green
  incl. the loopback FakeReview e2e). Dead `ServerSettings` wrapper dropped.
  (The earlier `style.rs`/`session.rs` cut on `feat/parent-dioxus-08` is superseded.)
- ✅ **`dioxus-router` adoption shipped (2026-06-10):** typed `Route` + `ConsoleLayout`
  + six routed screens + shared `Console` context (all 16 root signals — form state
  survives tab switches); `ActiveView`/`nav_class` deleted; check + 12/12 tests green.
- ⏭️ `ui/get_started.rs` — the journey: **Welcome → Choose server → Account (sign in/create) → Pair child → Done**, one job per screen
- ⏭️ `ui/dashboard.rs` — post-setup tabs (Alerts / Children / Protection)
- ⏭️ App gate: first-run/!logged-in → get-started; else → dashboard
- **Method:** module-by-module; `cargo check` + rebuild + **verify sign-in & pairing on the Pixel 7 after each step**; only swap the new flow in once it pairs. Keep current manager intact until then.
- **Accept:** fresh install → journey → dashboard; existing session → straight to dashboard; pairing still works.

## Workflow B — Native grants bridge (JNI)  ⏭️ functional foundation
The child app's Grant buttons currently flip local state only — they must open the real OS screens.
- ⏭️ `java_plugin!`/JNI: **Accessibility** (`ACTION_ACCESSIBILITY_SETTINGS`), **VPN consent** (`VpnService.prepare`), **Device Admin** (`DevicePolicyManager`)
- ⏭️ Reflect real granted-state back into the journey (don't advance until actually granted)
- **Accept:** tapping Grant opens the actual Android screen; journey gates on real permission state.
- Note: biometrics (Workflow A) + QR/NFC (Workflow C) ride the *same* JNI bridge — B unlocks them.

## Workflow C — Auth & pairing upgrades  ⏭️
- ⏭️ **Biometric "remember me"** — `BiometricPrompt` unlocks the saved guardian token in `session.rs`
- ⏭️ **Pairing via QR + NFC** (not just typed code): manager *generates* code/QR/NFC payload; child *scans (camera)* / *taps (NfcAdapter)* / types
- **Accept:** pair a device by QR and by NFC; guardian re-entry via biometric.

## Workflow D — Safety features  ⏭️ (after A+B)
- ⏭️ **Panic button** (child) → instant SOS + location to guardian; 2-min window then alert nearby parents (community SOS — emergency-scoped)
- ⏭️ **Location on request** (guardian asks → child shares, with consent)
- ⏭️ **Quick canned messages** (Home / School / Wake up)
- ⏭️ **Tamper/shutdown alert** — extend Device-Admin uninstall-guard to alert on attempt (honest: makes removal *hard*, not impossible)
- ♻️ **"Social-media monitoring"** → already delivered by the on-device detector (no platform API exists for parent-side monitoring) — document, don't build APIs
- ⛔ **Community account-reject / risk-rating / public warnings** — NOT building public accusations (defamation/vigilante/false-positive harm). Safe version only: private per-child block + **escalate verified cases to law enforcement** + a **vetted blocklist you control**.

## Workflow E — Branding polish  ⏭️
- ⏭️ **Launcher icons** — Dioxus.toml `[bundle] icon` didn't apply on Android; override the generated `res/mipmap-*` (BULWARK SHIELD mark) for child + manager
- ⏭️ **Labeling app** brand pass (still has emoji/generic style) to match child/manager
- ⏭️ Android app **display name** = "Bulwark Shield" / "Bulwark Manager" (Dioxus.toml name didn't take → manifest label)

## Workflow F — Model release (safe & open)  ⏭️
- ⏭️ Publish **model card + methodology + eval metrics** (architecture, training recipe, AUC/F1, intended use = defense/research, limitations, evasion caveat)
- ⏭️ Point researchers to the **original public datasets via proper academic channels** — do NOT re-host the corpus
- ⛔ Do NOT publish the **raw grooming dataset** or the **live deployed weights** (decided)
- Optional: a **synthetic-data-only** research model as the public artifact

## Workflow G — CI / release hardening  ⏭️
- ⛔/⏭️ **`APK boots on emulator`** is red on master too → pre-existing GitHub-Actions emulator flakiness (build+install succeed; the *real* app boots clean on the Pixel 7). Harden `reactivecircus/android-emulator-runner` (retry/boot-timeout) or mark non-required; capture the real launch log to rule out a true crash.
- ⏭️ Open PRs + merge the app-redesign branches (`feat/child-redesign`, the manager brand/light/modular commits on `feat/parent-dioxus-08`)
- Existing workflows: `android`, `android-emulator`, `ci`, `deploy`, `prerelease`, `release`, `store-publish` — wire the new app artifacts into release/store-publish when A–E land.

---

## Suggested order
**A.api.rs → A.get_started/dashboard → B (grants) → C (biometric/QR/NFC) → D (features) → E (icons/labeling) → F (model card) → G (CI/merge).**
B is the true functional unlock (grants + the bridge C rides on); A is the UX the guardian sees first.

## Decisions on record (do not relitigate)
- No AI decoy; no AI-CSAM generation. No public dataset/live-weights release. No crowd-sourced public accusations. (Rationale in session history + Workflow F/D.)
