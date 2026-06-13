# PH Bulwark — tester guide (public beta, FOSS channels)

This is the guide for a **guardian** who wants to help test PH Bulwark on a device
they own, used by a **minor they are the legal guardian of**. Read it end-to-end
before installing — it tells you honestly what works today, what is still being
validated, and how your family's data is handled.

PH Bulwark is a **consensual, openly-visible, parental-control content-filtering
VPN**. It is installed by the guardian, it is **visible on the child's device**, and
it **can be turned off**. It is not covert monitoring. See
[FRAMING.md](FRAMING.md) for how we describe what it does.

> **Beta status (be honest with yourself before you start).** This is an early
> public beta. Several core flows are implemented and CI-tested but **not yet
> validated on a real phone** — they are marked 🧪 below. The authoritative
> GO/NO-GO gate is [`public-beta-readiness.md`](public-beta-readiness.md); if that
> file says NO-GO for a surface, treat this guide as a preview for that surface, not
> a promise. Do not rely on PH Bulwark as a child's only protection during beta.

---

## 0. The two (three) apps

| App | Package id | Role |
|---|---|---|
| **PH Bulwark** (child) | `co.predatorhunters.bulwark` | The supervised child's device app — filtering VPN, protection status, SOS, pairing. |
| **PH Bulwark Camera** | `co.predatorhunters.bulwark.camera` | A safe camera for the child's device — on-device-only NSFW capture block. Declares **no network permission at all**. |
| **PH Bulwark Manager** | `co.predatorhunters.bulwark.manager` | The guardian console — create account, add child, mint a pair code/QR, see alerts and protection status. Desktop (Win/macOS/Linux) and experimental Android. |

The child app and the Manager can coexist on the same phone (different app ids),
but the normal setup is **Manager on the guardian's device, PH Bulwark + Camera on
the child's device.**

---

## 1. Installing from the FOSS channels (no Play Store)

PH Bulwark is free, non-profit, open-source and is **not distributed through the
Google Play Store** during beta. Install from one of the open channels below.

> **Availability today (read this first).** The CI release pipeline currently
> attaches the **child app APK** to GitHub Releases as a **debug/unsigned** build
> (signed release builds are gated on an owner-supplied keystore — see
> [`public-beta-readiness.md`](public-beta-readiness.md)). The **Camera app APK and
> the Android Manager APK are not yet attached to Releases** (the CI build compiles
> the Camera module but only uploads the child APK). So in practice:
>
> - **Child app** — installable now via Obtainium / direct download, **unsigned**.
> - **Camera app** — build locally from `platform/android` (`:camera` module) until
>   the release job ships it.
> - **Manager (Android)** — build locally with `dx` (see §1.4) until shipped; the
>   **desktop** Manager builds from `apps/parent`.
> - **F-Droid repo / Accrescent** — **not set up yet** (both require signed APKs).
>
> The per-channel instructions below are written so they are ready the moment those
> channels go live; each notes its current availability.

### 1.1 Obtainium → GitHub Releases (works today, child app)

[Obtainium](https://github.com/ImranR98/Obtainium) installs and auto-updates APKs
straight from a GitHub Releases page — no store account, no extra repo.

1. Install Obtainium (itself from F-Droid or its GitHub Release).
2. In Obtainium, **Add App** and paste the PH Bulwark repo Releases URL:
   `https://github.com/Jordan-Hall/PH-bulwark/releases`
3. Obtainium lists the published release assets. Pick the **child APK**
   (`ph-bulwark-child-android.apk`).
4. Tap **Install**. Android will ask you to allow installs from Obtainium ("Install
   unknown apps") — allow it for Obtainium only.
5. Obtainium will offer the update whenever a new release is tagged.

> ⚠️ During beta the published APK is **debug-signed (unsigned for release)**. You
> will see Play Protect / "unknown source" warnings — expected for a beta FOSS app.
> A signed channel is the minimum bar before we invite people outside this tester
> group (see [`public-beta-readiness.md`](public-beta-readiness.md)).

### 1.2 Self-hosted F-Droid repo (planned — needs signed APKs)

Once signed APKs exist we will publish a **self-hosted F-Droid repository** so you
can add one URL and get both apps with signature-pinned auto-updates:

1. Install the **F-Droid** client.
2. **Settings → Repositories → Add (＋)** and paste the repo add-URL
   (published in the release notes when live), including its `?fingerprint=…`.
3. Update the repo; PH Bulwark and PH Bulwark Camera appear in the app list.
4. Install from there; F-Droid pins the publisher signature on update.

> Status: **not available yet.** F-Droid inclusion (or a self-hosted repo) requires
> a stable release-signing key, and F-Droid may require the Device-Owner /
> Accessibility tooling to be clearly opt-in or repackaged — see
> [`release.md`](release.md) §1 and §4.

### 1.3 Accrescent (planned — needs signed APKs)

[Accrescent](https://accrescent.app/) is a modern, security-focused FOSS app store
(per-app signing, no auto-grant of dangerous permissions). When a signed release
exists we intend to submit both apps. **Status: not submitted yet.**

### 1.4 Building the apps yourself (always available)

Everything is buildable from source today — this is the FOSS guarantee and is how
you install the **Camera** app and the **Android Manager** until they ship on a
channel.

- **Child app + Camera app:** from `platform/android` build the JNI core then
  `gradle assembleDebug` (see root `CLAUDE.md` build table). `assembleDebug` builds
  **both** the `:app` (child) and `:camera` modules.
- **Manager (desktop):** from `apps/parent`, `cargo build --release`.
- **Manager (Android, experimental):** from `apps/parent`,
  `dx build --platform android --device <serial>` (must pass `--device`).

---

## 2. Pairing the child device to the guardian (Manager)

Pairing links the child's device to your guardian account on the server you choose,
so redacted alerts and the SOS reach **you** and nobody else.

> 🧪 The pairing flow is implemented and covered by gRPC end-to-end tests
> (`crates/bulwark-server/tests/e2e_accounts_pairing.rs`,
> `e2e_app_workflow_harness.rs`) and the apps run on a real Pixel 7, but the full
> **mint-code → scan-on-a-second-phone → redeem** loop has not been signed-off on
> real devices end-to-end. Expect rough edges; report them (see §7).

1. **On the guardian device (Manager):**
   1. Open PH Bulwark Manager.
   2. Choose your **server**: **UK/London cloud** (the live cloud region today), or
      a self-hosted `https://host:port`. *(A US cloud region is planned but **not
      deployed yet** — picking it during beta pairs against a dead endpoint; use
      UK/London or self-host.)*
   3. **Create an account** (or sign in) on that server.
   4. **Add child** and enter the child's display name.
   5. The Manager shows a **Setup code** panel: a short single-use code, a **QR**,
      and a **Copy setup code** button. (This is "pairing payload v2", shipped in
      the Manager in PR #104 / #125.) The payload carries the server endpoint, the
      one-time code, an expiry, and — only for a self-hosted/private-CA server — the
      pinned CA so the child can make its first verified TLS call. Cloud regions use
      a public Let's Encrypt cert, so no CA travels in the payload.

2. **On the child device (PH Bulwark):**
   1. Open PH Bulwark; choose the **same server** (or use the QR, which auto-selects
      it).
   2. **Scan the setup QR** (camera) — or **paste** the copied setup code — or type
      the short code by hand. All three carry the same single-use credential.
   3. The app redeems the code (`Accounts.RedeemPairCode`), stores its device id,
      `child_id`, and `family_id`, and is then **already protected** (the Manager
      seeds a first config with `filtering_enabled = true`).

Notes:
- Pair codes are **short-lived and single-use**; a leaked/expired code is dead.
- If the Manager and child app are on the **same phone**, you can't scan your own
  screen — use **Copy setup code → paste**.
- The child's first config comes up with filtering ON (region + strictness).

---

## 3. What to test (and how to tell it worked)

Please exercise these and report what you see. For each, note the device model,
Android version, and whether the device is **managed (Device-Owner)** or normal.

### 3.1 Filtering on / off
- After pairing, confirm the child app shows **protection active**.
- From the **Manager**, toggle filtering / strictness for the child and confirm the
  child app reflects the change (`GetChildStatus` echoes the desired config — PR
  #125).
- 🧪 The **transparent VPN data path** (the part that actually inspects HTTPS
  traffic on-device) is implemented and host-tested but **device-validation is
  pending** (`production-readiness.md`). On a normal (un-managed) device, HTTPS
  inspection is **partial** — see §4.

### 3.2 Protection status (anti-removal / "protection-status alert")
- Disable the VPN, or revoke a permission, or try to remove the app. The child app
  should show protection is off, and the **Manager should receive a
  `PROTECTION_DISABLED` alert** (the tamper heartbeat turns a downgrade — or missed
  heartbeats — into a guardian alert; `docs/design/tamper-protection.md`).
- This is **disclosed and consented**, not hidden. On a managed/Device-Owner device
  removal is made *hard*; on a normal device it is **detected and reported**, not
  prevented.

### 3.3 Child SOS ("I need help right now")
- In the child app's status dashboard, press **SOS**, then the explicit
  **"Yes — send"** confirm (two deliberate taps by design).
- The **Manager should receive an URGENT child-SOS alert**
  (`FamilySafety.RaiseSos` → `CHILD_SOS`; `crates/bulwark-server`). The SOS is
  **content-free** — device identity + time only, no location, no messages, no
  media.
- Honesty check built in: if **no** guardian path actually took the alert, the child
  is told to call **999 / a trusted adult** instead of being falsely reassured.
  Please test the "no guardian online" case too.

### 3.4 Alerts in the Manager
- Confirm grooming-pattern / content alerts and the protection/SOS alerts above
  appear in the Manager's review stream, **scoped to your children only**.
- Alerts are **redacted and content-free** — you should never see raw messages or
  media in an alert.

### 3.5 Camera app on-device NSFW block
- Install **PH Bulwark Camera**, open it, and take photos.
- A photo the on-device classifier scores as explicit is **blocked and dropped from
  memory** — never saved, hashed, logged, or sent. The app declares **no network
  permission**, so the OS itself guarantees nothing leaves the device
  (`platform/android/camera/.../NsfwGate.kt`).
- 🧪 The scoring mirrors the engine's bundled classifier; **on-device behaviour
  (accelerator/NNAPI vs CPU fallback, false-positive/negative rate on a real
  camera) is not yet device-validated.** Report obvious mis-blocks or misses.

---

## 4. Device requirements (honest)

| Requirement | Detail |
|---|---|
| **Child app — Android version** | **Android 8.0+ (API 26)**. Set in `platform/android/app/build.gradle.kts` (`minSdk = 26`). |
| **Camera app** | Any device with a camera; same Android baseline. |
| **Full HTTPS inspection** | Needs a **managed / Device-Owner** device. On Android 7+ a normal app **cannot** make other apps trust a user-installed inspection certificate, so on an un-managed device HTTPS filtering is **partial** (the system trust install via `DevicePolicyManager.installCaCert` only works when the app is Device Owner — shipped 2026-06-12; `production-readiness.md`). The on-device on-screen agent (below) is the fallback for what the network filter can't see. |
| **On-device screen agent (E2E / pinned apps)** | The accessibility/screenshot agent that covers WhatsApp/Signal-style apps is **API 30+** territory and is **not functional yet** (cross-platform orchestration exists in `bulwark-agent`; the native capture + overlay is the in-progress increment — `docs/design/on-device-scanning.md`). |
| **iOS** | **No installable iOS app yet** — only a Rust-FFI/Swift scaffold (`platform/apple`). |
| **Desktop child filter** | Windows today (`bulwark_proxy`); the transparent VPN path is fail-closed pending device validation. macOS/Linux child filter is not the beta focus. |
| **Manager** | Desktop Win/macOS/Linux (`apps/parent`, `cargo build --release`); Android Manager is experimental via `dx`. |

**Plain-English summary:** on a **managed/Device-Owner** child phone you get the
fullest protection. On a **normal** phone, network filtering is partial (HTTPS in
apps that pin or that don't trust the user CA won't be inspected), protection-status
is **detected and reported** rather than prevented, and the on-screen agent for
encrypted chat apps isn't available yet. The **Camera app works the same on any
device** because it doesn't rely on the network path.

---

## 5. Privacy promise to testers

- **Nothing about your child's content leaves their device except redacted,
  content-free safety alerts sent to *your* guardian account.** No raw messages, no
  media, no screenshots ride the alert channel — only *which* category/protection
  changed (and for SOS, device id + time).
- **Illegal child-abuse imagery is detected, blocked, and (on the network path)
  reported to the proper authority — never stored, never served, never archived.**
- **The Camera app sends nothing at all** — it declares no network permission; the
  OS enforces that.
- **No covert monitoring, no keylogging, no selling data.** PH Bulwark is visible on
  the child's device and can be turned off (with a protection-status alert to you).
- You choose the **server region** (UK / US / your own self-hosted box); your
  family's data stays on the deployment you pick.
- The grooming dataset and the live model weights are **not** published; there are
  **no crowd-sourced public accusations** — blocks are private to your family, with
  lawful escalation only.

---

## 6. Consent & uninstall (required reading)

- Install PH Bulwark only on a device **you own**, for a **minor you are the legal
  guardian of**, and **tell the child it is there** — that disclosure is what makes
  this a legitimate parental-control tool rather than stalkerware.
- **Turning it off / uninstalling:** the app is removable. On a normal device,
  disabling protection or uninstalling fires a **protection-status alert** to the
  guardian and is otherwise unobstructed. On a managed/Device-Owner device removal
  requires deactivating device admin first (deliberate friction), which also alerts
  you. There is no hidden, unremovable persistence.

---

## 7. Reporting bugs

- File issues on GitHub: **https://github.com/Jordan-Hall/PH-bulwark/issues**
- Please include: app + version, device model, Android version,
  **managed/Device-Owner or normal**, the channel you installed from, and exact
  steps. Logs without raw content are welcome (`adb logcat` snippets).
- **Never paste a child's actual messages, media, or any illegal imagery into an
  issue.** If you believe you have encountered illegal imagery, do **not** download
  or forward it — report it to the proper authority. PH Bulwark blocks and reports
  it automatically on the network path and never stores it.
- Security-sensitive reports: see `SECURITY.md` (if present) or mark the issue
  privately rather than posting details publicly.

Thank you for helping protect children. Honest, specific bug reports — especially
"this said it was protected but X got through" or "the alert never reached me" — are
the most valuable thing you can give us during beta.
