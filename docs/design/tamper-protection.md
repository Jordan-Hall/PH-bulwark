# Tamper resistance & uninstall protection

How Aegis keeps the **child** app from being removed or disabled without an
adult's approval — and, where prevention isn't possible, makes removal
**detected and reported**.

> **Framing — this is legitimate *because* it is transparent + consented.** These
> mechanisms apply only to a **managed child device** that the guardian set up,
> where the child can see Aegis is active. The same techniques applied covertly to
> an adult's device would be stalkerware; Aegis never does that (visible
> enrollment, no covert persistence, no raw-content exfiltration, no auto-reporting).

## The model: prevent → detect → re-enroll

No software-only protection is absolute. Honest layering:

1. **Prevent** removal where the platform allows it (managed devices).
2. **Detect + report** every downgrade/removal to the guardian (works everywhere).
3. **Re-enroll** on reset for devices enrolled as managed from setup
   (zero-touch / Apple ABM) — out of scope for v1, noted below.

---

## 1. Cross-platform safety net — tamper heartbeat (implemented)

The piece that works **on every platform**, even where removal can't be prevented.

- The child app sends a periodic **`Tamper.Heartbeat`** (`crates/aegis-proto`) with
  a content-free `ProtectionStatus` (VPN up? device-admin active? accessibility on?
  always-on lockdown?) plus any `TamperKind` events it detected locally.
- The cluster (`aegis-server::tamper::TamperService`) turns a self-reported
  downgrade — or the **absence** of heartbeats past a grace window (app killed,
  offline, or uninstalled) — into a guardian **`AlertEvent(PROTECTION_DISABLED)`**,
  fanned out through the same relay/Review stream as every other alert (scoped per
  child/device). A missed-heartbeat alert is debounced (once per outage).
- The desktop binaries (`aegis_proxy`, `aegis_vpn`) run the reporter
  (`aegis-client::tamper::run_heartbeats`); Android reports via
  `RustBridge.reportTamper`.

Carries **no content** — only *which* protection changed.

---

## 2–4. Android

Three tiers, weakest → strongest. All are visible/consented on the managed device.

### 2. Device Admin + uninstall-guard (no factory reset needed — weakest)
- **`AegisDeviceAdminReceiver`** (`co.libertyware.aegis.admin`): while it is an
  active device admin, Android won't uninstall the app until admin is first
  *deactivated* in Settings. Deactivation fires `onDisabled` →
  `TamperReporter.report(DEVICE_ADMIN_REMOVED)` so the guardian is told.
- **Uninstall-guard** (`AegisAccessibilityService`): watches the package
  installer / Settings (`TYPE_WINDOW_STATE_CHANGED`); if the visible screen is an
  attempt to uninstall Aegis, it raises `APP_UNINSTALL_ATTEMPT` and navigates Home.
  Friction + detection, not an absolute block. (Google Play restricts accessibility
  use — this is for managed/sideloaded distribution.)

### 3. Always-on VPN with lockdown (fail-closed)
- `Lockdown.enforce` calls `setAlwaysOnVpnPackage(admin, pkg, lockdownEnabled=true)`:
  if the filtering VPN is ever off, traffic is **blocked** rather than flowing
  unfiltered. Requires Device Owner to set programmatically (or the guardian toggles
  it once in Settings → Network → Advanced → Always-on VPN).

### 4. Device Owner (DPC) — the only *robust* tier
Provisioned on a **factory-reset** device via QR / NFC / zero-touch, or in dev with
`adb shell dpm set-device-owner co.libertyware.aegis/.admin.AegisDeviceAdminReceiver`.
`AegisDeviceAdminReceiver` handles `onProfileProvisioningComplete` (QR/NFC/zero-touch)
and `DEVICE_OWNER_CHANGED` (the dev `dpm` path): both call `Lockdown.enforce`, record
enrollment (`Enrollment`, reading `family_id`/`child_id`/`cluster_endpoint` from the
provisioning extras), and open the dashboard. `Lockdown.enforce` is also re-asserted
in `AegisApp.onCreate`.

As Device Owner it applies `setUninstallBlocked(self)`, `DISALLOW_FACTORY_RESET`,
`DISALLOW_SAFE_BOOT`, `DISALLOW_UNINSTALL_APPS`, and the always-on-VPN lockdown — and
the app **cannot** be deactivated or uninstalled without `dpm remove-active-admin` or
a factory reset. `Lockdown.release` relaxes everything for guardian-initiated
un-enrollment. Provisioning recipes (QR JSON, signing-cert checksum, dev `dpm`, FRP
limits): **`deploy/android/device-owner-provisioning.md`**.

---

## 5. Desktop (Windows / macOS / Linux)

**The linchpin is account separation:** the child is a **Standard (non-admin) user**
and the guardian holds the admin password. Then:

- The filter runs from a privileged, auto-started context the child user can't
  stop, and the uninstaller requires admin (UAC / `sudo` / polkit). A standard user
  cannot uninstall a machine-wide install or stop a system service.
- Auto-start scaffolding ships under `deploy/`:
  - **Windows** — `deploy/windows/install-aegis-service.ps1` (admin) installs the
    `aegis_svc` **SCM service** (LocalSystem, auto-start) and **locks its DACL**
    (`sc sdset`) so Interactive/Service users get query-only access — a Standard
    child can't `sc stop`/`sc delete` it or stop it from Services.msc; only
    LocalSystem + Administrators (the guardian) can. The service supervises
    `aegis_proxy.exe` and respawns it if killed. *Refinement (documented):* a
    session-0 service can't set the child's per-user WinINET proxy, so production
    should launch the proxy INTO the active session via `WTSQueryUserToken` +
    `CreateProcessAsUserW` (isolated Win32 in `aegis-net`), or host the in-process
    transparent VPN once its data path lands. `install-aegis-autostart.ps1` remains
    the no-service logon-task fallback.
  - **macOS** — `deploy/macos/co.libertyware.aegis.proxy.plist` (a LaunchDaemon for
    root-owned auto-start; a LaunchAgent variant for per-user). A managed Mac can
    additionally pin a Network/System Extension via MDM so it can't be removed
    without the management profile.
  - **Linux** — `deploy/linux/aegis-proxy.service` (systemd).
- The tamper heartbeat (§1) is the detection backstop: kill the filter and the
  guardian gets a missed-heartbeat alert.

A user with the admin password, Safe Mode, or recovery can still remove it — this
**raises the bar + guarantees detection**, it is not absolute.

---

## 6. iOS

A normal app **cannot** prevent its own deletion — Apple forbids it. Two supported
routes (no Aegis app code can change this):

- **Screen Time (consumer, no MDM):** *Settings → Screen Time → Content & Privacy
  Restrictions → iTunes & App Store Purchases → Deleting Apps → **Don't Allow***,
  gated by the **parent's Screen Time passcode**. Simple and effective for families.
- **MDM + Supervision (managed / school):** a supervised device (Apple Configurator
  / ABM) can restrict app removal and pin a managed config the child can't remove.

The iOS child build therefore relies on the platform restriction for *prevention*
and contributes to the tamper heartbeat (§1) for *detection*.

---

## Honest limits

- **Factory reset / recovery / re-flash defeats anything** short of devices
  **enrolled as managed from setup** (Android zero-touch / Knox, Apple ABM/DEP),
  where Factory Reset Protection / Activation Lock re-bind the device to the
  org/family. Aegis now supports Device Owner *provisioning* (QR / NFC / dev `dpm`;
  see `deploy/android/device-owner-provisioning.md`), so `DISALLOW_FACTORY_RESET`
  blocks reset-from-Settings — but re-binding *after* a recovery-mode wipe still
  requires **zero-touch** registration (an operational EMM/reseller step), which is
  not something the app can set programmatically.
- **Distributed video/parent review** still assumes a co-located guardian for
  `blob://` clips (see `on-device-scanning.md`); unrelated to tamper protection but
  the same "managed-device" assumption.
- Detection (§1) is the guarantee that survives every gap: if protection drops, the
  guardian is told.
