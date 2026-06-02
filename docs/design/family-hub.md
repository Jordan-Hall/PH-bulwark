# Aegis Family Hub — device management & parent control

A parent-controlled "family hub": one managed app on each child device + a parent
console, so a guardian can enforce content filtering that **can't be turned off
or uninstalled**, read messages (incl. E2E), control the device, and (on demand)
see the screen and location. Built on **Android Device Owner**.

> **Scope & line:** legitimate for a **guardian over their own minor child, on a
> device the guardian owns**, with **age-appropriate transparency** (a visible
> "managed by your family" posture — NOT covert spyware). Reading messages +
> screen/location is wiretap/consent-regulated; per-jurisdiction legal review is
> required (`legal-consent.md`). Distribution is via **Android Enterprise / EMM
> enrollment or sideload** + MASA Level 2 — not consumer Play.

## Capability matrix (Android)

| Capability | Mechanism | Constraint |
|---|---|---|
| **Can't be uninstalled** | Device Owner `setUninstallBlocked(true)`; can't be force-stopped/data-cleared/disabled | needs Device Owner |
| **Filtering can't be bypassed** | `setAlwaysOnVpnPackage(pkg, lockdown=true)` — always-on, fail-closed VPN | — |
| **Force-on settings** | `setLocationEnabled(true)`, disable Safe Mode, FRP bound to guardian account, block adding users | — |
| **Auto-granted permissions** | `setPermissionGrantState(GRANTED)` for location/SMS/etc. (no child prompts) | managed device only |
| **Read E2E chats** | `AegisAccessibilityService` reads rendered text (built) | accessibility consent |
| **Read SMS** | `READ_SMS` (DO-granted) | Play-restricted off managed devices |
| **See the screen (on-demand)** | `MediaProjection` capture → H.264 → stream to parent | OS shows a capture indicator; consent pre-granted only on a managed device |
| **Location (live + history)** | FusedLocationProvider → report to parent | background-location policy |
| **Remote lock / locate / wipe** | `DevicePolicyManager.lockNow()/wipeData()` + location | — |
| **App + screen-time policy** | block/allow apps, usage limits | — |

**Provisioning:** Device Owner can only be set on a **factory-reset** device
(QR / zero-touch enrollment, before any account). You can't silently become DO on
an in-use phone. Nothing survives a full reflash; DO makes removal require a wipe.

**iOS:** none of this is possible for a third-party app — iOS uses Supervised MDM
(Apple Configurator / ABM) with far narrower powers and **no** screen capture or
message reading. Family Hub is Android-first.

## Components
- **`aegis-dpc`** (new Android module): `DeviceAdminReceiver`/Device-Owner +
  `DevicePolicyManager` wrapper (uninstall-block, lockdown VPN, force-location,
  permission auto-grant, lock/locate/wipe, app/screen-time policy), a
  `MediaProjection` screen-capture+encoder, and a FusedLocation reporter.
- **proto `Control` service** (parent → cluster → child): `SetPolicy`,
  `BlockUninstall`, `ForceVpn`, `GrantPermissions`, `Lock`, `Locate`,
  `StartScreenStream`/`Snapshot`/`StopScreenStream`, `ListApps`, `RemoteWipe` —
  each command audited; the child DPC applies + acks.
- **Parent console** (mode of the existing app): device list, policy editor,
  alert + Review feed, live-screen view, map, command buttons.
- **Cluster command relay** (`aegis-server`): authenticated parent → child
  command routing over mTLS; commands queued/acked like work items.

## End-to-end
```
Parent console ──Control RPC (mTLS)──► cluster ──relay──► child aegis-dpc
   ▲  alerts / Review / screen / map        │                 │ applies policy,
   └──────────── push / stream ─────────────┘                 └ enforces, acks
```
Always-on lockdown VPN keeps `aegis-net` filtering inescapable; `aegis-agent`
(accessibility) + SMS feed the grooming pipeline; `aegis-policy`
approve/deny + the per-device allowlist govern overrides; every command +
override is in the tamper-evident audit log.

## Hard rules (unchanged)
Never persist/transmit explicit media; CSAM is flagged + reported, never shown or
stored, and never allowlistable. Screen/location/SMS are **managed-device,
visible** features with age-appropriate disclosure — not covert capture. All
control links are mTLS; the only outbound is the owner's own cluster + guardian
push.
