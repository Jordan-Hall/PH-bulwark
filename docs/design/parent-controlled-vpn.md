# Parent-Controlled VPN & Child Provisioning

How a guardian configures and governs the child's filtering VPN **remotely** from
the parent app — choosing the server/region, turning protection on/off, and setting
the filtering strictness — so the child device behaves like a normal "always-on VPN"
app but is **owned and controlled by the parent**, not the child.

This doc covers two linked capabilities:

1. **Easier pairing** — QR scan, NFC tap, or short code to create + link a child
   account in seconds (the friction-reducer for first-run). The mechanics live in
   [`app-pairing-and-regions.md`](app-pairing-and-regions.md); this doc adds the
   *parent-side UX* and how pairing seeds the first config.
2. **Remote VPN configuration** — a new `ChildControl` contract so the guardian sets
   a desired runtime config per child, and the child device applies it.

It builds on the existing `Accounts` model (parent account → assigned guardians →
children by `device_id`) and the `Tamper`/`Heartbeat` liveness channel in
[`bulwark.proto`](../../crates/bulwark-proto/proto/bulwark.proto). It is transparent
and consented: the child can always see protection is on and **who** manages it.

---

## 1. Product shape

The guardian app becomes the **remote control** for each child's protection — the
mental model parents already have from consumer VPN and parental-control apps:

- A per-child card with a **big VPN toggle** (Protected / Paused) and a **region/server
  picker** (UK · US · Self-hosted), plus a **strictness profile** (Younger child /
  Teen / Custom).
- Flipping the toggle or changing the region on the parent app **pushes** the new
  desired state to the child device, which applies it within seconds.
- The child device shows a calm status: *"Protected — managed by Mum"*, with the
  toggle **read-only locally** (the child can see it, not silently disable it).

This is the honest, consented version of "a VPN the parent turns on and off for the
child" — no covert control, no stalkerware surface (see the policy line in
[`apps.md`](apps.md)). What makes it enforceable vs. advisory depends on the Android
management tier (§4).

---

## 2. The `ChildControl` contract (new gRPC service)

A small, **content-free** control plane: desired config flows parent → cluster →
child; status flows child → cluster → parent (reuse the existing `Heartbeat`).
Add to `bulwark.proto` (sketch — exact field numbers fixed at implementation):

```proto
// Per-child desired runtime config, set by a guardian, applied by the child device.
// CONTENT-FREE: carries policy/routing only — never message or media data.
message ChildConfig {
  string child_id          = 1;
  string device_id         = 2;
  bool   filtering_enabled = 3; // the parent's master VPN on/off switch
  string server_region     = 4; // "uk" | "us" | "self"
  string server_endpoint   = 5; // resolved cluster endpoint the child filters through
  FilteringProfile profile = 6; // strictness / age band → bulwark-policy
  bool   require_always_on = 7; // request always-on VPN lockdown (needs Device Owner)
  uint64 config_version    = 8; // monotonic; the child applies only a strictly newer one
  int64  updated_ts        = 9; // unix epoch millis
  string updated_by        = 10; // guardian account id (audit)
}

// Strictness band; maps onto bulwark-policy AgeProfile + thresholds.
enum FilteringProfile {
  FILTERING_PROFILE_UNSPECIFIED = 0;
  YOUNG_CHILD                   = 1; // strictest
  PRETEEN                       = 2;
  TEEN                          = 3;
  CUSTOM                        = 4;
}

message SetChildConfigRequest {
  string token = 1;       // guardian session (also via Bearer metadata); must guard child_id
  ChildConfig config = 2; // config_version/updated_ts/updated_by set server-side
}
message ChildConfigAck { bool applied = 1; uint64 config_version = 2; string detail = 3; }

message ChildConfigFilter {
  string device_id = 1;   // child identifies by its device cert subject / device_id
  uint64 have_version = 2; // long-poll: return only when a newer config exists
  string device_token = 3; // per-device credential minted at pairing (PairResult)
}

service ChildControl {
  // Guardian sets desired config (auth: guardian token, scoped to their child).
  rpc SetChildConfig(SetChildConfigRequest) returns (ChildConfigAck);
  // Child fetches its current desired config (one-shot, e.g. on app start).
  // `have_version` doubles as the child's applied-version report (recorded).
  rpc GetChildConfig(ChildConfigFilter) returns (ChildConfig);
  // Child streams desired config; server pushes on every guardian change.
  rpc StreamChildConfig(ChildConfigFilter) returns (stream ChildConfig);
  // Guardian reads desired-vs-applied + last check-in (token-scoped).
  rpc GetChildStatus(ChildStatusRequest) returns (ChildConfigStatus);
}
```

Why a separate service (not bolted onto `Accounts`): config push is a **hot, polled**
path on the child and a **guardian-authenticated mutation** on the parent; keeping it
isolated mirrors how `Review`/`Tamper`/`AlertRelay` are separated, and keeps the
no-content invariant obvious by message shape.

### Versioning & safety
- `config_version` is **monotonic per child**; the child applies a config only if it is
  strictly newer than the one it holds. This prevents replay/rollback (an attacker
  can't re-push an old "filtering_disabled" config).
- `SetChildConfig` is authorized like every other mutation: a valid guardian session
  **assigned to that child** (same scoping as `Review.StreamPendingReviews`).
- `StreamChildConfig`/`GetChildConfig` **are device-authenticated** (DONE
  2026-06-11): the caller must present the per-device `device_token` minted at
  `RedeemPairCode` (returned exactly once; the server stores and compares only
  its sha256 digest, never the raw value). Unknown device or wrong token →
  `Unauthenticated`. Devices enrolled before tokens existed pass under a logged
  legacy grace (empty stored digest) until a device-removal/re-pair flow ships
  (re-pairing an enrolled device_id currently returns DeviceInUse — follow-up).
  `Tamper.Heartbeat`
  verifies the same token, so a spoofed heartbeat can't suppress the
  missed-check-in protection-status alert; pair-code redemption itself is
  rate-limited (the one unauthenticated guessing surface). The applied-version
  ack stays clamped to the desired version as defense-in-depth. mTLS
  client-cert binding remains a further hardening option in §7.
- The control plane is **content-free** — it carries policy + routing, never any
  message/media. Same privacy invariant as the rest of `bulwark.proto`.

---

## 3. How the child applies a config

On a newer `ChildConfig`, the child shell (Android `BulwarkVpnService` + the Rust
core) reconciles to the desired state:

| Field changed | Child action |
|---|---|
| `filtering_enabled` true→false | Stop the filtering pump / VpnService (or relax to always-on lockdown if managed); show *"Paused by guardian"*. |
| `filtering_enabled` false→true | Start `BulwarkVpnService` (consent permitting — §4); run the netstack pump. |
| `server_region` / `server_endpoint` | Reconnect the cluster client + restart the TLS inspection/pump against the new endpoint; trust the public roots for a public-cert region, or re-validate the per-server pinned CA when one is provisioned (private/self-hosted); re-scope alerts/heartbeats to the new server. (Matches the "on server switch" requirement already noted in `app-pairing-and-regions.md`.) |
| `profile` | Set the `bulwark-policy` `AgeProfile` + thresholds used by `analyzeText`/verdict evaluation. |
| `require_always_on` | If Device Owner: `Lockdown.enforce` (always-on VPN, fail-closed). Else: surface "ask the guardian to set this device up as managed" — cannot be forced. |

The child **acknowledges** the applied version on its next config poll: the
`have_version` it already sends in `ChildConfigFilter` (every 60s while filtering
runs + on app foreground) IS the applied-version report — the server records it
per enrolled device (monotonic; "last seen" in-memory) and the guardian-scoped
`GetChildStatus` exposes desired-vs-applied + the last check-in, so the parent UI
shows *"applied ✓ vN"* vs. *"pending — child offline"*. (Chosen over a `Heartbeat`
ack because the child sends no heartbeats yet — the poll already exists, so the
ack costs zero new child-side RPCs and zero new JNI surface.)

---

## 4. Android reality: advisory vs. enforced (be honest)

"Parent turns the child's VPN on/off remotely" is only fully enforceable under device
management. Three tiers, all transparent:

1. **Unmanaged (consent tier).** Android requires a **one-time** `VpnService.prepare`
   consent the first time the VPN starts (the new onboarding journey handles this).
   After that, the child app may start/stop **its own** VPN programmatically — so the
   parent's remote toggle works **while the app is installed and the service can run**.
   A determined child could disable it; that **downgrade is detected** and raises a
   `PROTECTION_DISABLED` alert via the `Tamper` heartbeat. Advisory + detected.
2. **Device Admin (friction tier).** Adds uninstall/disable friction via the existing
   `BulwarkDeviceAdminReceiver`; still not true enforcement.
3. **Device Owner (enforced tier).** On a factory-reset/managed child device,
   `Lockdown.enforce` sets **always-on VPN with lockdown** (`setAlwaysOnVpnPackage(...,
   lockdownEnabled = true)`) so traffic is **fail-closed** when the VPN is off, blocks
   uninstall, and disallows factory-reset/safe-boot. Here the parent's "on" is truly
   enforced; "off" relaxes the policy. This is the sanctioned managed-device path (see
   [`tamper-protection.md`](tamper-protection.md)), set up openly at provisioning.

The parent UI must **state the tier** per child ("Protection: enforced" vs. "advisory —
the child can pause it, you'll be told"). No false promises.

iOS/macOS: the equivalent remote toggle is via the Network Extension + an MDM/Managed
configuration; a non-managed iOS child can disable a content filter, so the same
"advisory + detected" honesty applies (see `apps.md` Apple limits).

---

## 5. Parent app UX (simple + calm)

Per-child home card:

```
┌────────────────────────────────────────────┐
│  Ava's phone                    ● Protected  │   ← live status (green/amber/grey)
│  ────────────────────────────────────────── │
│   Protection           [ ===( ) ]  ON        │   ← big VPN toggle (pushes ChildConfig)
│   Region               UK · London    ▾      │   ← region picker
│   Strictness           Teen           ▾      │
│   Enforcement          Advisory  ⓘ           │   ← honest tier badge
│   Last seen            2 min ago             │   ← from Heartbeat
│   [ View alerts ]      [ Settings ]          │
└────────────────────────────────────────────┘
```

- The toggle is **optimistic** (flips immediately) but shows **"applying…"** until the
  child's heartbeat confirms the new `config_version` — then **"applied ✓"**, or
  **"pending — child offline"** if it can't reach the device.
- Region change warns: *"This moves Ava's data to the US server and re-pairs filtering."*
- "Add child" launches the QR/NFC/code flow (§6).

Child app: a single calm status screen — *"Protected · managed by Mum · UK server"* —
with the toggle shown **read-only** (visible, not covertly removable), matching the
"the child can see it's running" transparency rule.

---

## 6. Easier child setup: QR · NFC · code

All three drop the child onto the **same server** as the parent and pre-fill the pair
code, then call `Accounts.RedeemPairCode` + seed the first `ChildConfig`. Details and
security live in [`app-pairing-and-regions.md`](app-pairing-and-regions.md#easier-pairing-qr--nfc--code);
summary of the parent-side flow:

- **QR (default, works phone-to-phone with no extra hardware):** parent app renders a
  QR encoding a signed pairing payload `{ server_region, server_endpoint, pair_code,
  expires_ts, child_name }`; the child app's camera scans it → auto-selects server +
  fills the code → one tap to pair. Fastest, no typing.
- **NFC tap:** parent device writes the same payload to an NDEF message; tapping the two
  phones transfers it. Great for the in-person setup most families do.
- **Code:** the existing short, single-use, short-lived `PairCode` typed manually — the
  universal fallback when cameras/NFC aren't available.

The payload is the **pair code (the credential) plus routing hints**; it is short-lived
and single-use, so a leaked QR/NFC blob expires fast and can't be replayed once redeemed
(same properties as the bare code today).

After redemption the parent immediately `SetChildConfig` with the chosen region +
strictness + `filtering_enabled = true`, so the child comes up **already protected**.

---

## 7. Build workflow (phased; each step shippable + tested)

1. **Proto + server — ✅ DONE (2026-06-10).** `ChildControl` is in `bulwark.proto`;
   `SetChildConfig`/`GetChildConfig`/`StreamChildConfig` are implemented in
   `bulwark-server` (`src/child_control.rs`) with guardian-scoped auth (reusing
   `AccountStore::guardian_scope`), per-child monotonic `config_version`, a
   `watch`-backed stream, and JSON persistence under `BULWARK_STATE_DIR`. Wired into
   the `accounts_enabled` server bootstrap. Covered by 4 unit tests + the
   `e2e_child_control.rs` e2e (guardian-set → version bump, non-guardian denied,
   get-by-device, stale-vs-current stream filtering).
2. **Child apply-loop — 🟠 PARTIAL (2026-06-10; applied-ack + profile reconcile
   added 2026-06-10).** Shipped: a `fetchChildConfig` JNI (one-shot
   `GetChildConfig`, same transport pattern as enrollment; config serialized
   content-free for Kotlin) + `ChildConfigSync` (Kotlin reconciler:
   `filtering_enabled` starts/stops `BulwarkVpnService`; strictly-older configs
   rejected — replay/rollback defense; applied `config_version` + strictness band
   persisted), polled every 60s while filtering runs and once on app foreground.
   The poll's `have_version` doubles as the applied-version ack (recorded
   server-side; `GetChildStatus` exposes it to the guardian), and the fetched
   `profile` live-updates the on-device `AgeProfile` policy global used by
   `analyzeText` (version-gated, no service restart; re-seeded from
   `deviceConfigJson()` after a process restart). Host-tested. Remaining:
   `StreamChildConfig` push, `server_endpoint` reconcile (reconnect the pump
   to a new region endpoint), and device-identity (mTLS-subject) binding for
   the child-facing Get/Stream reads.
3. **Parent UX — ✅ DONE (2026-06-10) for the control row + applied-ack.**
   `ChildVpnRow` in `apps/parent`: per-child region/server picker, filtering
   on/off, strictness band; Apply pushes `SetChildConfig`, shows the acked
   `config_version`, then polls `GetChildStatus` (5s cadence, ~3 min window) and
   flips the note to *"Applied on the child's device ✓"* once the child's config
   poll reports the version — else *"pending — not confirmed"*. NOT yet: the
   enforcement-tier badge.
4. **Easier pairing:** QR render/scan, then NFC; code stays as fallback.
5. **Enforcement tiers:** wire `require_always_on` → `Lockdown.enforce` on Device-Owner
   devices; surface the honest tier in both apps.

See the phase table in [`../../PLAN.md`](../../PLAN.md) for where this sits in the
roadmap, and [`realtime-filtering-and-attribution.md`](realtime-filtering-and-attribution.md)
for what the VPN actually filters once it's on.
