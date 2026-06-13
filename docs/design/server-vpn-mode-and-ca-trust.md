# Server-side VPN mode (tunnel + filter + IP-anonymise) and the CA-trust fix

Status: **Phase 1 (CA-trust install) SHIPPED 2026-06-12; §1/§3-6 DESIGN.** Pairs with [parent-controlled-vpn.md](parent-controlled-vpn.md),
[realtime-filtering-and-attribution.md](realtime-filtering-and-attribution.md), and the
existing WireGuard scaffold [`deploy/wireguard/setup-london.sh`](../../deploy/wireguard/setup-london.sh).

## Why this doc

Two guardian-facing asks that the current build does not yet satisfy:

1. **Optional server-side filtering with IP anonymisation.** When a child device
   connects to a *PH Bulwark Cloud* region, the guardian should be able to choose
   to route the child's traffic *through* that region (a real WireGuard tunnel),
   so the region (a) NATs the traffic out under its own IP (the child's home IP is
   anonymised to the wider internet) and (b) runs the content filter server-side.
   This must be **optional** and per the guardian's choice: **filter on-device**
   (today's default) **or filter on the PH Bulwark Cloud server**.

2. **"Connection not private" must be fixable.** On-device TLS inspection presents
   a leaf cert signed by the per-install root CA; the device must *trust* that root
   or every HTTPS site shows "connection not private". Today the root is generated
   but never installed into the device trust store.

The honest, load-bearing fact that ties them together: **inspecting HTTPS requires
the inspection CA to be trusted on the device — in BOTH modes.** Tunnelling to the
server does *not* remove that requirement; it only moves *where* the leaf is minted.
So the CA-trust fix (§2) is a prerequisite for either mode to show clean HTTPS.

---

## 1. Two filtering modes

Today the region picker (`Servers` / `CLOUD_REGIONS`) only sets the **gRPC control
endpoint** (`api.predatorhunters.co.uk` — Accounts/Review/ChildControl/AlertRelay).
Filtering is always on-device (smoltcp pump → in-process TLS-inspecting proxy).

We add a **data-plane mode** to the child config, surfaced as a guardian toggle:

| Mode | Capture | Where HTTPS is inspected | Exit IP | Cost / privacy |
|---|---|---|---|---|
| **On-device** (default, today) | `VpnService` TUN → smoltcp pump | in-process proxy on the device | child's own ISP IP | cheapest; no plaintext ever leaves the device |
| **PH Bulwark Cloud** (new, opt-in) | `VpnService` TUN → **boringtun** WG client → region | proxy **on the region** | **region's IP (anonymised)** | region sees decrypted traffic; bandwidth + compute scale with traffic |

New `ChildConfig` field (proto, additive — keep field numbers stable):

```proto
enum FilterLocation { FILTER_ON_DEVICE = 0; FILTER_ON_SERVER = 1; }
// in ChildConfig:
FilterLocation filter_location = N;   // default 0 = on-device (today's behaviour)
```

The parent console owns the switch (same as `filtering_enabled` / `profile`); the
child reconciles on its config poll (extend the table in
[parent-controlled-vpn.md](parent-controlled-vpn.md) §"reconcile").

### On-device → server-mode reconcile (child action)
- Bring up a **boringtun** WG interface (MIT/BSD — license-clean; no GPL) to the
  region's `vpn.<region>` endpoint on UDP `51820`, keys provisioned at/after pairing.
- Route the TUN's default route into the tunnel (`AllowedIPs = 0.0.0.0/0, ::/0`).
- The region runs the **same `bulwark-net` proxy + rules/AI engine** on the
  forwarded flows (reuse the exact engine — no second implementation), NATs out.
- Kill-switch: keep the existing always-on/lockdown (`Lockdown.enforce`,
  `setAlwaysOnVpnPackage(lockdown=true)`) so tunnel-down ⇒ traffic blocked, not leaked.

### Server side (region)
- The WG endpoint already exists as a script (`setup-london.sh`: `wg0` +
  `MASQUERADE` exit). Productionise it: per-device peers (not one shared test
  client), peer lifecycle tied to enrollment, UDP `51820` in the security group.
- Insert the `bulwark-net` inspecting proxy **in the forward path** of `wg0` (the
  script's own TODO: "AI TLS inspection filter … is a separate follow-up").
- **CSAM invariant is unchanged and easier to enforce here:** server-side detect →
  **block + NCMEC report, NEVER store/serve** (one controlled choke-point). No
  explicit-media persistence; hashes/redacted evidence only.

---

## 2. The CA-trust fix ("connection not private")

Root cause (confirmed in code): `bulwark-net::ca::CaManager::load_or_generate`
mints a per-install root (private key never leaves the device — keep that
invariant), but **nothing installs the root's public cert into the Android trust
store**, and there is **no JNI export** of the cert. So every inspected HTTPS site
is untrusted.

Fix (additive, FFI-boundary-safe):
1. **bulwark-net:** expose the root cert bytes already held (`cert_der`/`cert_pem`)
   via a small accessor (public cert only — never the key).
2. **bulwark-android JNI:** add `nativeInspectionCaPem()` returning the PEM (mirror
   the existing JNI export pattern; one `external fun` in `RustBridge.kt`).
3. **Kotlin install:**
   - **Managed device (Device Owner / work-profile):**
     `DevicePolicyManager.installCaCert(admin, caBytes)` → lands in the **system**
     store ⇒ trusted by Chrome and (non-pinned) apps. This is the real fix and the
     only one that gives transparent HTTPS coverage.
   - **Unmanaged device:** can only reach the **user** store (Settings → Security →
     Install a certificate → CA), which **Android 7+ apps ignore by default**.
     Surface honest guidance; full coverage needs management.

### Honest coverage limit (drives the product decision)
On modern Android, transparent HTTPS inspection requires a **managed** device
(Device Owner via factory-reset/QR/zero-touch provisioning, or a work profile).
The phone currently has **Device Admin only** (Device Owner was blocked by the
pre-existing accounts on it). Until it's managed:
- **Cert-pinned / E2E apps** (WhatsApp, Signal, iMessage, many games) can never be
  read on the wire by *any* network position — on-device or server-tunnel. These
  are covered by the **on-device OCR / accessibility path** (`bulwark-agent`), which
  is the designed fallback and is independent of this whole TLS question.
- **Server-mode does not rescue this**: the region still mints a leaf the device
  must trust, so the CA-trust fix is required there too.

---

## 3. Constraints carried in (non-negotiable)

- **Licensing:** boringtun (BSD-3) / wireguard-go (MIT) only — **no GPL** (the
  reason `tun2proxy` was removed). The WG userspace must stay permissive.
- **CSAM:** detect → block → NCMEC report, **never stored / never served**, in
  server-mode exactly as on-device.
- **Privacy disclosure:** server-mode means the region decrypts and forwards the
  child's traffic. That is a real change in data flow and MUST be presented to the
  guardian plainly at the toggle ("traffic is routed through and filtered by the
  PH Bulwark Cloud region you chose"). Default stays **on-device** (no backhaul).
- **mTLS / no plaintext** between nodes unchanged; per-install CA never shared.

---

## 4. Phased plan (each a reviewable PR)

1. ✅ **CA-trust fix (SHIPPED 2026-06-12):** `bulwark-net::vpn::inspection_ca_pem`
   → JNI `inspectionCaPem(caDir)` → Kotlin `CaTrust.ensureInstalled` →
   `DevicePolicyManager.installCaCert` on the Device-Owner path (idempotent via
   `hasCaCertInstalled`), wired into `MainActivity.requestAntiRemoval`. Honest
   coverage limit (managed device required) documented in §2. Remaining for this
   phase: a non-managed-device Settings-guided fallback + an in-app trust-status
   indicator, and the Pixel install check (post-loop, on-device).
2. **WG server hardening:** per-device peers + lifecycle, SG UDP 51820, idempotent
   provisioning folded into the deploy (or a sibling role); keep it OFF by default.
   **Provisioning contract (server side):** the child calls
   `WgProvision.RegisterWgPeer` (device-token auth, public key only) and receives
   `{assigned_address, server_public_key, server_endpoint, keepalive_secs,
   filter_active}`. The gRPC handler never touches wg(8): it persists the desired
   peer set to `${BULWARK_STATE_DIR}/wg_peers.json`
   (`/var/lib/bulwark/wg_peers.json` on the region box) and an on-box reconciler
   (cron/SSM, root) applies it:
   `jq -r '.peers[] | [.device_id, .public_key] | @tsv' /var/lib/bulwark/wg_peers.json |
   while IFS=$'\t' read -r dev key; do bulwark-wg-peers add-peer "$dev" "$key"; done`.
   The file is sorted by address (= allocation order) and peers are never removed
   in this increment, so wg-peers.sh's lowest-free allocation converges on the
   granted addresses; an `add-peer --ip` pin must land before any deregistration
   flow. Env knobs: `BULWARK_WG_SERVER_PUBLIC_KEY` (required for grants),
   `BULWARK_WG_ENDPOINT`, `BULWARK_WG_KEEPALIVE_SECS`, `BULWARK_WG_FILTER_ACTIVE`
   (stays unset/false until phase 3 is actually in-path).
3. **`bulwark-net` proxy in the `wg0` forward path** on the region (reuse the engine).
   **Code SHIPPED (Phase 3 increment):** `crates/bulwark-net/src/vpn/transparent.rs`
   (Linux-only `SO_ORIGINAL_DST` front-end adapting REDIRECT'd sockets into the
   CONNECT bridge the on-device pump already uses — one engine, both modes) +
   `deploy/wireguard/wg-filter.sh` (iptables REDIRECT on wg0 tcp/80+443, QUIC/443
   drop, forwarded-v6 drop; `enable` REFUSES unless the proxy is listening, and
   proxy death = fail-closed RST — the redirect is never torn down to "restore"
   an unfiltered exit). STILL REQUIRED before any child uses it: server-bin
   wiring that runs the proxy + transparent listener on the box, the region
   inspection-CA contract (separate, MORE powerful than the gRPC cluster_ca —
   per-device recommended; installed/removed on the device like the §2 CA),
   staged validation per §6, and only then `BULWARK_WG_FILTER_ACTIVE=1`.
4. **`filter_location` in the proto + ChildConfig + parent toggle** (additive).
5. **boringtun client in the Android shell** + reconcile (bring tunnel up/down on
   the toggle) + kill-switch wiring to the existing lockdown.
6. **End-to-end validation** on the Pixel: on-device mode vs cloud mode, IP shows
   the region in cloud mode, filter fires in both, fail-closed on tunnel drop.

Increment 1 is the direct answer to "ensure connection-not-private is fixed" and is
shared by every later step, so it leads.
