# Child/Guardian Apps, Server Choice, and Pairing

This is the product plan for the two app roles and the server/account lifecycle.
It supersedes older "family hub" language that implied remote control, screen
capture, or covert monitoring. The product scope here is transparent content
safety: child-side filtering, redacted alerts, guardian review, and honest
coverage status.

## App Roles

### Child App

Runs on the supervised child device.

- Filters traffic/content using the platform-appropriate child shell:
  - Windows: `bulwark_proxy` today; transparent VPN path is still fail-closed while
    the replacement netstack is device-tested.
  - Android: native `VpnService`/accessibility shell plus the shared Rust core.
  - macOS/iOS: Network Extension shell planned.
- Sends redacted `AlertEvent`s and protection heartbeats to the selected server.
- Has enrollment UI only: choose server, enter pair code, show protection status.
- Does not expose guardian review, account management, or device-control UI.

### Guardian/Adult App

Runs on the guardian's device.

- Chooses exactly one active server: UK/London cloud, US cloud, or self-hosted.
- Creates/logs into a guardian account on that server.
- Creates children and guardian assignments.
- Generates a short-lived child pairing code.
- Streams pending reviews scoped to the logged-in guardian's children.
- Submits approve/deny decisions.
- Shows coverage and protection status honestly.

## Server Choice

The active server is a deployment boundary, not just a display setting. A family
belongs to one selected backend at a time:

- UK/London cloud: data stays on the UK deployment.
- US cloud: data stays on the US deployment.
- Self-hosted: user enters `http(s)://host:port` for their own `bulwark-server`.

Current parent app state:

- `server.txt` stores the active server id; legacy raw self-hosted URLs still
  resolve and are surfaced as saved self-hosted entries.
- `servers.json` stores named self-hosted endpoints, merged with the built-in
  UK/London and US cloud choices.
- `cluster_endpoint()` resolves the saved choice and passes it to the spawned
  child filter through `BULWARK_CLUSTER_ENDPOINT`.
- Guardian sessions are endpoint-scoped under
  `sessions/<server_hash>/guardian_token.txt`, so a London token is not silently
  reused against US or self-hosted servers.
- A server-specific pinned CA can be placed at
  `sessions/<server_hash>/cluster_ca.pem`; `BULWARK_CLUSTER_CA` still wins as the
  ops override.

Required next change:

- On server switch:
  - stop/restart the local child filter so it uses the new endpoint,
  - reconnect the Review stream,
  - require login or token selection for the newly selected server,
  - show "not enrolled on this server" until the child device is paired there.

## Account and Pairing Flow

The server already implements the core primitives in `Accounts`:

- `CreateAccount`
- `Login`
- `AddChild`
- `AssignGuardian`
- `ListChildren`
- `CreatePairCode`
- `RedeemPairCode`

The target UX:

1. Guardian selects UK, US, or self-hosted.
2. Guardian creates/logs into an account on that selected server.
3. Guardian taps "Add child", enters the child's display name.
4. Adult app calls `Accounts.CreatePairCode(token, child_name)`.
5. Adult app shows the short code and expiry.
6. Child app is installed on the child device.
7. Child app uses the same server selection and asks for the code.
8. Child app computes/loads its stable `device_id`.
9. Child app calls `Accounts.RedeemPairCode(code, device_id)`.
10. Server creates the child record, links `device_id`, assigns the minting
    guardian, and returns `child_id`/`family_id`.
11. Child app stores endpoint, `device_id`, `child_id`, and `family_id`.
12. Alerts and heartbeats now route by `device_id`; `child_id`/`family_id` are
    extra diagnostics and can ride on heartbeats where the platform shell has them.

Important security properties:

- Pair codes are short-lived, single-use credentials.
- Pair code redemption is unauthenticated by design; the code is the credential.
- Wrong-code redemption attempts share one GLOBAL rate limit (same window as
  sign-in). Known tradeoff: sustained wrong-code traffic pauses ALL new pairing
  for the window — fail-direction safe (already-enrolled children are
  unaffected); per-peer keying at the transport layer is the follow-up if it
  ever bites.
- A successful redeem also mints the `device_token` the device authenticates
  with from then on. Rollout note: ship the child app update with/after the
  server that mints tokens — an OLD child app pairing against a NEW server
  discards the minted token, and that enrollment's heartbeats/config fetches
  are then refused.
- `device_id` must be unique. Reuse is rejected because it could route one
  device into two families' scopes.
- Guardian review streams and decisions require a valid guardian session token in
  accounts mode.
- A guardian can see or approve only children they are assigned to.

## Easier pairing: QR · NFC · code

The bare short code (above) is the universal fallback, but typing a code + picking a
server is the main first-run friction. Two faster methods front-load the same
`RedeemPairCode` call so the child device is paired in seconds. All three carry the
**same credential** — a short-lived, single-use pair code — plus routing hints, so they
inherit the same security properties (a leaked QR/NFC blob expires fast and is dead once
redeemed).

The shared **pairing payload** (what QR encodes / NFC writes / "Copy setup code"
copies — **v2, shipped in the Manager console 2026-06-11**):

```json
{
  "v": 2,
  "server_region": "uk",
  "server_endpoint": "https://<cluster-host>:8443",
  "pair_code": "ABCD2345",
  "expires_ts": 1750000000000,
  "child_name": "Ava",
  "cluster_ca_pem_b64": "<base64 of the pinned CA PEM — omitted when no CA is pinned>"
}
```

`cluster_ca_pem_b64` is OPTIONAL. The cloud regions (UK/London, US) now serve a
real public certificate (Let's Encrypt on `api.predatorhunters.co.uk` /
`vpn.predatorhunters.co.uk`), so the child device validates them with the
standard public trust store and needs no pinned CA — the field is simply
omitted. It is carried only for a **self-hosted / private-CA** server, so the
child can make its FIRST TLS call there with no manual CA provisioning. It is
public certificate material, not a secret — the short-lived, single-use
`pair_code` remains the only credential. If a large CA makes the QR too dense to
encode, the console falls back to a QR without it; the "Copy setup code" paste
path always carries the complete payload.

- **QR (default — phone-to-phone, no extra hardware).** After "Add child", the parent
  app renders the payload as a QR. The child app opens the camera, scans it, and
  **auto-selects the server + fills the code** — the guardian's chosen region and the
  code arrive together, so the child can't accidentally pair to the wrong server. One
  tap → `RedeemPairCode`. Fastest path; no typing.
- **NFC tap — honestly NOT viable phone-to-phone anymore (corrected 2026-06-11).**
  Android removed Beam (phone-to-phone NFC push) in Android 10, so "tap the two
  phones back-to-back" no longer exists on modern devices. NFC survives only as
  *tag* reading (a guardian writes the payload to a physical NFC tag) — a niche
  flow we are not building. QR scan (shipped: the child app's "Scan the setup
  QR" button, zxing-android-embedded) + copy/paste + the typed code cover the
  real cases. Single-device note: when the Manager runs on the SAME phone as
  the child app, a phone cannot scan its own screen — copy/paste is the path.
- **Code.** The existing short, single-use, short-lived code typed by hand — the
  always-available fallback (camera denied, accessibility setup).

Implementation notes:

- The payload is **not** a second credential — the `pair_code` inside it is the same
  one `CreatePairCode` mints, so no new server surface is required for QR/NFC; only the
  apps change. Redemption still goes through the unauthenticated `RedeemPairCode` (the
  code is the credential) and is single-use.
- Encode `expires_ts` so the child app can show *"this code has expired — ask for a new
  one"* before even calling the server.
- After a successful redeem, the parent app seeds the child's first
  [`ChildConfig`](parent-controlled-vpn.md) (region + strictness + `filtering_enabled =
  true`) so the device comes up **already protected**.

## Self-Hosted Server

A self-hosted family runs the same `bulwark-server` binary:

```text
BULWARK_ACCOUNTS=1
BULWARK_STATE_DIR=/var/lib/bulwark
BULWARK_BIND=0.0.0.0:8443
bulwark-server --role all-in-one
```

For production self-hosting:

- Prefer TLS. With a publicly-trusted cert (e.g. Let's Encrypt) no pin is needed.
  Set `BULWARK_CLUSTER_CA` in the guardian app only when using a private CA.
- Keep `BULWARK_STATE_DIR` durable, backed up, and private.
- Provision SMTP/FCM only if alerts need email/push fan-out.
- Client heavy-media offload still needs client mTLS material; alert/review can
  use the normal guardian token path.

## Current Status

Implemented:

- Server selection in the parent app for UK, US, and self-hosted URL.
- Named parent server inventory UI backed by `servers.json`, with per-endpoint
  saved-session and pinned-CA status.
- Endpoint propagation from parent app to spawned child filter.
- Per-server guardian token file/env support.
- Parent app setup dashboard with server status, create/login, child list, and
  create-pair-code flow.
- Android child app enrollment screen: server choice, pair-code redemption via
  `Accounts.RedeemPairCode`, stable device id, and local
  `family_id`/`child_id`/endpoint persistence.
- Accounts service, guardian scoping, child/device records, pair codes.
- JSON persistence when `BULWARK_STATE_DIR` is set.
- CLI provisioning for accounts, children, guardians, and pair codes.
- E2E gRPC coverage for guardian pairing, guardian-scoped alert delivery,
  decision authorization, and cross-server token/code isolation:
  `crates/bulwark-server/tests/e2e_accounts_pairing.rs`.
- Reusable app-workflow harness for future UI/account screens:
  `crates/bulwark-server/tests/support/workflow.rs` models guardian and child app
  actors over real gRPC, and
  `crates/bulwark-server/tests/e2e_app_workflow_harness.rs` covers happy-path
  enrollment, server switching, single-use pair codes, and duplicate-device
  rejection.

Missing:

- Enrollment UI for Windows/macOS/iOS child shells.
- Child-side stable device-id provisioning across Windows/macOS/iOS.
- Automatic stop/restart of local filtering when the active parent server
  changes.
- Region migration flow. Moving a family between London, US, and self-hosted
  should be explicit export/import or re-enrollment, not silent token reuse.

## UI Framework Direction

Both apps (`apps/parent`, `apps/child`) ship on **Dioxus 0.8.0-alpha.0** today.
Dioxus Native/Blitz remains the route to a shared native-rendered UI across
desktop/mobile without a webview, so the account/enrollment views stay small
pure-RSX components that can move from desktop to native/mobile as the 0.8
runtime stabilises.

Planned UI screens:

- Guardian login/create-account.
- Server chooser with per-server session state.
- Child list.
- Add child / create pair code.
- Child enrollment / redeem pair code.
- Protection status and coverage.
