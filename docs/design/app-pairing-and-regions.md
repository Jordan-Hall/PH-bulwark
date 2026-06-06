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
  - Windows: `aegis_proxy` today; transparent VPN path is still fail-closed while
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
- Self-hosted: user enters `http(s)://host:port` for their own `aegis-server`.

Current parent app state:

- `server.txt` stores the active server id; legacy raw self-hosted URLs still
  resolve and are surfaced as saved self-hosted entries.
- `servers.json` stores named self-hosted endpoints, merged with the built-in
  UK/London and US cloud choices.
- `cluster_endpoint()` resolves the saved choice and passes it to the spawned
  child filter through `AEGIS_CLUSTER_ENDPOINT`.
- Guardian sessions are endpoint-scoped under
  `sessions/<server_hash>/guardian_token.txt`, so a London token is not silently
  reused against US or self-hosted servers.
- A server-specific pinned CA can be placed at
  `sessions/<server_hash>/cluster_ca.pem`; `AEGIS_CLUSTER_CA` still wins as the
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
- `device_id` must be unique. Reuse is rejected because it could route one
  device into two families' scopes.
- Guardian review streams and decisions require a valid guardian session token in
  accounts mode.
- A guardian can see or approve only children they are assigned to.

## Self-Hosted Server

A self-hosted family runs the same `aegis-server` binary:

```text
AEGIS_ACCOUNTS=1
AEGIS_STATE_DIR=/var/lib/aegis
AEGIS_BIND=0.0.0.0:8443
aegis-server --role all-in-one
```

For production self-hosting:

- Prefer TLS and set `AEGIS_CLUSTER_CA` in the guardian app if using a private CA.
- Keep `AEGIS_STATE_DIR` durable, backed up, and private.
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
- JSON persistence when `AEGIS_STATE_DIR` is set.
- CLI provisioning for accounts, children, guardians, and pair codes.
- E2E gRPC coverage for guardian pairing, guardian-scoped alert delivery,
  decision authorization, and cross-server token/code isolation:
  `crates/aegis-server/tests/e2e_accounts_pairing.rs`.
- Reusable app-workflow harness for future UI/account screens:
  `crates/aegis-server/tests/support/workflow.rs` models guardian and child app
  actors over real gRPC, and
  `crates/aegis-server/tests/e2e_app_workflow_harness.rs` covers happy-path
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

The parent app is currently a Dioxus desktop app pinned to the 0.6 line. Dioxus
0.7 is the current published line, and Dioxus Native/Blitz is the route to a
shared native-rendered UI across desktop/mobile without a webview. Dioxus 0.8 is
still a future migration target, so the near-term implementation should keep the
account/enrollment views as small pure-RSX components that can move from desktop
to native/mobile once the runtime is stable enough for our app.

Planned UI screens:

- Guardian login/create-account.
- Server chooser with per-server session state.
- Child list.
- Add child / create pair code.
- Child enrollment / redeem pair code.
- Protection status and coverage.
