# Accounts + per-child guardians

How Aegis knows *which* parent to alert. Implemented in `aegis-proto` (the
`Accounts` service) and `aegis-server/src/accounts.rs`; the same store scopes the
guardian review stream.

## Model

- **Parent account** — email + password. The password is **never stored**: only a
  PBKDF2-HMAC-SHA256 hash (`ring`), 100k iterations, per-account 16-byte random
  salt, verified in constant time. `Login` mints an opaque random session token.
- **Child** — belongs to a family, linked to a supervised `device_id`. Created via
  `AddChild` (the caller becomes its first guardian).
- **Guardian assignment** — `AssignGuardian` adds another account as a guardian of
  a child (caller must already guard that child).

## Alert routing (the point)

`AlertEvent` carries `child_id` + `family_id` (and always `device_id`).
`Review.StreamPendingReviews` authenticates the guardian by session token
(`DeviceFilter.token` or `authorization: Bearer …` metadata) and delivers an alert
**only if** its `child_id` — or the `device_id` of one of the guardian's assigned
children — is in that guardian's scope. An unknown token is rejected, not leaked.

A child's alerts therefore reach **only that child's assigned guardian(s)**, never
other families or unassigned accounts.

## RPCs

`CreateAccount`, `Login`, `AddChild`, `AssignGuardian`, `ListChildren`.

## Child app

The child-side app is **filter + enrollment only** — no parent/review UI, no
device-control surface. Enrollment links the device to a child record so alerts
route to the right guardians.

## Pairing

The server supports both direct provisioning and app-driven pairing:

- Direct provisioning: `AddChild(token, child_name, device_id)`.
- App-driven pairing:
  1. Guardian logs in and calls `CreatePairCode(token, child_name)`.
  2. Child app calls `RedeemPairCode(code, device_id)`.
  3. The server creates the child, links the stable device id, assigns the
     minting guardian, and returns `child_id` + `family_id`.

Pair codes are short-lived and single-use. Redemption is unauthenticated because
the code is the credential.

## Server Choice

Accounts and tokens are scoped to one backend: UK/London cloud, US cloud, or a
self-hosted server. A token from one backend must not be reused on another. See
[`app-pairing-and-regions.md`](app-pairing-and-regions.md) for the region and
self-hosting UX plan.

## Status / SEAMs

State is persisted as JSON when `AEGIS_STATE_DIR` is configured; otherwise it is
in-memory for dev/single-home runs. Deliberately **no** `aegis-store`/rusqlite
dependency here (it fails to build on the Windows host, os error 4551).
