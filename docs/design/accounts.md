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

## Status / SEAMs

State is in-memory this wave (`Arc<Mutex<…>>`). `// SEAM:` markers show where
durable, audited storage plugs in. Deliberately **no** `aegis-store`/rusqlite
dependency (it fails to build on the Windows host, os error 4551).
