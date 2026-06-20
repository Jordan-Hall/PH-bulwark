# PH Staff Management System (`StaffAdmin`)

The **internal operators console** for Predator Hunters staff — the people who run
the service (fleet operations, guardian-account support, the legal safety-report
workflow). It is NOT guardian-facing and NOT child-facing: a completely separate
account system, token namespace, gRPC service, and (eventually) app from
PH Bulwark / PH Bulwark Manager.

Design rule that shapes everything below: **guardian privacy from staff is a
product feature**. Staff operate the *service*, never the *families*. Every staff
surface is content-free by message shape, mirroring the invariants already
enforced in [`bulwark.proto`](../../crates/bulwark-proto/proto/bulwark.proto)
(hash-only `Evidence`, redacted `AlertEvent`, content-free `ChildConfig`).

Status: **Increments 1–4 SHIPPED** (#133 2026-06-13, #184/#188/#189 2026-06-14):
proto `StaffAdmin` + `crates/bulwark-server/src/staff.rs` + `safety_cases.rs` + live
fleet data + opt-in mount behind `BULWARK_STAFF=1`. **Increment 5 (the `apps/staff`
console) BUILT 2026-06-15** as a **desktop** Dioxus app (branch `feat/staff-console`):
login + TOTP, fleet/region health with per-node `HealthStatus`, guardian support,
the NCMEC safety queue with validated transitions, the audit log, and role-gated
tabs — all over the shipped `StaffAdmin` gRPC, `cargo check` clean. Built desktop
(mirrors `apps/parent`/tonic) rather than web because a wasm/grpc-web build needs a
server `tonic-web` layer not specced here; a web variant + E2E tests are follow-ups.

---

## 1. Scope — what PH staff legitimately need

| Area | What it is | Content exposure |
|---|---|---|
| **Fleet / region health** | Per-region dashboard: box up/down, deploy version, TLS-cert expiry, WireGuard peer **counts**, enrolled-device **counts**, node `HealthStatus` (queue depth, latency, load) via the existing `ClusterControl` snapshots. | None — gauges, versions, timestamps. |
| **Guardian-account support** | "I'm locked out / lost my recovery code" calls: trigger the existing emailed reset (`reset_mailer` sends it — staff never see the code), clear a rate-limit lockout, view account **metadata** (account id, created/last-login timestamps, lockout state, child/device *counts*). | Metadata only. NEVER alerts, children's names, configs' history, or any content. |
| **Abuse / safety-report queue** | The NCMEC escalation workflow for `CSAM_SUSPECTED` events: case id, content **sha256/pHash**, category, timestamps, jurisdiction (region granularity only), workflow state, NCMEC report reference. | Hashes + ids + timestamps ONLY. There is **no media to show** (report-never-store), so the queue manages *legal workflow state*, not content review. |
| **Region / capacity management** | Mark a region accepting/not-accepting new pairings; drain a region (proxies `ClusterControl.Drain`); see capacity headroom. | None. |
| **Staff audit log** | Every staff action — logins, creations, support actions, case transitions, even dashboard reads — appended to a tamper-evident **sha256 hash chain** (same construction as `bulwark-store::hashchain`). Queryable in-console; verified on every load and query. | Content-free: actor id, role, action, target id, timestamp, chain hash. |

## 2. What staff must NEVER access (hard section)

Staff have **no path** — not "no permission", no *path* — to: child content of any
kind (messages, transcripts, browsing, OCR text, media); alert payloads
(snippets, safe-thumbnails, `Evidence`, `AlertEvent` streams — those exist for the
child's *guardians* only); grooming material (raw or redacted) or the dataset;
CSAM in any form (none is stored — the queue carries hashes + workflow state
only); child location / IP (`FILTER_ON_SERVER` anonymises the child's IP — staff
see peer *counts*, never identities); live traffic (no packet/flow/log viewer,
ever); guardian credentials (KDF-hashed; reset codes go to the guardian's inbox).

Enforced **by construction**, not by role flag:

1. **Message shape** — no `StaffAdmin` message may carry `Evidence`, `AlertEvent`,
   `TextSpan`, `InlineMedia`, `SegmentChunk`, or any free-text content field. A PR
   adding such a field to `StaffAdmin` is a review-gate reject.
2. **Token namespace isolation** — content-bearing guardian RPCs resolve tokens
   against `AccountStore`; staff tokens live in `StaffStore` and simply do not
   exist there (and vice versa). A leaked staff token authorizes zero guardian
   RPCs; a leaked guardian token authorizes zero staff RPCs. (Test:
   `guardian_and_staff_token_namespaces_are_isolated`.)
3. **Server-side reality check** — routine operations move to content-free RPCs;
   shell access (SSM) becomes break-glass only, separately logged.

## 3. AuthN / AuthZ (Increment 1 — SHIPPED #133, 2026-06-13)

- **Separate `StaffStore`** (`crates/bulwark-server/src/staff.rs`), persisted to
  `staff.json` + `staff_audit.json` under `BULWARK_STATE_DIR` — never mixed into
  `accounts.json`. Same `JsonFile` atomic-write pattern (0700 dir, 0600 files).
- **Argon2id** PHC at rest (the guardian helpers, now `pub(crate)`: `argon2_hash`/
  `argon2_verify`), per-email sign-in throttle (same window/limits), sessions
  keyed + persisted as **sha256 digests only** (raw bearer token never stored).
- **Mandatory TOTP 2FA** (RFC 6238: SHA-1, 30s step, 6 digits, ±1-step skew) on
  every staff login. No new dependency: `ring::hmac` + `data-encoding` (both
  in-tree). Secret generated server-side, shown **exactly once** at creation
  (base32 + `otpauth://` URI), replay within a step refused (last accepted
  counter remembered). Honest note: unlike a password, a TOTP secret must be
  stored retrievable; it lives only in the 0600 state file — encrypting it under
  an operator key is a listed follow-up.
- **Bootstrap-gated first account**: `CreateStaff` works with
  `BULWARK_STAFF_BOOTSTRAP_CODE` (sha256-compared) **only while zero staff
  accounts exist**, and forces role ADMIN. The moment one exists the bootstrap
  path is dead forever (`CreateStaff` then requires a live ADMIN session).
- **RBAC roles** (one per account): `SUPPORT` (guardian-account support + read
  region list), `SAFETY_OFFICER` (safety-report queue + read region list),
  `OPERATOR` (fleet health + region/capacity), `ADMIN` (everything incl.
  `CreateStaff` + audit query).
- **Short session TTL**: 2h default (`BULWARK_STAFF_SESSION_TTL_SECS`), vs the
  guardians' 12h — staff sessions are higher-blast-radius and desk-bound.
- **Every action audited** (hash chain). Future hardening: bind staff sessions to
  mTLS client certs; per-IP throttles.

## 4. Surface

**Server**: a `StaffAdmin` gRPC service in `bulwark.proto`, mounted by the same
`bulwark-server` behind the same TLS listener — but **only when `BULWARK_STAFF=1`**
(default off: a guardian-facing node exposes no staff surface at all). Same
plaintext refusal as accounts mode (staff passwords + TOTP codes must never cross
the network in clear).

**UI (Increment 5)**: a **separate small Dioxus app, `apps/staff`** (web-first) —
NOT a tab in PH Bulwark Manager. Blast radius (Manager ships to guardians' phones
via public stores; a staff area inside it puts staff RPC clients + role gates into
every family's binary), different release train, and cheap code-sharing (copy the
`apps/parent` skeleton) all argue for separation.

## 5. Phased plan

1. **Increment 1 (SHIPPED #133, 2026-06-13)** — proto `StaffAdmin` (CreateStaff
   bootstrap-gated, StaffLogin with TOTP, ListRegions/GetFleetHealth content-free
   static, QueryStaffAudit) + `staff.rs` (store, TOTP, RBAC, sessions, hash-chain
   audit, 12 in-module tests) + opt-in mount (`BULWARK_STAFF=1`).
2. **Increment 2 (SHIPPED #184, 2026-06-14)** — guardian support:
   `TriggerGuardianReset` (reuses `AccountStore::request_password_reset` +
   `ResetMailer`; staff never see the code), `UnlockGuardianAccount`,
   `GetGuardianMeta` (metadata + counts only). SUPPORT + ADMIN.
3. **Increment 3 (SHIPPED #188, 2026-06-14)** — safety-report queue: a `SafetyCase`
   store (`crates/bulwark-server/src/safety_cases.rs`, in-memory + optional
   `safety_cases.json` persistence) + the NCMEC workflow state machine behind
   `OpenSafetyCase` / `ListSafetyCases` / `TransitionSafetyCase` / `GetSafetyCase`,
   SAFETY_OFFICER+ADMIN-gated (`SAFETY_ROLES`), every transition appended to the
   staff hash-chain audit. Forward path
   OPENED→UNDER_REVIEW→REPORTED_NCMEC→LAW_ENFORCEMENT→CLOSED, **plus a direct
   `REPORTED_NCMEC→CLOSED` edge** (many NCMEC reports are triaged and resolved
   without a separate law-enforcement handoff — forcing the LE state through would
   misrecord the legal workflow); REJECTED is reachable from OPENED or UNDER_REVIEW;
   CLOSED and REJECTED are terminal. Cases carry content sha256 + pHash + category +
   region + workflow state + an opaque NCMEC reference ONLY — no media, names, or
   message text.
4. **Increment 4 (SHIPPED #189, 2026-06-14)** — real fleet data: the LOCAL region's
   `RegionInfo`/`FleetHealth` now joins this node's live `ClusterControl.Health`
   snapshot (`probed=true`, `healthy` from `accepting_work`, per-node
   `HealthStatus` in `FleetHealth.nodes` — queue depth / latency / load, already
   content-free), the enrolled WG peer **count** (`WgPeerStore::peer_count`), the
   enrolled-device **count** (`AccountStore::staff_enrolled_device_count`), and
   the TLS-cert expiry from `BULWARK_TLS_CERT_EXPIRY_TS` (env, no x509 dep).
   **Single-region honesty caveat:** no cross-region gossip on the single-box
   deploy, so any region OTHER than the one this node serves (`BULWARK_REGION`)
   stays honestly `probed=false` rather than faking a green light. No proto change
   (the fields already existed). Region accept/drain is deferred to a follow-up
   (it proxies `ClusterControl.Drain`, a mutating capacity action).
5. **Increment 5 — `apps/staff` Dioxus console (BUILT 2026-06-15, `feat/staff-console`).**
   Desktop (Win/macOS/Linux) Dioxus + tonic, mirroring `apps/parent`: login + TOTP →
   short-TTL session; fleet/region health + per-node `HealthStatus`; guardian support
   (lookup/reset/unlock by email); the NCMEC safety queue with the validated
   transition controls; the tamper-evident audit log; role-gated tabs (persisted
   role). `cargo check` clean, content-free throughout. **Remaining/follow-ups:**
   a web/grpc-web variant (needs a server `tonic-web` layer) + Midscene/E2E tests;
   token-expiry → auto sign-out; TOTP-secret encryption at rest; mTLS-bound staff
   sessions; audit-file sealing; CI packaging for the FOSS channels.

## 6. Risks (honest)

| Risk | Mitigation |
|---|---|
| TOTP secret stored retrievable | 0600/0700 perms now; keystore/env-key encryption follow-up; shown once. |
| Bootstrap code mishandled | Digest-compared; only works while the store is empty — auto-dead after first admin; remove the env var after use. |
| Audit file rewrite is O(n) per action; reads audited → growth | Modest dashboard poll cadence; sealing/rotation in increment 5. |
| `bulwark-server` is CI-only on this host | Pattern-mirrors `accounts.rs`; in-module tests run on CI + the Windows host (no rusqlite). |
| Insider with shell access bypasses the console | The console exists to make shell access unnecessary day-to-day; SSM stays break-glass + separately logged. |

## 7. Invariants checklist (review gate for every StaffAdmin PR)

- [ ] No content-capable types (`Evidence`, `AlertEvent`, `TextSpan`,
      `InlineMedia`, `SegmentChunk`) in any `StaffAdmin` message.
- [ ] No RPC returns child names, locations, addresses, or per-peer identities.
- [ ] CSAM: hashes + workflow state only — never media (none exists to serve).
- [ ] Staff tokens resolve only in `StaffStore`; guardian tokens only in `AccountStore`.
- [ ] Every new staff RPC appends an audit entry.
- [ ] Secrets at rest: Argon2id PHC / sha256 digests only (the TOTP secret is the
      sole documented exception, file-permission-guarded).
