# PH Staff operators console (`apps/staff`)

Internal Dioxus **desktop** console for Predator Hunters staff — fleet/region
health, guardian-account support, the NCMEC safety-report workflow, and the
tamper-evident staff audit log. This is **Increment 5** of
[`docs/design/staff-management-system.md`](../../docs/design/staff-management-system.md).

**Separate from PH Bulwark Manager by design** — different binary, account system,
token namespace, and gRPC service — so no staff RPC client or role gate ever ships
inside a guardian's phone app.

## Content-free by construction

Every value shown is a count / gauge / id / hash / timestamp — never child
content, names, locations, alert payloads, or media (none exists; CSAM is
detect/block/report — never store). See the design doc §2 + §7.

## Run (desktop)

```
cargo run        # from apps/staff (Win/macOS/Linux); or `dx serve` for hot reload
```

It speaks the `StaffAdmin` gRPC service, which the server exposes **only** when
started with `BULWARK_STAFF=1`.

## Configuration (env)

| Var | Default | Purpose |
|---|---|---|
| `BULWARK_STAFF_ENDPOINT` | `https://api.predatorhunters.co.uk:8443` | gateway to dial |
| `BULWARK_CLUSTER_CA` | unset → public roots | pin a private-CA PEM (self-hosted) |
| `BULWARK_STAFF_TOKEN` | unset | ops/dev override for a saved session token |

The session token + role persist under a SEPARATE `BulwarkStaff` config dir, never
mixed with the guardian Manager's `Bulwark` dir (token-namespace isolation).

## Screens

- **Login** — email + password + mandatory TOTP (`StaffLogin`).
- **Fleet health** — region gauges + per-node `HealthStatus` (`ListRegions` / `GetFleetHealth`).
- **Guardian support** (SUPPORT/ADMIN) — look up / email-reset / unlock by email.
- **Safety queue** (SAFETY_OFFICER/ADMIN) — the NCMEC case list + validated workflow transitions.
- **Audit log** (ADMIN) — the tamper-evident staff hash chain (`chain_ok` re-verified each read).

Tabs are role-gated client-side; the **server is the authority** (RBAC enforced per RPC).

## Desktop vs web

Built **desktop** (mirrors `apps/parent`: tonic over TLS). The design notes a
"web-first" intent; a wasm/grpc-web build would need a server-side `tonic-web`
layer that Increment 5 does not spec, so desktop is the buildable/testable path
today. A web variant can follow.

## Follow-ups

TOTP-secret encryption at rest; mTLS-bound staff sessions; token-expiry →
auto sign-out; E2E tests (with the web variant); CI packaging for the FOSS channels.
