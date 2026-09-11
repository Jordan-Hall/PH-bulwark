# Remote VPN authentication contract

Remote VPN is a distinct product mode from Local VPN.

## Modes

| Mode | Device responsibility | Region responsibility |
|---|---|---|
| Local VPN | capture, TLS inspection, analysis, policy, enforcement | control plane / optional heavy analysis |
| Remote VPN | Android VpnService + WireGuard encryption only | TLS inspection, analysis, policy, enforcement, NAT/exit |

The guardian is the authority for mode selection through `ChildConfig.filter_location`.
The child never silently changes Local ↔ Remote as a recovery mechanism.

## Remote VPN authentication

Remote VPN deliberately separates long-lived enrollment from short-lived tunnel access.

1. Pairing mints the device's long-lived `device_token`.
2. The guardian explicitly sets `filtering_enabled=true` and `FILTER_ON_SERVER` for that device.
3. The device creates/persists its own WireGuard private key in app-private storage and sends only the public key.
4. `WgProvision.RegisterWgPeer` accepts the pairing credential only for bootstrap.
5. The region checks the durable guardian config before granting access.
6. The region returns a short-lived HMAC-SHA256 session token in `x-bulwark-vpn-session` metadata.
7. The token is bound to `device_id`, SHA-256 of the exact WireGuard public key, expiry and random nonce.
8. Renewal sends the short-lived session token in metadata and does not resend the long-lived device token.
9. Every successful renewal rotates the session token and advances the peer lease expiry.
10. Guardian revocation, auth failure, loss of server filter readiness, or lease expiry stops the Remote VPN. There is no unfiltered fallback.

The region stores no raw VPN session token. It stores only the desired WireGuard peer, public key and expiry. Session validity is cryptographically verified from the signed token.

## Server configuration

Required before Remote VPN can issue a grant:

- `BULWARK_STATE_DIR` with the durable `child_config.json` guardian authority.
- `BULWARK_WG_SERVER_PUBLIC_KEY` with the region WireGuard public key.
- `BULWARK_WG_ENDPOINT` with the region UDP endpoint.
- `BULWARK_WG_FILTER_ACTIVE=true` only after the region filtering data path is actually active.
- `BULWARK_WG_INSPECTION_CA_PEM` or `<BULWARK_STATE_DIR>/wg_inspection_ca.pem` with the region inspection root public certificate.
- `BULWARK_REMOTE_VPN_SESSION_SECRET` containing at least 32 bytes of high-entropy secret material. Store it in the deployment secret manager, never in source control.

Optional:

- `BULWARK_REMOTE_VPN_SESSION_TTL_SECS` controls lease lifetime and is bounded server-side.
- `BULWARK_WG_KEEPALIVE_SECS` controls WireGuard keepalive.

## Live revocation

`wg_peers.json` now carries `expires_ts`. The root-only `wg-lease-reconcile.sh` service runs every 15 seconds, removes expired peers from live WireGuard, repairs address drift, and applies only currently leased peers.

Install it with:

```sh
sudo deploy/wireguard/install-remote-vpn-auth.sh
```

The data plane therefore requires both:

- possession of the enrolled device's WireGuard private key; and
- an unexpired server-issued lease that keeps that peer present in live WireGuard state.

A copied stale key is insufficient after lease expiry/revocation.

## CA trust

Remote VPN moves TLS inspection to the region but does not remove Android's trust requirement. The authenticated provisioning response includes only the region inspection **public** root CA. A managed Device Owner installs it into the system trust store before the Remote VPN TUN starts. The region CA private key never reaches the child.

Certificate-pinned/E2E applications remain outside transparent TLS interception in either VPN mode and require the complementary rendered-content/accessibility layer.
