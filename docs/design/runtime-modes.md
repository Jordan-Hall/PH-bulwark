# Runtime modes — Proxy vs VPN

Bulwark filters a device's traffic in one of two desktop modes. Both decrypt
HTTPS with the **per-install root CA** (generated on first run, key wrapped by the
OS keystore, never shipped) and run the same classification pipeline; they differ
only in how traffic reaches the filter.

## 1. Explicit Proxy — `bulwark_proxy` (no admin)

- A `hudsucker` TLS-inspecting proxy on `127.0.0.1:8080`.
- The per-user **system proxy** (Windows `Internet Settings`, HKCU — no admin) is
  pointed at it. Browsers + apps that honour the system proxy are filtered.
- Fallback for when elevation isn't available. Apps that ignore the system proxy
  (or use their own cert store, e.g. Firefox/Zen) need extra config and are the
  documented gap this mode can't fully close.

## 2. Transparent VPN — `bulwark_vpn` (admin)

- A layer-3 **TUN** captures *all* traffic; the in-tree **smoltcp** userspace
  netstack pump (`bulwark-net::vpn::netstack` — the GPL `tun2proxy` crate was
  removed for licensing) terminates captured **TCP → CONNECTs to the local
  TLS-inspecting proxy**, forwards DNS, and **downgrades QUIC/UDP-443** so HTTP/3
  can't bypass the TCP TLS inspection.
- No per-app/proxy settings — every app is covered *once the pump is enabled on
  that platform* (table below).
- Status (honest): the fd-driven pump is implemented + host-tested for
  **unix/Android**; on-device validation is pending. **Desktop host routing is
  disabled pending that validation**, so desktop transparent mode **fails
  closed** (it never silently passes traffic) — explicit proxy mode is the
  shipping desktop path today.
- Routing contract: `Tun::install_routing` adds the redirect after `up()`;
  `Tun::teardown_routing` reverses exactly what was added and is idempotent
  (runs on the crash/`ExecStop` path too — no-blackhole contract).
- Requires **Administrator/root** (TUN adapter + default route). `bulwark_vpn`
  self-checks elevation and exits with the exact relaunch command if not elevated.

### Per-platform VPN mechanism

| Platform | Mechanism | Status |
|----------|-----------|--------|
| Windows  | smoltcp pump + **wintun** (WireGuard-signed) | pump not enabled — **fails closed**; use explicit proxy mode |
| Linux    | smoltcp pump + `/dev/net/tun` | pump implemented (host-tested); host routing disabled pending device validation — fails closed |
| macOS    | smoltcp pump + utun | same as Linux |
| Android  | native **VpnService** fd → the same smoltcp pump | capture pump wired to `startVpn`; classification consumer + on-device validation pending |
| iOS      | native **NetworkExtension** (no TUN pump) | skeleton in `platform/apple`, unvalidated |

Desktop and Android share one pump (`bulwark-net::vpn::netstack`); mobile uses the
OS-mandated native VPN APIs in `platform/android` + `platform/apple` to obtain the
device fd / filter hooks.

## Shared requirements

- **CA trust** — HTTPS inspection needs the per-install root trusted once
  (`certutil -addstore -user Root …` on Windows; no admin). TUN capture does not
  change this.
- **Code signing (release blocker)** — unsigned fresh builds are blocked by
  Windows **Smart App Control** (os error 4551). Release binaries must be signed;
  `wintun.dll` is already WireGuard-signed.
