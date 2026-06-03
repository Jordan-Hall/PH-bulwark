# Runtime modes — Proxy vs VPN

Aegis filters a device's traffic in one of two desktop modes. Both decrypt
HTTPS with the **per-install root CA** (generated on first run, key wrapped by the
OS keystore, never shipped) and run the same classification pipeline; they differ
only in how traffic reaches the filter.

## 1. Explicit Proxy — `aegis_proxy` (no admin)

- A `hudsucker` MITM proxy on `127.0.0.1:8080`.
- The per-user **system proxy** (Windows `Internet Settings`, HKCU — no admin) is
  pointed at it. Browsers + apps that honour the system proxy are filtered.
- Fallback for when elevation isn't available. Apps that ignore the system proxy
  (or use their own cert store, e.g. Firefox/Zen) need extra config and are the
  documented gap this mode can't fully close.

## 2. Transparent VPN — `aegis_vpn` (admin)

- A layer-3 **TUN** captures *all* traffic; `tun2proxy` (smoltcp userspace
  netstack) redirects captured **TCP → the local MITM proxy**, NATs other UDP
  out, and **downgrades QUIC/UDP-443** so HTTP/3 can't bypass the TCP MITM.
- No per-app/proxy settings — every app is covered.
- `setup(true)` installs the default route and **restores host routing on
  teardown** (no-blackhole contract).
- Requires **Administrator/root** (TUN adapter + default route). `aegis_vpn`
  self-checks elevation and exits with the exact relaunch command if not elevated.

### Per-platform VPN mechanism

| Platform        | Mechanism                                   |
|-----------------|---------------------------------------------|
| Windows         | `tun2proxy` + **wintun** (WireGuard-signed) |
| Linux           | `tun2proxy` + `/dev/net/tun`                |
| macOS           | `tun2proxy` + utun                          |
| Android         | native **VpnService** (not tun2proxy)       |
| iOS             | native **NetworkExtension** (not tun2proxy) |

Desktop shares one code path (`aegis-net::vpn`); mobile uses the OS-mandated
native VPN APIs in `platform/android` + `platform/apple`.

## Shared requirements

- **CA trust** — HTTPS inspection needs the per-install root trusted once
  (`certutil -addstore -user Root …` on Windows; no admin). TUN capture does not
  change this.
- **Code signing (release blocker)** — unsigned fresh builds are blocked by
  Windows **Smart App Control** (os error 4551). Release binaries must be signed;
  `wintun.dll` is already WireGuard-signed.
