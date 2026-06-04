# Cross-platform transparent-VPN data path — implementation plan

Status: **planned, not implemented.** This is the roadmap to eliminate the
`todo!()` stubs in `crates/aegis-net/src/tun/stub.rs` and make the transparent VPN
work on Linux, macOS, and Android (Windows already works via `tun/windows.rs`).

> **Why it isn't "just delete the stubs".** Tracing the data path shows a missing
> bridge: the removed (GPL) `tun2proxy` crate owned a **smoltcp L3↔proxy netstack**
> that turned raw TUN IP packets into TCP sessions for the local MITM proxy. With it
> gone, `vpn.rs::run_vpn` **fails closed**. So the work is two layers: (1) per-platform
> `TunDevice` impls, and (2) rebuilding that shared netstack bridge. A brought-up TUN
> with a default route but **no** bridge blackholes the device — so the bridge must
> land first and be spiked for feasibility.
>
> **This must be built AND tested on real Linux/macOS/Android (root / devices / live
> network).** It cannot be verified in CI or an offline sandbox. For a child-safety
> filter, shipping untested VPN-data-path code that merely compiles is worse than the
> loud `todo!()` (silent non-filtering = an unprotected child). Today's working paths
> are **proxy mode (all OSes)** and the **Windows VPN**.

## Part 0 — shared layer first (everything depends on it)

**`tun/mod.rs` trait additions** (Windows inherits the no-op defaults — unchanged):
- `install_routing(&cfg)` / `teardown_routing()` — default no-op; Linux/macOS override (nftables / pf). Splits routing out of `up()` so teardown is independent + idempotent.
- `#[cfg(unix)] fn as_raw_fd(&self) -> Option<RawFd>` — reactor integration.

**New `vpn/netstack.rs`** (promote `vpn.rs` → `vpn/`): a `smoltcp` `Device` over `TunDevice::recv/send` that, per captured TCP SYN, opens a smoltcp socket and bridges its bytes to a `TcpStream` → the local hudsucker proxy (`127.0.0.1:8080`) via HTTP CONNECT (no proxy change needed). UDP NAT'd out; QUIC/443 not tunnelled (downgrade handled by `quic.rs`). Driven by `CancellationToken`. Add `smoltcp` to `aegis-net/Cargo.toml` (declared in the workspace, currently unused).
- `run_vpn` changes from "return error" → `open_tun → up → install_routing → run_netstack → (on cancel) teardown_routing → close`.
- **Highest risk / spike first:** the smoltcp↔proxy bridge is exactly what GPL `tun2proxy` did for free. Fallback: a minimal permissively-licensed TCP-only relay (parse SYN → synthesise CONNECT → splice).
- **Testable without a device:** segment→CONNECT translation, flow table, half-close, UDP NAT — unit-tested with an in-memory fake `TunDevice`; loopback integration with the real proxy. **Needs root:** attaching the OS default route.

## Part 1 — Linux (`tun/stub.rs` → real)
- `up`: `tun_rs::DeviceBuilder` (name/ipv4/mtu) → `build_sync`; store fd. `recv/send`: device read/write. `close`: drop + `teardown_routing`.
- `install_routing`: nftables TPROXY + fwmark → `ip rule`/`ip route` to the proxy port — **for v4 AND v6** (IPv6 must be duplicated or the LAN blackholes). Shell out via `Command` (reuse `quic.rs`'s helper). systemd unit gets `ExecStop=` teardown. Needs `CAP_NET_ADMIN`.
- Testable: the nft/ip **arg-list builders** as pure fns (like `quic.rs` tests). Needs root + a throwaway VM: real interface + TPROXY + verifying teardown restores connectivity.
- Size/risk: medium; the bridge (Part 0) dominates.

## Part 2 — macOS (same backend file, `cfg(macos)` arm)
- `up/recv/send` identical to Linux (tun-rs abstracts `utun`) **except** the kernel assigns `utunN` — read the real name back for the pf anchor.
- `install_routing`: `pf` via `pfctl` (rdr anchor → proxy port, v4+v6); `teardown_routing`: flush the anchor. LaunchDaemon plist instead of systemd.
- **Productisation gap (not a dev blocker):** App Store distribution needs a signed NetworkExtension; root + pfctl is enough for dev/test.
- Testable: pfctl arg builders (pure). Needs a real Mac + root (GitHub macOS runners likely can't).

## Part 3 — Android (largest, highest risk)
- The Kotlin side is **done**: `AegisVpnService.kt` calls `RustBridge.startVpn(fd, config)`; `RustBridge.kt` declares it; routing is declarative in Kotlin.
- aegis-android's `startVpn` currently boxes the fd **unused**. Make it real (Option A — reuse the shared netstack):
  - A `cfg(android)` `TunDevice` over the VpnService fd. **Fd ownership:** `dup()` the fd so Rust owns its copy (Kotlin's `ParcelFileDescriptor` keeps + closes the original) — avoids double-close.
  - Add `aegis-net` as a dep of `aegis-android`; enable the `vpn` mod on android; add `smoltcp` + `libc` to the android target block; reconcile `jni` 0.21 vs 0.22.
  - **`protect()` is the critical wire:** upstream sockets must be `protect()`-ed or they loop. Pass the `VpnService` instance into `startVpn` (new JNI param in `RustBridge.kt` + `AegisVpnService.kt` + `lib.rs`); hold a `GlobalRef` + `JavaVM`; call `service.protect(fd)` before each upstream connect.
  - `stopVpn`: cancel the token, join, drop (closes the dup'd fd).
- Honest coverage: only ~30–50% of Android-7+ app traffic is MITM-able; pinned/E2E apps go to the AccessibilityService OCR path (already implemented).
- Testable on host: fd read/write via `socketpair`; the netstack bridge; fd-dup logic. Needs JVM: the `protect()` callback. Needs a device + VPN consent: `establish()` + end-to-end.

## Sequencing
0 (trait hooks + smoltcp bridge — **spike feasibility first**) → 1 Linux (VM-testable) → 2 macOS (Linux + pf swap) → 3 Android (protect() JNI + aegis-net cross-compile). Each landed only after **real-device validation**, never on compile-only.

## Files
- `crates/aegis-net/src/tun/stub.rs` — replace all 8 `todo!()`s (Linux/macOS tun-rs + Android fd loop)
- `crates/aegis-net/src/tun/mod.rs` — trait: `install_routing`/`teardown_routing`/`as_raw_fd` (Windows inherits no-ops)
- `crates/aegis-net/src/vpn.rs` → `vpn/` + `vpn/netstack.rs` (smoltcp bridge; make `run_vpn` run it)
- `crates/aegis-net/Cargo.toml` — add `smoltcp` (desktop+android), reconcile `jni`, enable `vpn` on android
- `platform/android/rust/aegis-android/src/lib.rs` (+ Cargo.toml) — real `startVpn`/`stopVpn`, `protect()` JNI
- `platform/android/app/.../vpn/AegisVpnService.kt` + `core/RustBridge.kt` — add the `VpnService` arg for `protect()`
- `deploy/linux` + `deploy/macos` service units — `ExecStop`/teardown
</content>
