# Wave A — A3 Platform & Topology Feasibility

> Findings from research agent A3 (2026-06), cross-referenced with mitmproxy, Bark/Net Nanny,
> WireGuard, Zscaler/Forcepoint. Overall: **GO**, with spikes on the Tier-1 risks first.

## Verdict summary
| Item | Verdict | Risk |
|---|---|---|
| 1. Windows Wintun + MITM + per-install CA | **GO** | Medium — needs admin; CA key is crown jewel |
| 2. Linux home-gateway (TUN + nftables TPROXY) | **GO** | Medium — routing loops / systemd cleanup |
| 3. Android VpnService + AccessibilityService | **GO** | High — user-CA limit, Play Store/MASA, E2E only via OCR |
| 4. QUIC/HTTP3 downgrade (block UDP/443) | **GO** | Low — most apps fall back to TCP |
| 5. Cert-pinning detection + routing | **GO** | Medium — OCR fallback is lossy |
| 6. Clustered server (gRPC/mTLS/SWIM) | **GO** | High — split-brain, cert rotation, exfil surface |

## Key points per item
1. **Windows:** `wintun` ships pre-signed by WireGuard → no EV/WHCP needed unless we recompile it.
   Per-install CA via `rcgen`; private key in **DPAPI, ideally TPM**; install to Trusted Root via certutil/Win32.
   Admin + one UAC prompt at install (expected, like Bark/Net Nanny). ~5–10 ms/flow proxy overhead.
2. **Linux gateway:** `tun` + `hudsucker`; route LAN via **nftables TPROXY** + fwmark; run as systemd
   service with `CAP_NET_ADMIN`/`CAP_NET_BIND_SERVICE`. Must add `ExecStop` to tear down rules (else
   blackhole), and duplicate rules for **IPv6**. Test on a throwaway VM first.
3. **Android (the hard one):** `VpnService` is the only device-wide intercept. **Android 7+ apps ignore
   user CAs** unless they opt in → MITM works for maybe 30–50% of apps; pinned/E2E apps reject it.
   Commercial tools (Bark/mSpy/KidsGuard) **read plaintext via AccessibilityService + notification text
   AFTER the app decrypts** — they do NOT crack the wire. We do the same. AccessibilityService needs
   explicit user grant. Play Store **allows** parental-control VPNs but requires VPN disclosure, Data
   Safety declaration (no plaintext exfiltration), and a **MASA Level 2** assessment (~12 wks + fee).
4. **QUIC:** block UDP/443 → apps fall back to inspectable TCP/HTTP2 (~85–90%). Cost: 1–3 s first-conn
   delay; a few apps won't fall back → need a per-app allowlist + a "failed to connect" dashboard.
5. **Pinning:** discovered only on handshake failure → maintain a **per-app capability matrix** (MITM vs
   route-to-OCR). Recommend **fail-open + log** for parental control (block is too disruptive). OCR only
   sees on-screen/notification text — document the loss honestly.
6. **Cluster:** single binary, `--role lb|worker|all-in-one`. `foca` SWIM gossip; Postgres as quorum
   source-of-truth to avoid split-brain (stop accepting work if heartbeat lost). `tonic` + `tonic-health`
   + `ginepro` for LB. **Per-device client cert** (`rcgen`, key in DPAPI/Keystore/Keychain) → mTLS;
   worker↔worker mTLS via cluster CA. Stateless workers (no sticky routing → clean drain). Offload
   decision in `aegis-infer`: device caps + queue backpressure + RTT>100 ms → prefer local. Cluster sees
   plaintext analysis intermediates → in-memory only, audit logs, deploy on owned hardware.

## Spike priority (do Tier-1 first)
1. **Per-install CA key storage** (Windows DPAPI/TPM + Android Keystore) — showstopper if wrong.
2. **Android AccessibilityService capture** of a real chat app + Play Store/MASA path.
3. **QUIC downgrade** validation on real devices.
4. **2-node `foca` + `tonic` mTLS cluster** — gossip, health, graceful drain, partition behavior.
Tier-2 (parallel): `aegis-infer` latency/offload heuristic; pinning detection; Linux nftables+systemd.

## Unresolved → routed elsewhere
- Grooming model accuracy/bias on-device → A2 (train + eval).
- Live-video latency budget → video-pipeline phase spike.
- **Legal:** E2E plaintext capture (even via OCR) may hit wiretap / two-party-consent law → **B2 threat
  model + per-region legal review** before any deployment.
- Commercial Play Store viability (MASA cost/timeline) → B2 / product decision.
