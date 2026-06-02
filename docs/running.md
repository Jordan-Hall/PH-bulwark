# Aegis — Build, Run & Setup Guide

> ⚠️ The tree is **not compile-verified yet**. Do the integration pass in
> [`integration-todo.md`](integration-todo.md) alongside the first `cargo build`.
> This guide is the target operating procedure once it builds.

## 1. Prerequisites

| Need | Why | Install |
|---|---|---|
| **Rust stable** (≥ 1.79) + cargo | build everything | https://rustup.rs |
| **Admin / elevation** | open the TUN device + install the per-install root CA into the trust store | Windows: run elevated (one UAC at setup) |
| **ffmpeg** binary | `aegis-video` (only with `--features ffmpeg`) | Windows: `winget install Gyan.FFmpeg`; Linux: distro pkg |
| **Postgres** | only for a **multi-node** cluster (single-node uses SQLite) | any 14+ |
| **Model artifacts** | `onnx`/`classifier` features (NSFW image/audio, grooming text) | download + SHA-256 pin (see §6) |
| `cargo-deny` | license/advisory gate | `cargo install cargo-deny` |

Dev tooling: `cargo install cargo-deny`; `rustup component add clippy rustfmt`.

## 2. First build (the integration pass)

Because the crates were written in parallel against the contract and never compiled,
expect to fix the items in [`integration-todo.md`](integration-todo.md) here:

```bash
cargo build --workspace 2>&1 | tee build.log     # fix fallout iteratively
cargo clippy --workspace -- -D warnings
cargo test  --workspace
cargo deny check                                 # licenses + advisories + bans
```

Likely first fixes (all catalogued in integration-todo): unify the per-crate `Analyzer`
trait into `aegis-core`; confirm `tonic` generated server-trait associated-type names
(`AnalyzeStreamStream`, `WatchHealthStream`); confirm a few cross-crate constructors
(`aegis_store::SqliteStore::open_in_memory`, `aegis_policy::AgeProfile::default`).

## 3. Feature flags (all OFF by default)

| Feature | Crate | Effect |
|---|---|---|
| `classifier` | `aegis-text` | small ONNX text classifier backs up the rule engine |
| `onnx` | `aegis-vision`, `aegis-audio` | real model inference via `ort` (else fails open) |
| `ffmpeg` | `aegis-video` | real decode/sample via ffmpeg-sidecar (else passes video) |
| `tesseract` / `winocr` | `aegis-agent` | OCR backends (else stub source) |
| `gossip` / `quorum` | `aegis-cluster` | multi-node SWIM (`foca`) / Postgres quorum |
| `llm-explain` | `aegis-ui` | guardian-initiated "explain thread" endpoint (opt-in only) |

A bare `cargo run` (no features) starts and wires the loop but the model analyzers
**fail open** (allow) and video isn't decoded — useful for exercising the control flow,
not for real filtering.

## 4. Run — single node (Windows-first)

Three processes (or fold client+server via `all-in-one`):

```bash
# 1) Backend (all services in one process)
AEGIS_BIND=127.0.0.1:8443  cargo run -p aegis-server -- --role all-in-one

# 2) Interception loop (ELEVATED — opens TUN, installs the CA on first run)
cargo run -p aegis-client

# 3) Dashboard
AEGIS_UI_BIND=127.0.0.1:8080  cargo run -p aegis-ui
# open http://127.0.0.1:8080  (/api/events, /api/coverage, /healthz)
```

Environment variables:

| Var | Used by | Meaning |
|---|---|---|
| `AEGIS_ROLE` | server | `lb` \| `worker` \| `all-in-one` |
| `AEGIS_BIND` | server | gRPC listen addr (default `127.0.0.1:8443`) |
| `AEGIS_UI_BIND` | ui | dashboard listen addr (default `127.0.0.1:8080`) |
| `AEGIS_CONFIG` | all | path to the TOML config (see §5) |
| `AEGIS_LOG` / `RUST_LOG` | all | tracing filter (e.g. `info`, `aegis_net=debug`) |
| `AEGIS_SMTP_USERNAME` / `AEGIS_SMTP_PASSWORD` | alert | SMTP creds (never put in the config file) |

## 5. Configuration

`aegis-core::Config` loads **defaults → TOML file (`$AEGIS_CONFIG`) → `AEGIS_` env**
(nested with `__`, e.g. `AEGIS_SMTP__HOST`). Example `aegis.toml`:

```toml
[smtp]
host = "smtp.example.com"
port = 587
from = "aegis@example.com"
recipients = ["guardian@example.com"]
# username/password come from AEGIS_SMTP_USERNAME / AEGIS_SMTP_PASSWORD only

[cluster]
endpoint = "https://127.0.0.1:8443"

[models]
dir = "./models"
# each model's SHA-256 is pinned in the checksum registry and verified on load

[policy]
# per-age-band thresholds live in aegis-policy's PolicyConfig (log/flag/block)
```

## 6. Models (only for `onnx` / `classifier`)

Place artifacts in `[models].dir` and pin their SHA-256 (rejected on mismatch).
Per [`research/model-research.md`](research/model-research.md):
- **NSFW image:** NudeNet 320n/640m (MIT) or Falconsai ViT (Apache-2.0), ONNX/INT8.
- **Explicit audio:** YAMNet/PANNs backbone + a **head you must train** (no off-the-shelf).
- **Grooming text:** rule engine ships built-in; the optional classifier is a DistilBERT/
  MiniLM you **fine-tune** on PAN2012 + PJ corpora.

## 7. Security setup (the per-install CA)

On first `aegis-client` run (elevated), `aegis-net`:
1. **generates a unique per-install root CA** (`rcgen`) — never shared/baked-in;
2. wraps the private key with the OS keystore (**DPAPI** on Windows; non-exportable);
3. installs the public root into the **current-user Trusted Root** store (one UAC prompt).

**Uninstall must remove the root** (an orphaned root is a latent MITM backdoor): call the
uninstall path (`NetInterceptor::set_remove_root_on_shutdown(true)` then `shutdown`).
Inspect the CA fingerprint in the dashboard for verification.

## 8. Multi-node cluster (optional)

Build with `--features gossip,quorum`. Run one `--role lb` + N `--role worker`, give workers
the LB as a seed, point all at the same Postgres (`quorum` = split-brain protection: a node
that loses its lease stops accepting work). Every link is **mTLS** with per-node certs.

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Some apps stop connecting | QUIC blocked (downgrade) or cert-pinned app rejecting the MITM cert | allowlist the app's QUIC, or accept it routes to the on-device OCR path; check the coverage matrix |
| A messaging app shows nothing filtered | it's E2E/pinned — network can't read it | enable `aegis-agent` (OCR) for that app |
| `aegis-video` passes everything | built without `--features ffmpeg`, or ffmpeg not on PATH | install ffmpeg + rebuild with the feature |
| NSFW never triggers | built without `--features onnx` or no model artifact | add the model + SHA-256 pin + rebuild |
| Browser warns the CA isn't trusted | CA not installed / wrong store | re-run setup elevated; confirm install |
```
