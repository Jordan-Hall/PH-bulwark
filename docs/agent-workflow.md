# Bulwark — Agent Spawning & Build Workflow

The orchestrator (lead session) spawns agents in **waves**. Independent crate work runs in
**parallel git worktrees**; dependent work is sequenced. Every agent gets a charter
(scope, inputs, outputs, done-criteria) so hand-offs are contracts.

## Orchestration pattern

```
Wave A (read-only, parallel)  →  Wave B (design)  →  Wave C (build, parallel worktrees)
  research + feasibility           architecture +       proto/cluster first, then
                                   threat model         per-crate builders
                                        ↓                        ↓
                              Wave D (integration)  →  Wave E (review + verify + docs)
```

- Worktree isolation for every builder; background for long spikes/builds.
- Builders never start before their **interface contract** (Wave B + `bulwark-proto`) exists.
- One `/security-review` pass per phase + a final full review.

## Agent roster

| ID | subagent_type | Mode | Charter |
|---|---|---|---|
| **A1 Crate research** | Explore (very thorough) | read-only | Confirm crates + **OSS licenses** + maturity: TUN, `hudsucker`, `rustls`/`rcgen`, `ort`, `ffmpeg-sidecar`, `lettre`, `sqlx`/`rusqlite`, `axum`/`tauri`, **`tonic`/`prost` (gRPC), SWIM membership (`foca`/`chitchat`/alt), Postgres, mTLS** + `cargo-deny`/`audit`. Output: dep table + license red-flags + recommended set |
| **A2 Model research** | Explore (very thorough) | read-only | Pick **small dedicated** OSS models (minimal-AI steer): NSFW image, explicit-audio, grooming text classifier; **conventional OCR engines** (Tesseract/OS-native, NOT vision-LLMs); note the deterministic rule/lexicon approach for grooming; LLM only as optional escalation. License + size + quantization + device tier + eval datasets (PAN2012). Output: model registry + per-tier recommendation |
| **A3 Platform + topology** | Explore (very thorough) | read-only | Go/no-go for: Win Wintun+TLS inspection+CA-install; Linux gateway; Android VpnService+AccessibilityService (+Android-7 user-CA limit); QUIC downgrade; pinning behavior; **client⇄clustered-server gRPC/mTLS topology + role-based single binary + offload path**. Output: feasibility report w/ risks |
| **B1 Architect** | general-purpose | worktree | Per-crate design + **`bulwark-proto` gRPC/protobuf contracts** all builders code against; client/server/cluster boundaries; device-capability + offload interface. Output: `docs/design/*.md` + `bulwark-proto` definitions |
| **B2 Threat model** | general-purpose | worktree | Threat model + CA-key handling + sandboxing + mTLS/cluster trust + data/CSAM policy + legal/consent doc. Output: `docs/security/` |
| **C0 proto** | general-purpose | worktree | `bulwark-proto` finalized (tonic/prost) — gates all client/server builders |
| **C-cluster** | general-purpose | worktree | `bulwark-cluster` (membership/health/LB/work queue/shared state) — after C0 |
| **C-server** | general-purpose | worktree | `bulwark-server` (role: lb\|worker\|all-in-one, hosts analyzers) — after C0, C-cluster |
| **C-client** | general-purpose | worktree | `bulwark-client` (device orchestrator wiring net/agent/flow/infer) — after C0 |
| **C-net** | general-purpose | worktree | `bulwark-net` (TUN + TLS inspection + per-install CA) |
| **C-flow** | general-purpose | worktree | `bulwark-flow` (classify + buffer/delay) — after C-net |
| **C-vision** | general-purpose | worktree | `bulwark-vision` (small ONNX NSFW image/frame) |
| **C-audio** | general-purpose | worktree | `bulwark-audio` (small ONNX explicit-audio) |
| **C-video** | general-purpose | worktree | `bulwark-video` (ffmpeg pipeline) — after C-vision, C-audio |
| **C-text** | general-purpose | worktree | `bulwark-text` (rules+lexicon FIRST, small classifier SECOND, no hot-path LLM) |
| **C-agent** | general-purpose | worktree | `bulwark-agent` (conventional OCR + accessibility) — feeds C-text |
| **C-supervision** | general-purpose | worktree | `bulwark-supervision` (family-platform connectors) |
| **C-pas** | general-purpose | worktree | `bulwark-policy` + `bulwark-alert` (email) + `bulwark-store` (encrypted SQLite + Postgres adapter) |
| **C-infer** | general-purpose | worktree | `bulwark-infer` (device detection + local-vs-cluster offload) |
| **C-ui** | general-purpose | worktree | `bulwark-ui` (axum + dashboard + cluster admin) |
| **D1 Integrator** | general-purpose | worktree | Merge crates, wire `bulwark-core`, single-node end-to-end smoke, then multi-node |
| **E1 Security review** | `/security-review` | — | Per-phase + final |
| **E2 Verify** | `/verify` + general-purpose | worktree | Integration/perf tests, latency budget, model precision/recall harness |
| **E3 Docs/packaging** | general-purpose | worktree | Setup, coverage dashboard, limitations, gateway/MSI/Android/cluster manifests |

## Dependency graph

```
A1 A2 A3 ─► B1 (incl. bulwark-proto contract) , B2
                 │
                 ├─► C0 proto ─► C-cluster ─► C-server ─┐
                 │            └► C-client ───────────────┤
                 ├─► C-net ─► C-flow                     │
                 ├─► C-vision ─┐                         │
                 ├─► C-audio ──┴► C-video                ├─► D1 ─► E1/E2/E3
                 ├─► C-text  ◄── C-agent                 │
                 ├─► C-supervision                       │
                 ├─► C-pas                               │
                 ├─► C-infer                             │
                 └─► C-ui ────────────────────────────────┘
```

Parallel after gates: C-net, C-vision, C-audio, C-text, C-supervision, C-pas, C-infer, C-ui, and
(after C0) C-cluster/C-client. Sequenced: C-flow←C-net, C-video←C-vision+C-audio, C-server←C-cluster,
C-text←C-agent.

## Hand-off contract (every builder receives)

1. Target crate + its public interface from B1 + `bulwark-proto` (code to the contract; don't invent APIs).
2. Approved deps (A1) + models (A2) — **no new deps without flagging**.
3. Constraints: `forbid(unsafe_code)` except audited FFI; **mTLS on all node links**; **minimal AI**
   (rules/small models/conventional OCR, no hot-path LLM); no telemetry; no explicit-media persistence.
4. Done = compiles, `cargo deny`/`clippy` clean, unit tests, README, **honest can't-do notes**.
5. Report: what was built, deviations, gaps, follow-ups.

## Persistent agent roster (`.claude/agents/`)

The wave roster above built the engine. Ongoing product work (PLAN.md §6 workflows
A–D) uses a **persistent, project-local roster** — each is a markdown agent in
`.claude/agents/` with the project's hard-won facts baked in (toolchain paths, SAC
workaround, framing glossary, proven code patterns):

| Agent | Owns | Typical use |
|---|---|---|
| `rust-core` | `crates/bulwark-*` engine | data-path tracing, crate review, cargo verify |
| `android-bridge` | JNI cdylib + Kotlin shell + builds | cargo-ndk `.so`, gradle APK, adb/logcat |
| `dioxus-ui` | `apps/child` + `apps/parent` UI | screens, router, theme, code-split (Workflow A) |
| `grpc-contract` | `bulwark.proto` + server services | ChildControl-style contracts (Workflow B) |
| `midscene-qa` | `tools/ui-tests` harness | UI journeys web/android, smoke, devices |
| `framing-review` | language only | protective-framing audit before every PR |
| `plan-sync` | PLAN.md + docs/design + finish-plan | mark DONE, flag drift, draft next increment |

**House rule:** spawned agents cannot write files in this environment — every agent
is read-only by contract and returns exact `path` + old→new edits (plain text, never
HTML-escaped) that the **main session applies and verifies**. Root `CLAUDE.md` is
loaded by every agent and carries the shared constraints.

Standard loop per increment: `plan-sync` (where are we) → specialist agent(s) in
parallel (design + exact edits) → main session applies + `cargo check`/tests →
`framing-review` on the diff → `plan-sync` edits to mark DONE → PR with `@codex review`.

## Mapping to the six requirements

- **All deployment targets** → C-net per-OS TUN + C-agent + Android shell + gateway/MSI/Android in E3.
- **Commercial-grade but free/OSS** → A1/A2 license gates + `cargo-deny` allowlist + ffmpeg shelled out.
- **All 3 E2E approaches** → C-text (network) + C-agent (on-device OCR) + C-supervision (platform APIs).
- **Detect device + offload on mobile** → C-infer + C-core capability detection + C-server cluster.
- **Client/server with clustering** → C0 proto + C-cluster + C-server (roles) + C-client + mTLS.
- **Use AI sparingly** → C-text rules-first + small classifier; C-agent conventional OCR; C-vision/audio
  small dedicated models; optional LLM off by default in C-ui review escalation only.
