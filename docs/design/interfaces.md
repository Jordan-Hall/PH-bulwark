# Bulwark — Interface Contracts (B1)

The Rust **trait contracts** every builder codes against. They are expressed in
`bulwark-proto` (`bulwark.v1`) types so the in-process boundaries and the on-the-wire
boundaries use one vocabulary. Builders **implement the trait for their crate;
they do not invent new public APIs** (workflow hand-off rule #1).

Conventions:
- `async fn` in traits via **`async-trait`** (workspace dep) — used wherever the
  call does I/O (network, disk, model session) or may block.
- Pure CPU/in-memory predicates are **sync**.
- Errors use a shared `bulwark_core::Error` (`thiserror`); shown here as
  `bulwark_core::Result<T>`.
- `use bulwark_proto::v1::*;` and helper newtypes (`DeviceId`, `NodeId`,
  `GroomingRule`) are assumed in scope.

These signatures are the **contract**; exact lifetimes/streams may be refined by
C0 when the proto compiles, but names, arguments, and ownership must hold.

---

## Summary

| Trait | Implemented by | Async? | Purpose |
|---|---|---|---|
| `Interceptor` | **bulwark-net** | yes | TUN/TLS inspection capture; CA; QUIC downgrade; pinning detection |
| `FlowClassifier` | **bulwark-flow** | yes | classify flow, demux streams, buffer/delay |
| `Analyzer` | **bulwark-vision / -audio / -video / -text / -supervision** (server) and **bulwark-infer** (local) | yes | `AnalysisRequest → Verdict` |
| `OcrSource` | **bulwark-agent** | yes | on-device conventional OCR / accessibility → `TextSpan` |
| `OffloadRouter` | **bulwark-infer** | yes | local-vs-cluster routing; offload negotiation |
| `PolicyEngine` | **bulwark-policy** | no | `Verdict → Action`; alert-worthiness |
| `AlertSink` | **bulwark-alert** | yes | raise `AlertEvent` (rate-limit/digest, redacted) |
| `Store` | **bulwark-store** | yes | persist redacted events/verdicts (SQLite client / Postgres server) |
| `ClusterMember` | **bulwark-cluster** | yes | membership, health, work queue, drain |

---

## `Interceptor` — bulwark-net

Captures and (where possible) decrypts device traffic, surfacing inspectable
units. Owns the per-install CA and the QUIC-downgrade / pinning-detection logic.

```rust
/// A captured, inspection-decrypted (or marked-unreadable) network unit handed up to
/// the flow layer. Carries no verdict yet.
pub struct CapturedFlow {
    pub flow_id: u64,
    pub source_channel: SourceChannel, // WEB / VIDEO_STREAM / LIVE_STREAM
    pub app_or_host: String,
    pub readable: bool,                 // false = pinned/E2E → route to OcrSource
    pub payload: FlowPayload,           // bytes + protocol metadata
}

pub enum InterceptDecision {
    Forward,                 // pass through unchanged
    Rewrite(Vec<u8>),        // replace payload (blur image / interstitial)
    Drop,                    // BLOCK
}

#[async_trait::async_trait]
pub trait Interceptor: Send + Sync {
    /// Bring the TUN/VpnService + TLS-inspecting proxy up; install/load the per-install CA.
    async fn start(&self) -> bulwark_core::Result<()>;

    /// Stream of decrypted (or pinning-flagged) flows for classification.
    async fn next_flow(&self) -> bulwark_core::Result<Option<CapturedFlow>>;

    /// Apply a policy decision back onto a live flow (forward/rewrite/drop).
    async fn apply(&self, flow_id: u64, decision: InterceptDecision)
        -> bulwark_core::Result<()>;

    /// True if a flow was rejected by cert pinning (→ OCR fallback path).
    fn is_pinned(&self, app_or_host: &str) -> bool;

    /// Graceful teardown (MUST restore routing/nftables; see platform feasibility §2).
    async fn shutdown(&self) -> bulwark_core::Result<()>;
}
```

---

## `FlowClassifier` — bulwark-flow

Turns a `CapturedFlow` into analysis-ready units: text spans, image frames,
audio spans, or buffered video segments — applying the ring-buffer/delay for
streaming media.

```rust
/// One analysis-ready unit produced from a flow. Maps 1:1 onto an
/// `AnalysisRequest` (the router fills device_id/ts/request_id).
pub enum AnalysisUnit {
    Text(TextSpan),
    Image(InlineMedia),
    Audio(InlineMedia),
    VideoSegment { media: InlineMedia, deadline_ms: u32 },
}

#[async_trait::async_trait]
pub trait FlowClassifier: Send + Sync {
    /// Classify + demux a captured flow into zero or more analysis units.
    /// For streaming media this drives the buffer; units are released as the
    /// delay window permits.
    async fn classify(&self, flow: CapturedFlow)
        -> bulwark_core::Result<Vec<AnalysisUnit>>;

    /// How far behind live the play-out buffer currently sits (live budget).
    fn current_delay_ms(&self) -> u32;
}
```

---

## `Analyzer` — server analyzers + local first-pass

The core analysis contract. The **same trait** is implemented server-side by
`bulwark-vision`/`-audio`/`-video`/`-text`/`-supervision` (heavy models) and
client-side by `bulwark-infer` (tiny first-pass models). `bulwark-server` dispatches
to the right analyzer by `AnalysisRequest.media_kind`.

```rust
#[async_trait::async_trait]
pub trait Analyzer: Send + Sync {
    /// Which media kinds this analyzer handles (server uses it to dispatch).
    fn handles(&self) -> &[MediaKind];

    /// Analyse one request → one verdict. MUST NOT return raw explicit media in
    /// `Verdict.evidence` (hashes / safe thumbnail / redacted snippet only).
    async fn analyze(&self, req: AnalysisRequest) -> bulwark_core::Result<Verdict>;

    /// Batched analyse (sampled video frames). Default = sequential `analyze`.
    async fn analyze_batch(&self, batch: AnalysisBatch)
        -> bulwark_core::Result<VerdictBatch> {
        let mut verdicts = Vec::with_capacity(batch.requests.len());
        for req in batch.requests {
            verdicts.push(self.analyze(req).await?);
        }
        Ok(VerdictBatch { verdicts })
    }

    /// Streaming analyse for live capture (bidi). Returns a verdict stream.
    async fn analyze_stream(
        &self,
        requests: futures_core::stream::BoxStream<'static, AnalysisRequest>,
    ) -> bulwark_core::Result<
        futures_core::stream::BoxStream<'static, bulwark_core::Result<Verdict>>,
    >;
}
```

`bulwark-text` additionally exposes the deterministic rule layer so the verdict is
explainable; this is a crate-local detail layered under `Analyzer`:

```rust
/// bulwark-text internal: deterministic rules FIRST, classifier SECOND.
pub trait GroomingRules {
    /// Run the eight indicator rules + context multipliers (no model).
    fn evaluate(&self, span: &TextSpan, thread: &ThreadState) -> GroomingSignal;
}
```

---

## `OcrSource` — bulwark-agent

The E2E / cert-pinned answer: **conventional OCR** (never a vision-LLM) plus the
accessibility tree and notification text, emitting `TextSpan`s into the same
text pipeline as network chat.

```rust
#[async_trait::async_trait]
pub trait OcrSource: Send + Sync {
    /// Begin capturing on-screen / notification text for the supervised apps.
    async fn start(&self, device: &DeviceId) -> bulwark_core::Result<()>;

    /// Next OCR'd / accessibility-extracted text span (tagged with app + thread).
    /// `source_channel` is OCR_ONSCREEN or NOTIFICATION.
    async fn next_text(&self) -> bulwark_core::Result<Option<TextSpan>>;

    /// Engines available on this device (OS-native first, Tesseract fallback).
    fn engines(&self) -> &[&'static str];

    async fn shutdown(&self) -> bulwark_core::Result<()>;
}
```

---

## `OffloadRouter` — bulwark-infer

Decides local vs. cluster per unit, negotiates and caches the `OffloadPolicy`,
and is the client's single door to the `Analysis`/`Offload` gRPC services.

```rust
pub enum Route {
    Local,
    Cluster,
}

#[async_trait::async_trait]
pub trait OffloadRouter: Send + Sync {
    /// Negotiate an offload policy from this device's capabilities
    /// (`DeviceProfile` built by bulwark-core). Caches until TTL / RefreshOffload.
    async fn negotiate(&self, profile: DeviceProfile)
        -> bulwark_core::Result<OffloadPolicy>;

    /// Decide where a given unit runs, honouring the cached policy + live RTT
    /// + cluster backpressure (see latency budget in architecture.md §4).
    fn route(&self, kind: MediaKind, rtt_ms: u32, queue_depth: u32) -> Route;

    /// Analyse a unit, transparently running locally or calling the cluster
    /// `Analysis` service per `route`.
    async fn analyze(&self, req: AnalysisRequest) -> bulwark_core::Result<Verdict>;

    /// Re-negotiate after TTL or a material capability change (battery, RTT).
    async fn refresh(&self, req: RefreshOffloadRequest)
        -> bulwark_core::Result<OffloadPolicy>;
}
```

---

## `PolicyEngine` — bulwark-policy

Maps a `Verdict` to an `Action` for the age profile, and decides whether an alert
should fire. **Sync** — pure thresholds/profiles, no I/O.

```rust
pub struct PolicyContext {
    pub device: DeviceId,
    pub source_channel: SourceChannel,
    pub age_profile: AgeProfile, // crate-local: thresholds per age band
}

pub trait PolicyEngine: Send + Sync {
    /// Decide the action for a verdict under the given context.
    fn decide(&self, verdict: &Verdict, ctx: &PolicyContext) -> Action;

    /// Whether (and how) this verdict+action should raise a guardian alert.
    /// `None` = no alert (e.g. plain LOG). Builds the kind; bulwark-alert dedupes.
    fn alert_for(&self, verdict: &Verdict, action: Action, ctx: &PolicyContext)
        -> Option<AlertKind>;
}
```

---

## `AlertSink` — bulwark-alert

Raises guardian alerts with **redacted context only**, rate-limited / digested.
Hosts the `AlertRelay` gRPC service server-side; the client calls it through this
trait.

```rust
#[async_trait::async_trait]
pub trait AlertSink: Send + Sync {
    /// Raise one alert (rate-limited / deduped). MUST carry redacted_context +
    /// hash/safe-thumbnail Evidence only — never explicit media.
    async fn raise(&self, event: AlertEvent) -> bulwark_core::Result<AlertAck>;

    /// Flush a digest batch (periodic roll-up of LOG-level events).
    async fn raise_batch(&self, batch: AlertBatch)
        -> bulwark_core::Result<AlertAckBatch>;
}
```

---

## `Store` — bulwark-store

Persists redacted events/verdicts. **Encrypted SQLite** on the client
(`rusqlite` + `age`/SQLCipher), **Postgres** on the server (`sqlx`). The same
trait, two adapters. **Never stores explicit media.**

```rust
pub struct StoredEvent {
    pub device: DeviceId,
    pub verdict: Verdict,        // evidence is already redacted by contract
    pub action: Action,
    pub alert: Option<AlertKind>,
    pub ts: i64,
}

#[async_trait::async_trait]
pub trait Store: Send + Sync {
    async fn record(&self, event: StoredEvent) -> bulwark_core::Result<()>;

    /// Recent events for the dashboard / coverage matrix (paged).
    async fn recent(&self, device: &DeviceId, limit: u32)
        -> bulwark_core::Result<Vec<StoredEvent>>;

    /// Conversation state for the grooming state machine (thread-scoped).
    async fn thread_state(&self, thread_id: &str)
        -> bulwark_core::Result<Option<Vec<u8>>>;

    async fn put_thread_state(&self, thread_id: &str, state: &[u8])
        -> bulwark_core::Result<()>;
}
```

---

## `ClusterMember` — bulwark-cluster

SWIM membership, health, work queue, and graceful drain. Hosts the
`ClusterControl` gRPC service; Postgres is the quorum source-of-truth.

```rust
#[async_trait::async_trait]
pub trait ClusterMember: Send + Sync {
    /// Join the cluster (gossip seeds) → current member view.
    async fn join(&self, req: JoinRequest) -> bulwark_core::Result<JoinResponse>;

    async fn leave(&self, req: LeaveRequest) -> bulwark_core::Result<LeaveResponse>;

    /// Current health for a node (or aggregate when node_id empty).
    async fn health(&self, req: HealthRequest) -> bulwark_core::Result<HealthStatus>;

    /// Push health updates (feeds LB + offload backpressure).
    async fn watch_health(&self, req: WatchHealthRequest)
        -> bulwark_core::Result<
            futures_core::stream::BoxStream<'static, bulwark_core::Result<HealthStatus>>,
        >;

    /// Enqueue a work item; `accepted=false` under backpressure → caller runs local.
    async fn enqueue(&self, req: EnqueueRequest)
        -> bulwark_core::Result<EnqueueResponse>;

    /// Claim work (long-poll, capability-filtered).
    async fn dequeue(&self, req: DequeueRequest)
        -> bulwark_core::Result<DequeueResponse>;

    /// Stop taking new work, finish in-flight within deadline, then go DEAD.
    async fn drain(&self, req: DrainRequest) -> bulwark_core::Result<DrainResponse>;
}
```

---

## Notes for builders

- **Code to the trait + `bulwark-proto`.** Do not widen these signatures without
  flagging the orchestrator (workflow hand-off rule #1).
- `futures_core::stream::BoxStream` is used for the streaming methods; the exact
  stream type will be finalized by **C0** once tonic codegen exists (tonic uses
  `tonic::Streaming<T>` server-side). If `futures` is not yet a workspace dep,
  C0 should add it (flag to A1) or substitute `tonic::Streaming`.
- The `Analyzer` default `analyze_batch` is sequential; GPU workers override it
  with true batching.
- Privacy invariants are **typed where possible** (`Evidence` shape) and **noted
  in every doc-comment** where they are not — never return explicit media.
