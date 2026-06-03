//! aegis-cluster — SWIM membership, health, work queue, and graceful drain.
//!
//! Implements the [`ClusterMember`] contract from `docs/design/interfaces.md`.
//! A single-node `all-in-one` deployment uses the in-process membership + work
//! queue here with no external dependency. Multi-node deployments enable the
//! `gossip` feature (SWIM via `foca`) and the `quorum` feature (Postgres as the
//! split-brain-avoiding source-of-truth) — those integration points are marked.
//!
//! No AI/ML, no telemetry. `#![forbid(unsafe_code)]`.
#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use aegis_core::Result;
use aegis_proto::v1::{
    DequeueRequest, DequeueResponse, DrainRequest, DrainResponse, EnqueueRequest,
    EnqueueResponse, HealthRequest, HealthStatus, JoinRequest, JoinResponse, LeaveRequest,
    LeaveResponse, NodeInfo, NodeState, WatchHealthRequest, WorkItem,
};
use async_trait::async_trait;
use futures_core::stream::BoxStream;
use tokio::sync::{Mutex, Notify};

pub mod service;

/// Configuration for this node's participation in the cluster.
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    pub node_id: String,
    pub cluster_id: String,
    /// host:port mTLS endpoint advertised to peers.
    pub address: String,
    /// Seeds to gossip with on join (empty = bootstrap a new single-node cluster).
    pub seeds: Vec<String>,
    /// Enqueue is refused (accepted=false → caller runs local) above this depth.
    pub backpressure_depth: u32,
    /// Optional Postgres DSN; when set (and `quorum` enabled) it is the
    /// authoritative membership/lease store. A node that loses its lease stops
    /// accepting work — this is what prevents split-brain.
    pub quorum_dsn: Option<String>,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: "node-local".to_string(),
            cluster_id: "aegis-local".to_string(),
            address: "127.0.0.1:8443".to_string(),
            seeds: Vec::new(),
            backpressure_depth: 512,
            quorum_dsn: None,
        }
    }
}

#[derive(Default)]
struct Queue {
    items: VecDeque<WorkItem>,
}

/// The cluster member: membership view + work queue + health, behind the
/// [`ClusterMember`] trait. Cheap to `clone` (everything is `Arc`-shared).
#[derive(Clone)]
pub struct Cluster {
    cfg: Arc<ClusterConfig>,
    members: Arc<Mutex<HashMap<String, NodeInfo>>>,
    queue: Arc<Mutex<Queue>>,
    inflight: Arc<AtomicU32>,
    seq: Arc<AtomicU64>,
    /// false after `drain`/`leave` or when quorum/lease is lost.
    accepting: Arc<std::sync::atomic::AtomicBool>,
    work_ready: Arc<Notify>,
}

impl Cluster {
    pub fn new(cfg: ClusterConfig) -> Self {
        Self {
            cfg: Arc::new(cfg),
            members: Arc::new(Mutex::new(HashMap::new())),
            queue: Arc::new(Mutex::new(Queue::default())),
            inflight: Arc::new(AtomicU32::new(0)),
            seq: Arc::new(AtomicU64::new(1)),
            accepting: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            work_ready: Arc::new(Notify::new()),
        }
    }

    /// Mark a unit of work finished (worker calls this after producing a Verdict).
    pub fn complete_inflight(&self) {
        // Saturating decrement: an extra completion (or one with nothing in
        // flight) must not wrap the unsigned counter to u32::MAX.
        let _ = self
            .inflight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    async fn queue_depth(&self) -> u32 {
        self.queue.lock().await.items.len() as u32
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    #[cfg(feature = "gossip")]
    /// Placeholder for the SWIM (`foca`) gossip loop: announce this node, run the
    /// probe/suspect/confirm cycle over the mTLS transport, and reconcile the
    /// `members` map from gossip. Wired by the multi-node deployment.
    pub async fn run_gossip(&self) -> Result<()> {
        tracing::info!("gossip loop placeholder — wire foca SWIM here");
        Ok(())
    }
}

#[async_trait]
impl ClusterMember for Cluster {
    async fn join(&self, req: JoinRequest) -> Result<JoinResponse> {
        let mut members = self.members.lock().await;
        if let Some(node) = req.node.clone() {
            members.insert(node.node_id.clone(), node);
        }
        Ok(JoinResponse {
            accepted: true,
            members: members.values().cloned().collect(),
            cluster_id: self.cfg.cluster_id.clone(),
            reason: String::new(),
        })
    }

    async fn leave(&self, req: LeaveRequest) -> Result<LeaveResponse> {
        if req.graceful {
            self.accepting.store(false, Ordering::SeqCst);
        }
        self.members.lock().await.remove(&req.node_id);
        Ok(LeaveResponse { accepted: true })
    }

    async fn health(&self, _req: HealthRequest) -> Result<HealthStatus> {
        let depth = self.queue_depth().await;
        Ok(HealthStatus {
            node_id: self.cfg.node_id.clone(),
            state: if self.accepting.load(Ordering::SeqCst) {
                NodeState::Alive as i32
            } else {
                NodeState::Draining as i32
            },
            queue_depth: depth,
            inflight: self.inflight.load(Ordering::Relaxed),
            cpu_load: 0.0,
            gpu_load: 0.0,
            mem_used_mb: 0,
            p50_latency_ms: 0,
            p99_latency_ms: 0,
            accepting_work: self.accepting.load(Ordering::SeqCst),
            ts: now_ms(),
        })
    }

    async fn watch_health(
        &self,
        req: WatchHealthRequest,
    ) -> Result<BoxStream<'static, Result<HealthStatus>>> {
        let this = self.clone();
        let interval = req.interval_ms.max(250) as u64;
        let stream = futures_util::stream::unfold(this, move |c| async move {
            tokio::time::sleep(std::time::Duration::from_millis(interval)).await;
            let h = c.health(HealthRequest::default()).await;
            Some((h, c))
        });
        Ok(Box::pin(stream))
    }

    async fn enqueue(&self, req: EnqueueRequest) -> Result<EnqueueResponse> {
        let mut q = self.queue.lock().await;
        let depth = q.items.len() as u32;
        if !self.accepting.load(Ordering::SeqCst) || depth >= self.cfg.backpressure_depth {
            // Backpressure → caller falls back to local analysis.
            return Ok(EnqueueResponse {
                work_id: String::new(),
                queue_position: depth,
                accepted: false,
            });
        }
        let item = req.item.unwrap_or_default();
        let work_id = if item.work_id.is_empty() {
            format!("{}-{}", self.cfg.node_id, self.next_seq())
        } else {
            item.work_id.clone()
        };
        let mut item = item;
        item.work_id = work_id.clone();
        q.items.push_back(item);
        let position = q.items.len() as u32;
        drop(q);
        self.work_ready.notify_one();
        Ok(EnqueueResponse {
            work_id,
            queue_position: position,
            accepted: true,
        })
    }

    async fn dequeue(&self, req: DequeueRequest) -> Result<DequeueResponse> {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(req.wait_ms.max(1) as u64);
        loop {
            {
                let mut q = self.queue.lock().await;
                if !q.items.is_empty() {
                    let n = req.max_items.max(1) as usize;
                    let mut items = Vec::with_capacity(n.min(q.items.len()));
                    for _ in 0..n {
                        match q.items.pop_front() {
                            Some(i) => {
                                self.inflight.fetch_add(1, Ordering::Relaxed);
                                items.push(i);
                            }
                            None => break,
                        }
                    }
                    return Ok(DequeueResponse { items });
                }
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Ok(DequeueResponse { items: Vec::new() });
            }
            // Long-poll: wake on new work or timeout.
            let _ = tokio::time::timeout(remaining, self.work_ready.notified()).await;
        }
    }

    async fn drain(&self, req: DrainRequest) -> Result<DrainResponse> {
        self.accepting.store(false, Ordering::SeqCst);
        self.work_ready.notify_waiters();
        // Best-effort: report remaining in-flight; a real drain awaits completion
        // up to `deadline_secs` then transitions the node to DEAD.
        let inflight = self.inflight.load(Ordering::Relaxed);
        tracing::info!(deadline_secs = req.deadline_secs, inflight, "draining node");
        Ok(DrainResponse {
            accepted: true,
            inflight,
        })
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// SWIM membership, health, work queue, and graceful drain (interfaces.md).
#[async_trait]
pub trait ClusterMember: Send + Sync {
    async fn join(&self, req: JoinRequest) -> Result<JoinResponse>;
    async fn leave(&self, req: LeaveRequest) -> Result<LeaveResponse>;
    async fn health(&self, req: HealthRequest) -> Result<HealthStatus>;
    async fn watch_health(
        &self,
        req: WatchHealthRequest,
    ) -> Result<BoxStream<'static, Result<HealthStatus>>>;
    async fn enqueue(&self, req: EnqueueRequest) -> Result<EnqueueResponse>;
    async fn dequeue(&self, req: DequeueRequest) -> Result<DequeueResponse>;
    async fn drain(&self, req: DrainRequest) -> Result<DrainResponse>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::v1::AnalysisRequest;

    fn work(id: &str) -> WorkItem {
        WorkItem {
            work_id: id.to_string(),
            request: Some(AnalysisRequest::default()),
            priority: 0,
            enqueued_ts: 0,
            attempts: 0,
        }
    }

    #[tokio::test]
    async fn enqueue_dequeue_roundtrip() {
        let c = Cluster::new(ClusterConfig::default());
        let r = c
            .enqueue(EnqueueRequest {
                item: Some(work("")),
            })
            .await
            .unwrap();
        assert!(r.accepted);
        let d = c
            .dequeue(DequeueRequest {
                node_id: "w1".into(),
                max_items: 10,
                provides: vec![],
                wait_ms: 50,
            })
            .await
            .unwrap();
        assert_eq!(d.items.len(), 1);
        assert_eq!(c.inflight.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn backpressure_refuses_when_full() {
        let cfg = ClusterConfig {
            backpressure_depth: 1,
            ..Default::default()
        };
        let c = Cluster::new(cfg);
        assert!(c
            .enqueue(EnqueueRequest { item: Some(work("a")) })
            .await
            .unwrap()
            .accepted);
        let refused = c
            .enqueue(EnqueueRequest { item: Some(work("b")) })
            .await
            .unwrap();
        assert!(!refused.accepted, "should refuse under backpressure");
    }

    #[tokio::test]
    async fn drain_stops_accepting() {
        let c = Cluster::new(ClusterConfig::default());
        c.drain(DrainRequest {
            node_id: "n".into(),
            deadline_secs: 5,
        })
        .await
        .unwrap();
        let refused = c
            .enqueue(EnqueueRequest { item: Some(work("x")) })
            .await
            .unwrap();
        assert!(!refused.accepted, "draining node must refuse new work");
    }

    #[tokio::test]
    async fn dequeue_times_out_when_empty() {
        let c = Cluster::new(ClusterConfig::default());
        let d = c
            .dequeue(DequeueRequest {
                node_id: "w".into(),
                max_items: 1,
                provides: vec![],
                wait_ms: 20,
            })
            .await
            .unwrap();
        assert!(d.items.is_empty());
    }
}
