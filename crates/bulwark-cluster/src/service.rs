//! gRPC adapter: exposes a [`ClusterMember`] as the generated `ClusterControl`
//! tonic service so `bulwark-server` can mount it. The exact generated trait
//! signatures are finalized when the proto compiles (C0); this matches tonic's
//! standard server shape.
//!
//! Transport note: this service is always served over **mTLS** (configured in
//! `bulwark-server`); peers authenticate with role-scoped client certs.

use std::pin::Pin;
use std::sync::Arc;

use bulwark_proto::v1::cluster_control_server::ClusterControl;
use bulwark_proto::v1::{
    DequeueRequest, DequeueResponse, DrainRequest, DrainResponse, EnqueueRequest, EnqueueResponse,
    HealthRequest, HealthStatus, JoinRequest, JoinResponse, LeaveRequest, LeaveResponse,
    WatchHealthRequest,
};
use futures_util::StreamExt;
use tonic::{Request, Response, Status};

use crate::ClusterMember;

/// Wraps any [`ClusterMember`] as the gRPC `ClusterControl` service.
#[derive(Clone)]
pub struct ClusterControlService<M: ClusterMember> {
    inner: Arc<M>,
}

impl<M: ClusterMember> ClusterControlService<M> {
    pub fn new(inner: Arc<M>) -> Self {
        Self { inner }
    }
}

fn to_status(e: bulwark_core::Error) -> Status {
    Status::internal(e.to_string())
}

#[tonic::async_trait]
impl<M: ClusterMember + 'static> ClusterControl for ClusterControlService<M> {
    async fn join(&self, req: Request<JoinRequest>) -> Result<Response<JoinResponse>, Status> {
        self.inner
            .join(req.into_inner())
            .await
            .map(Response::new)
            .map_err(to_status)
    }

    async fn leave(&self, req: Request<LeaveRequest>) -> Result<Response<LeaveResponse>, Status> {
        self.inner
            .leave(req.into_inner())
            .await
            .map(Response::new)
            .map_err(to_status)
    }

    async fn health(&self, req: Request<HealthRequest>) -> Result<Response<HealthStatus>, Status> {
        self.inner
            .health(req.into_inner())
            .await
            .map(Response::new)
            .map_err(to_status)
    }

    type WatchHealthStream =
        Pin<Box<dyn futures_core::Stream<Item = Result<HealthStatus, Status>> + Send + 'static>>;

    async fn watch_health(
        &self,
        req: Request<WatchHealthRequest>,
    ) -> Result<Response<Self::WatchHealthStream>, Status> {
        let inner = self
            .inner
            .watch_health(req.into_inner())
            .await
            .map_err(to_status)?;
        let mapped = inner.map(|r| r.map_err(to_status));
        Ok(Response::new(Box::pin(mapped)))
    }

    async fn enqueue(
        &self,
        req: Request<EnqueueRequest>,
    ) -> Result<Response<EnqueueResponse>, Status> {
        self.inner
            .enqueue(req.into_inner())
            .await
            .map(Response::new)
            .map_err(to_status)
    }

    async fn dequeue(
        &self,
        req: Request<DequeueRequest>,
    ) -> Result<Response<DequeueResponse>, Status> {
        self.inner
            .dequeue(req.into_inner())
            .await
            .map(Response::new)
            .map_err(to_status)
    }

    async fn drain(&self, req: Request<DrainRequest>) -> Result<Response<DrainResponse>, Status> {
        self.inner
            .drain(req.into_inner())
            .await
            .map(Response::new)
            .map_err(to_status)
    }
}
