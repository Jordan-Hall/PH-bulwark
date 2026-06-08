//! Shared identifier newtypes.
//!
//! These wrap the stringly-typed ids that flow through the `bulwark.v1` wire
//! contract so call sites cannot accidentally swap a request id for a thread id
//! (a class of bug that is otherwise invisible to the compiler).
//!
//! [`DeviceId`] (and [`NodeId`]) are the contract's canonical newtypes and live
//! in `bulwark-proto`; we re-export `DeviceId` here so downstream crates have a
//! single `bulwark_core` import surface for all four ids. [`ThreadId`] and
//! [`RequestId`] are defined here because they are in-process glue, not part of
//! the wire vocabulary beyond their raw string fields.

use std::fmt;

// Re-export the proto-owned device identifier so `bulwark_core::DeviceId` and
// `bulwark_proto::DeviceId` are the same type (no conversion needed at boundaries).
pub use bulwark_proto::DeviceId;

/// Stable per-conversation identifier used by the grooming state machine.
///
/// Mirrors `TextSpan.thread_id` / `Store::thread_state(thread_id)`; wrapping it
/// keeps it distinct from request/device ids at call sites.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct ThreadId(pub String);

impl ThreadId {
    /// Borrow the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the underlying string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for ThreadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for ThreadId {
    fn from(s: String) -> Self {
        ThreadId(s)
    }
}

impl From<&str> for ThreadId {
    fn from(s: &str) -> Self {
        ThreadId(s.to_owned())
    }
}

/// Client-generated idempotency key for one analysis request.
///
/// Mirrors `AnalysisRequest.request_id` / `Verdict.request_id`; a worker uses it
/// to dedupe retries.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct RequestId(pub String);

impl RequestId {
    /// Borrow the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the underlying string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for RequestId {
    fn from(s: String) -> Self {
        RequestId(s)
    }
}

impl From<&str> for RequestId {
    fn from(s: &str) -> Self {
        RequestId(s.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_id_round_trips() {
        let t = ThreadId::from("conv-42");
        assert_eq!(t.as_str(), "conv-42");
        assert_eq!(t.to_string(), "conv-42");
        assert_eq!(t.into_inner(), "conv-42");
    }

    #[test]
    fn request_id_round_trips() {
        let r: RequestId = String::from("req-7").into();
        assert_eq!(r.as_str(), "req-7");
        assert_eq!(r.to_string(), "req-7");
    }

    #[test]
    fn device_id_is_reexported_proto_type() {
        // Same underlying type as bulwark_proto::DeviceId — proves the re-export.
        let d: DeviceId = bulwark_proto::DeviceId("dev-1".to_owned());
        assert_eq!(d.to_string(), "dev-1");
    }
}
