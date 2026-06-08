//! Crate-local error type, convertible into the shared [`bulwark_core::Error`].
//!
//! The [`FlowClassifier`](crate::FlowClassifier) trait (docs/design/interfaces.md)
//! returns [`bulwark_core::Result`], so [`FlowError`] exists only to give the
//! classification/buffering internals precise, matchable variants; it `From`-converts
//! into [`bulwark_core::Error`] at the trait boundary.

/// Result alias for the crate's internal fallible operations.
pub type Result<T> = std::result::Result<T, FlowError>;

/// Errors raised while classifying or buffering a flow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FlowError {
    /// The captured flow carried no body/stream we could classify, and its
    /// headers gave no usable signal (treated as pass-through by the classifier,
    /// surfaced as an error only when the caller demands a unit).
    #[error("flow is unclassifiable (no usable content-type, extension, or magic bytes)")]
    Unclassifiable,

    /// A streaming manifest (HLS/DASH) was detected but could not be parsed.
    #[error("malformed streaming manifest: {0}")]
    Manifest(String),

    /// The delay buffer is full and back-pressure could not be relieved within
    /// the latency budget (the producer must slow down or shed).
    #[error("delay buffer at capacity (back-pressure): {0}")]
    BufferFull(String),

    /// A segment was referenced (by id) that the buffer no longer holds —
    /// already released, dropped, or never admitted.
    #[error("buffered segment {0} not found (already released or dropped)")]
    SegmentNotFound(u64),

    /// The live deadline elapsed before a verdict arrived; the fail-safe default
    /// applies (per policy: block or warn).
    #[error("live deadline ({0} ms) missed before a verdict arrived")]
    DeadlineMissed(u32),
}

impl From<FlowError> for bulwark_core::Error {
    fn from(e: FlowError) -> Self {
        match e {
            // Capacity / deadline issues are an in-process channel-shaped failure.
            FlowError::BufferFull(_) | FlowError::DeadlineMissed(_) => {
                bulwark_core::Error::Ipc(e.to_string())
            }
            // Everything else is a malformed/unsupported input.
            other => bulwark_core::Error::InvalidValue(other.to_string()),
        }
    }
}
