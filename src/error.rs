//! The error module defines structured failures returned externally by the relay.
//!
//! This module only stores the observable error model. Other modules pass failures through `RelayResult`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `RelayResult` is the result type shared by relay modules.
pub type RelayResult<T> = Result<T, RelayError>;

/// `RelayError` expresses failure code, stage, target, and retry semantics.
///
/// # Examples
///
/// ```
/// use rust_supervisor_relay::error::RelayError;
///
/// let error = RelayError::new(
///     "invalid_public_url",
///     "config",
///     None,
///     "listen.public_url must use wss://",
///     false,
/// );
///
/// assert_eq!(error.code, "invalid_public_url");
/// assert!(!error.retryable);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{code} at {stage}: {message}")]
pub struct RelayError {
    /// `code` is the stable machine-readable failure type.
    pub code: String,
    /// `stage` identifies whether the failure happened in configuration, registration, authentication, session, IPC, or command paths.
    pub stage: String,
    /// `target_id` stores the target process when the failure is target-bound.
    pub target_id: Option<String>,
    /// `message` stores the diagnostic text readable by operators.
    pub message: String,
    /// `retryable` indicates whether the caller may retry after state changes.
    pub retryable: bool,
}

impl RelayError {
    /// Creates a structured relay error.
    ///
    /// The `code` parameter is the stable error code.
    /// The `stage` parameter is the failure stage.
    /// The `target_id` parameter is the optional target identifier.
    /// The `message` parameter is the operator-readable diagnostic.
    /// The `retryable` parameter indicates whether the failure is retryable.
    /// The return value is the complete `RelayError`.
    pub fn new(
        code: impl Into<String>,
        stage: impl Into<String>,
        target_id: Option<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            code: code.into(),
            stage: stage.into(),
            target_id,
            message: message.into(),
            retryable,
        }
    }

    /// Creates a structured relay error bound to a target process.
    ///
    /// The `code` parameter is the stable error code.
    /// The `stage` parameter is the failure stage.
    /// The `target_id` parameter is the target process identifier.
    /// The `message` parameter is the operator-readable diagnostic.
    /// The `retryable` parameter indicates whether the failure is retryable.
    /// The return value is the complete `RelayError`.
    pub fn for_target(
        code: impl Into<String>,
        stage: impl Into<String>,
        target_id: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self::new(code, stage, Some(target_id.into()), message, retryable)
    }
}
