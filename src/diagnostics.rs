//! The diagnostics module provides structured fields for relay failure paths.
//!
//! These structures can be written to tracing or converted into dashboard error messages.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// `DiagnosticEvent` stores an observable failure or state change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    /// `stage` identifies whether the diagnostic came from configuration, registration, authentication, session, IPC, or command handling.
    pub stage: String,
    /// `target_id` stores the target process when the diagnostic is target-bound.
    pub target_id: Option<String>,
    /// `code` is the machine-readable diagnostic type.
    pub code: String,
    /// `message` is the operator-readable diagnostic.
    pub message: String,
    /// `occurred_at` is the diagnostic generation time.
    pub occurred_at: OffsetDateTime,
}

impl DiagnosticEvent {
    /// Creates a diagnostic event.
    ///
    /// The `stage` parameter is the failure or state-change stage.
    /// The `target_id` parameter is the optional target process identifier.
    /// The `code` parameter is the machine-readable diagnostic code.
    /// The `message` parameter is the operator-readable diagnostic.
    /// The `occurred_at` parameter is the diagnostic generation time.
    /// The return value is the structured diagnostic event.
    pub fn new(
        stage: impl Into<String>,
        target_id: Option<String>,
        code: impl Into<String>,
        message: impl Into<String>,
        occurred_at: OffsetDateTime,
    ) -> Self {
        Self {
            stage: stage.into(),
            target_id,
            code: code.into(),
            message: message.into(),
            occurred_at,
        }
    }
}
