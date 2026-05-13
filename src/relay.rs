//! The relay module fans out events, logs, state deltas, and errors by session and authorized target.
//!
//! This module does not connect to target IPC directly. It only dispatches messages for bound sessions.

use time::OffsetDateTime;

use crate::error::RelayResult;
use crate::registry::{ConnectionState, TargetProcessRegistry};
use crate::session::{DashboardSession, EventRecord, LogRecord, ServerMessage};

/// `RelayHub` provides the fan-out boundary.
pub struct RelayHub;

impl RelayHub {
    /// Fans out a target event.
    ///
    /// The `session` parameter is the dashboard session that receives the message.
    /// The `target_id` parameter is the target process identifier.
    /// The `sequence` parameter is the target-local event sequence.
    /// The `event_type` parameter is the event type.
    /// The `severity` parameter is the severity level.
    /// The `occurred_at` parameter is the event time.
    /// The return value is the server message set generated for this event.
    pub fn fan_out_event(
        session: &mut DashboardSession,
        target_id: &str,
        sequence: u64,
        event_type: &str,
        severity: &str,
        occurred_at: OffsetDateTime,
    ) -> RelayResult<Vec<ServerMessage>> {
        session.accept_event(EventRecord {
            target_id: target_id.to_owned(),
            sequence,
            event_type: event_type.to_owned(),
            severity: severity.to_owned(),
            occurred_at,
        })
    }

    /// Fans out a target log.
    ///
    /// The `session` parameter is the dashboard session that receives the message.
    /// The `target_id` parameter is the target process identifier.
    /// The `sequence` parameter is the optional log sequence.
    /// The `severity` parameter is the severity level.
    /// The `message` parameter is the log text.
    /// The `occurred_at` parameter is the log time.
    /// The return value is the server message set generated for this log.
    pub fn fan_out_log(
        session: &mut DashboardSession,
        target_id: &str,
        sequence: Option<u64>,
        severity: &str,
        message: &str,
        occurred_at: OffsetDateTime,
    ) -> RelayResult<Vec<ServerMessage>> {
        session.accept_log(LogRecord {
            target_id: target_id.to_owned(),
            sequence,
            severity: severity.to_owned(),
            message: message.to_owned(),
            occurred_at,
        })
    }

    /// Fans out a state delta.
    ///
    /// The `session` parameter is the dashboard session that receives the message.
    /// The `target_id` parameter is the target process identifier.
    /// The `delta` parameter is the state-change payload.
    /// The return value is the server message set generated for this delta.
    pub fn fan_out_state_delta(
        session: &mut DashboardSession,
        target_id: &str,
        delta: serde_json::Value,
    ) -> RelayResult<Vec<ServerMessage>> {
        session.accept_state_delta(target_id, delta)
    }

    /// Fans out a dropped-count diagnostic.
    ///
    /// The `session` parameter is the dashboard session that receives the message.
    /// The `target_id` parameter is the target process identifier.
    /// The `dropped_event_count` parameter is the number of dropped events.
    /// The return value is the server message set generated for this diagnostic.
    pub fn fan_out_dropped_count(
        session: &mut DashboardSession,
        target_id: &str,
        dropped_event_count: u64,
    ) -> RelayResult<Vec<ServerMessage>> {
        session.accept_dropped_count(target_id, dropped_event_count)
    }

    /// Handles a reconnect timeout and fans out the unavailable state.
    ///
    /// The `session` parameter is the dashboard session that receives the message.
    /// The `registry` parameter is the target process registry.
    /// The `target_id` parameter is the target process identifier.
    /// The `now` parameter is the timeout time.
    /// The return value is the server message set generated for this timeout.
    pub fn reconnect_timeout(
        session: &mut DashboardSession,
        registry: &mut TargetProcessRegistry,
        target_id: &str,
        now: OffsetDateTime,
    ) -> RelayResult<Vec<ServerMessage>> {
        registry.mark_unavailable(target_id, "reconnect timeout after 10 seconds", now);
        session.accept_connection_state(target_id, ConnectionState::Unavailable)
    }
}
