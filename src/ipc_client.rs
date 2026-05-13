//! The ipc_client module encapsulates the local IPC boundary from the relay to target processes.
//!
//! Production paths can use Unix domain sockets with newline-delimited JSON.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use uuid::Uuid;

use crate::command::{ControlCommandName, ControlCommandResult, PreparedCommand};
use crate::error::{RelayError, RelayResult};
use crate::registry::TargetProcessRegistration;

/// `DashboardState` is the minimal state model that the relay reads from target IPC and forwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardState {
    /// `target_id` is the target process identity.
    pub target_id: String,
    /// `state_generation` is the monotonically increasing state version inside the target process.
    pub state_generation: u64,
    /// `generated_at` is the state generation time.
    pub generated_at: OffsetDateTime,
    /// `payload` stores the complete target-side supervision tree and runtime state.
    pub payload: serde_json::Value,
}

/// `TargetIpcPort` defines the IPC capabilities required by the relay.
pub trait TargetIpcPort {
    /// Connects to target IPC and reads state.
    ///
    /// The `registration` parameter is the active target process registration.
    /// The `now` parameter is the connection time.
    /// The return value is the target process state, or a structured IPC error.
    fn connect_state(
        &self,
        registration: &TargetProcessRegistration,
        now: OffsetDateTime,
    ) -> RelayResult<DashboardState>;

    /// Establishes an event and log subscription on target IPC.
    ///
    /// The `registration` parameter is the active target process registration.
    /// The `now` parameter is the subscription time.
    /// The return value is empty when the subscription is established successfully.
    fn subscribe_event_log(
        &self,
        registration: &TargetProcessRegistration,
        now: OffsetDateTime,
    ) -> RelayResult<()>;

    /// Forwards a control command to target IPC.
    ///
    /// The `command` parameter is the validated control command with bound identity.
    /// The `now` parameter is the forwarding time.
    /// The return value is the target process command result.
    fn forward_command(
        &self,
        registration: &TargetProcessRegistration,
        command: &PreparedCommand,
        now: OffsetDateTime,
    ) -> RelayResult<ControlCommandResult>;
}

impl TargetIpcPort for UnixNdjsonIpcClient {
    fn connect_state(
        &self,
        registration: &TargetProcessRegistration,
        now: OffsetDateTime,
    ) -> RelayResult<DashboardState> {
        let response = self.request_json_blocking(
            &registration.ipc_path,
            json!({
                "request_id": request_id(),
                "method": "state",
                "params": {
                    "target_id": registration.target_id
                }
            }),
        )?;
        let result = response_result(response)?;
        let state = result.get("state").cloned().ok_or_else(|| {
            RelayError::for_target(
                "ipc_state_missing",
                "ipc_response",
                registration.target_id.clone(),
                "state response did not include state payload",
                false,
            )
        })?;
        Ok(DashboardState {
            target_id: result
                .get("target_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(&registration.target_id)
                .to_owned(),
            state_generation: state
                .get("state_generation")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default(),
            generated_at: now,
            payload: state,
        })
    }

    fn subscribe_event_log(
        &self,
        registration: &TargetProcessRegistration,
        _now: OffsetDateTime,
    ) -> RelayResult<()> {
        self.subscription_request(
            &registration.ipc_path,
            &registration.target_id,
            "events.subscribe",
        )?;
        self.subscription_request(&registration.ipc_path, &registration.target_id, "logs.tail")?;
        Ok(())
    }

    fn forward_command(
        &self,
        registration: &TargetProcessRegistration,
        command: &PreparedCommand,
        now: OffsetDateTime,
    ) -> RelayResult<ControlCommandResult> {
        let response = self.forward_command_request(registration, command, now)?;
        let result = response_result(response)?;
        let command_result = result.get("result").cloned().ok_or_else(|| {
            RelayError::for_target(
                "ipc_command_result_missing",
                "ipc_response",
                command.target_id.clone(),
                "command response did not include result payload",
                false,
            )
        })?;
        Ok(ControlCommandResult {
            command_id: command_result
                .get("command_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(&command.command_id)
                .to_owned(),
            correlation_id: command_result
                .get("correlation_id")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| command.correlation_id.clone()),
            target_id: command_result
                .get("target_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(&command.target_id)
                .to_owned(),
            accepted: command_result
                .get("accepted")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            status: command_result
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("failed")
                .to_owned(),
            requested_by: command.requested_by.clone(),
            completed_at: now,
        })
    }
}

/// `UnixNdjsonIpcClient` provides minimal request-response capability for real target IPC.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnixNdjsonIpcClient;

impl UnixNdjsonIpcClient {
    /// Sends one IPC request and reads one response line.
    ///
    /// The `ipc_path` parameter is the target process Unix domain socket path.
    /// The `request` parameter is the JSON object to write.
    /// The return value is the target process response JSON.
    pub async fn request_json(
        &self,
        ipc_path: &Path,
        request: serde_json::Value,
    ) -> RelayResult<serde_json::Value> {
        let mut stream = UnixStream::connect(ipc_path).await.map_err(|error| {
            RelayError::new(
                "ipc_connect_failed",
                "ipc_connect",
                None,
                format!("target process IPC could not be connected: {error}"),
                true,
            )
        })?;

        let mut line = serde_json::to_vec(&request).map_err(|error| {
            RelayError::new(
                "ipc_encode_failed",
                "ipc_request",
                None,
                format!("IPC request could not be encoded: {error}"),
                false,
            )
        })?;
        line.push(b'\n');
        stream.write_all(&line).await.map_err(|error| {
            RelayError::new(
                "ipc_write_failed",
                "ipc_request",
                None,
                format!("IPC request could not be written: {error}"),
                true,
            )
        })?;

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await.map_err(|error| {
            RelayError::new(
                "ipc_read_failed",
                "ipc_response",
                None,
                format!("IPC response could not be read: {error}"),
                true,
            )
        })?;

        serde_json::from_str(response.trim()).map_err(|error| {
            RelayError::new(
                "ipc_decode_failed",
                "ipc_response",
                None,
                format!("IPC response could not be decoded: {error}"),
                false,
            )
        })
    }

    /// Sends one IPC request and synchronously waits for the response.
    ///
    /// The `ipc_path` parameter is the target process Unix domain socket path.
    /// The `request` parameter is the JSON object to write.
    /// The return value is the target process response JSON.
    pub fn request_json_blocking(
        &self,
        ipc_path: &Path,
        request: serde_json::Value,
    ) -> RelayResult<serde_json::Value> {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            return tokio::task::block_in_place(|| {
                handle.block_on(self.request_json(ipc_path, request))
            });
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(|error| {
                RelayError::new(
                    "ipc_runtime_failed",
                    "ipc_request",
                    None,
                    format!("IPC runtime could not be built: {error}"),
                    false,
                )
            })?;
        runtime.block_on(self.request_json(ipc_path, request))
    }

    /// Sends a subscription request to target IPC.
    ///
    /// The `ipc_path` parameter is the target process Unix domain socket path.
    /// The `target_id` parameter is the target process identifier.
    /// The `method` parameter is the subscription method.
    /// The return value is empty when subscription succeeds.
    fn subscription_request(
        &self,
        ipc_path: &Path,
        target_id: &str,
        method: &str,
    ) -> RelayResult<()> {
        let response = self.request_json_blocking(
            ipc_path,
            json!({
                "request_id": request_id(),
                "method": method,
                "params": {
                    "target_id": target_id,
                    "session_established": true
                }
            }),
        )?;
        response_result(response).map(|_| ())
    }

    /// Forwards a control command to target IPC.
    ///
    /// The `command` parameter is the validated control command with bound identity.
    /// The `now` parameter is the forwarding time.
    /// The return value is the target process response JSON.
    fn forward_command_request(
        &self,
        registration: &TargetProcessRegistration,
        command: &PreparedCommand,
        now: OffsetDateTime,
    ) -> RelayResult<serde_json::Value> {
        self.request_json_blocking(
            &registration.ipc_path,
            json!({
                "request_id": request_id(),
                "method": command_method(command.command),
                "params": {
                    "command_id": command.command_id,
                    "correlation_id": command.correlation_id,
                    "target_id": command.target_id,
                    "command": command.command,
                    "target": {
                        "child_path": command.target.child_path
                    },
                    "reason": command.reason,
                    "requested_by": command.requested_by,
                    "confirmed": command.confirmed,
                    "requested_at_unix_nanos": now.unix_timestamp_nanos()
                }
            }),
        )
    }
}

/// Creates an IPC request identifier.
///
/// This function has no parameters because the request identifier is generated locally by the relay.
/// The return value is the UUID string.
fn request_id() -> String {
    Uuid::new_v4().to_string()
}

/// Parses the successful result from a target IPC response.
///
/// The `response` parameter is the target process response JSON.
/// The return value is the `result` field, or a structured error.
fn response_result(response: serde_json::Value) -> RelayResult<serde_json::Value> {
    if response
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return response.get("result").cloned().ok_or_else(|| {
            RelayError::new(
                "ipc_result_missing",
                "ipc_response",
                None,
                "IPC response did not include result",
                false,
            )
        });
    }
    if let Some(error) = response.get("error") {
        return Err(RelayError::new(
            error
                .get("code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("ipc_error"),
            error
                .get("stage")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("ipc_response"),
            error
                .get("target_id")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            error
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("IPC response returned an error"),
            error
                .get("retryable")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        ));
    }
    Err(RelayError::new(
        "ipc_response_failed",
        "ipc_response",
        None,
        "IPC response was not successful",
        false,
    ))
}

/// Returns the IPC method for a control command.
///
/// The `command` parameter is the command name accepted by the relay.
/// The return value is the target process IPC method name.
fn command_method(command: ControlCommandName) -> &'static str {
    match command {
        ControlCommandName::RestartChild => "command.restart_child",
        ControlCommandName::PauseChild => "command.pause_child",
        ControlCommandName::ResumeChild => "command.resume_child",
        ControlCommandName::QuarantineChild => "command.quarantine_child",
        ControlCommandName::RemoveChild => "command.remove_child",
        ControlCommandName::AddChild => "command.add_child",
        ControlCommandName::ShutdownTree => "command.shutdown_tree",
    }
}
