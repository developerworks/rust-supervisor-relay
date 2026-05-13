//! The session module implements `wss://` control sessions, first-message ordering, and IPC binding gates.
//!
//! A session must complete identity authentication and send the target process list before binding target IPC.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::AuditRecorder;
use crate::auth::RemoteIdentity;
use crate::command::{ClientCommand, ControlCommandResult, prepare_client_command};
use crate::error::{RelayError, RelayResult};
use crate::ipc_client::TargetIpcPort;
use crate::registry::{ConnectionState, TargetProcessRegistry, VisibleTarget};

/// `TransportSecurity` represents the external protocol security level of a remote connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSecurity {
    /// `Wss` indicates that TLS completed before WebSocket.
    Wss,
    /// `Ws` indicates a plaintext connection where full control is not allowed.
    Ws,
}

/// `ConnectionStateForSession` expresses the remote connection lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStateForSession {
    /// `Handshaking` indicates that identity has not been established yet.
    Handshaking,
    /// `Established` indicates that the control session has been established.
    Established,
    /// `Closing` indicates that the connection is closing.
    Closing,
    /// `Closed` indicates that the connection is closed.
    Closed,
}

/// `ControlState` indicates whether a session is allowed to control targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlState {
    /// `NotEstablished` indicates that IPC must not be triggered.
    NotEstablished,
    /// `Established` indicates that authentication and control session setup are complete.
    Established,
    /// `Revoked` indicates that authorization has been revoked.
    Revoked,
}

/// `EventRecord` is the minimal event model that the relay fans out externally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    /// `target_id` is the target process that owns the event.
    pub target_id: String,
    /// `sequence` is the monotonically increasing event sequence inside the target process.
    pub sequence: u64,
    /// `event_type` is the supervision event name.
    pub event_type: String,
    /// `severity` is the event severity level.
    pub severity: String,
    /// `occurred_at` is the event time.
    pub occurred_at: OffsetDateTime,
}

/// `LogRecord` is the minimal log model that the relay fans out externally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    /// `target_id` is the target process that owns the log.
    pub target_id: String,
    /// `sequence` is the optional log sequence that can correlate with events.
    pub sequence: Option<u64>,
    /// `severity` is the log severity level.
    pub severity: String,
    /// `message` is the log text.
    pub message: String,
    /// `occurred_at` is the log time.
    pub occurred_at: OffsetDateTime,
}

/// `LogEventFilterMode` indicates whether the relay or the local client handles filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogEventFilterMode {
    /// `Remote` indicates that the relay reduces delivery according to conditions.
    Remote,
    /// `Local` indicates that the relay sends complete subsequent data.
    Local,
}

/// `ResumeCursorEntry` represents the resume point for a single target and stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeCursorEntry {
    /// `delivery_mode` is remote or local filtering.
    pub delivery_mode: String,
    /// `filter_config_version` is the configuration version sent by the relay.
    pub filter_config_version: u64,
    /// `stream_epoch` isolates sequences after a target restart.
    pub stream_epoch: String,
    /// `sequence` is the next inclusive sequence boundary.
    pub sequence: u64,
}

/// `ResumeCursor` stores resume requests for the event and log streams.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeCursor {
    /// `events` stores event stream resume points.
    #[serde(default)]
    pub events: HashMap<String, ResumeCursorEntry>,
    /// `logs` stores log stream resume points.
    #[serde(default)]
    pub logs: HashMap<String, ResumeCursorEntry>,
}

/// `ClientHello` is the first message sent by the client after establishing the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    /// `client_store_id` is the local database partition key.
    pub client_store_id: String,
    /// `resume_cursor` is the resume request supplied by the local persistent store.
    #[serde(default)]
    pub resume_cursor: ResumeCursor,
}

/// `LogEventFilterConditionsMessage` expresses the client's current filter conditions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEventFilterConditionsMessage {
    /// `target_ids` restricts targets.
    #[serde(default)]
    pub target_ids: Vec<String>,
    /// `child_paths` restricts child tasks.
    #[serde(default)]
    pub child_paths: Vec<String>,
    /// `lifecycle_states` restricts lifecycle states.
    #[serde(default)]
    pub lifecycle_states: Vec<String>,
    /// `event_types` restricts event types.
    #[serde(default)]
    pub event_types: Vec<String>,
    /// `severities` restricts severity levels.
    #[serde(default)]
    pub severities: Vec<String>,
    /// `sequence_min` indicates the minimum sequence filtered by the client.
    pub sequence_min: Option<u64>,
    /// `correlation_id` indicates the correlation filter text.
    pub correlation_id: Option<String>,
}

/// `ClientMessage` is the inbound message accepted by the current protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// `ClientHello` must be the first client message.
    ClientHello(ClientHello),
    /// `Command` is a control command after handshake.
    Command(ClientCommand),
    /// `LogEventFilterConditions` is the filter update message in the current protocol.
    LogEventFilterConditions(LogEventFilterConditionsMessage),
}

/// `ServerMessage` is the message sent by the relay to the dashboard through `wss://`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// `ServerHello` is the identity bootstrap sent by the relay before business data.
    ServerHello {
        /// `session_id` is the UUID generated by the relay.
        session_id: Uuid,
        /// `client_identity` is the mTLS certificate identity key.
        client_identity: String,
        /// `log_event_filter_mode` is the filter mode for the current identity.
        log_event_filter_mode: LogEventFilterMode,
        /// `log_event_filter_conditions` contains the filter conditions for the current identity.
        log_event_filter_conditions: serde_json::Value,
        /// `filter_config_version` is the configuration version for the current identity.
        filter_config_version: u64,
    },
    /// `TargetList` is the business data sent after `client_hello` succeeds.
    TargetList {
        /// `targets` contains the current active targets.
        targets: Vec<VisibleTarget>,
    },
    /// `State` is sent after target binding or reconnection.
    State {
        /// `target_id` is the target process identity.
        target_id: String,
        /// `state` is the current target process dashboard payload.
        state: serde_json::Value,
    },
    /// `Event` is an active event from the target process.
    Event {
        /// `target_id` is the target process identity.
        target_id: String,
        /// `event` is the supervision event record.
        event: EventRecord,
    },
    /// `Log` is an active log from the target process.
    Log {
        /// `target_id` is the target process identity.
        target_id: String,
        /// `log` is the target log record.
        log: LogRecord,
    },
    /// `StateDelta` is a target state change.
    StateDelta {
        /// `target_id` is the target process identity.
        target_id: String,
        /// `delta` is the state-change payload.
        delta: serde_json::Value,
    },
    /// `DroppedCount` is an event gap or buffer drop diagnostic.
    DroppedCount {
        /// `target_id` is the target process identity.
        target_id: String,
        /// `dropped_event_count` is the drop or gap count.
        dropped_event_count: u64,
    },
    /// `CommandResult` is the target process control command result.
    CommandResult {
        /// `target_id` is the target process identity.
        target_id: String,
        /// `result` is the control command result.
        result: ControlCommandResult,
    },
    /// `ConnectionState` is a target IPC availability change.
    ConnectionState {
        /// `target_id` is the target process identity.
        target_id: String,
        /// `state` is the target connection state.
        state: ConnectionState,
    },
    /// `Error` is a structured error message.
    Error {
        /// `error` is the structured relay error.
        error: RelayError,
    },
}

/// Decodes a client message and rejects historical protocol fields.
///
/// The `raw` parameter is the WebSocket text message.
/// The return value is the current protocol client message, or a structured rejection error.
pub fn decode_client_message(raw: &str) -> RelayResult<ClientMessage> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|error| {
        RelayError::new(
            "invalid_message_json",
            "session_decode",
            None,
            format!("client message could not be parsed: {error}"),
            false,
        )
    })?;

    let message_type = value.get("type").and_then(serde_json::Value::as_str);
    if message_type == Some("client_hello") {
        let object = value.as_object().ok_or_else(|| {
            RelayError::new(
                "invalid_message_schema",
                "session_decode",
                None,
                "client message must be a JSON object",
                false,
            )
        })?;
        let allowed = ["type", "client_store_id", "resume_cursor"];
        if object.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(RelayError::new(
                "unsupported_field",
                "session_decode",
                None,
                "message field is not supported by the current protocol",
                false,
            ));
        }
    } else if !matches!(
        message_type,
        Some("command" | "log_event_filter_conditions")
    ) {
        return Err(RelayError::new(
            "unsupported_message_type",
            "session_decode",
            None,
            "message type is not supported by the current protocol",
            false,
        ));
    }

    serde_json::from_value(value).map_err(|error| {
        RelayError::new(
            "invalid_message_schema",
            "session_decode",
            None,
            format!("client message schema is invalid: {error}"),
            false,
        )
    })
}

/// `DashboardSession` stores the state of an authenticated remote connection.
#[derive(Debug)]
pub struct DashboardSession {
    /// `session_id` is the UUID generated by the relay.
    session_id: Uuid,
    /// `remote_identity` stores identity after successful authentication.
    remote_identity: Option<RemoteIdentity>,
    /// `client_store_id` is stored after `client_hello`.
    client_store_id: Option<String>,
    /// `connection_state` stores the remote connection lifecycle.
    connection_state: ConnectionStateForSession,
    /// `control_state` stores whether IPC triggering is allowed.
    control_state: ControlState,
    /// `bound_targets` stores targets whose IPC binding has been triggered.
    bound_targets: HashSet<String>,
    /// `last_sequences` stores the latest forwarded event sequence for each target.
    last_sequences: HashMap<String, u64>,
    /// `outbox` stores generated server messages in order.
    outbox: Vec<ServerMessage>,
    /// `created_at` is the session creation time.
    created_at: OffsetDateTime,
    /// `last_seen_at` is the latest session activity time.
    last_seen_at: OffsetDateTime,
}

impl DashboardSession {
    /// Creates an unauthenticated session.
    ///
    /// The `now` parameter is the creation time.
    /// The return value is a session that cannot trigger IPC.
    pub fn unauthenticated(now: OffsetDateTime) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            remote_identity: None,
            client_store_id: None,
            connection_state: ConnectionStateForSession::Handshaking,
            control_state: ControlState::NotEstablished,
            bound_targets: HashSet::new(),
            last_sequences: HashMap::new(),
            outbox: Vec::new(),
            created_at: now,
            last_seen_at: now,
        }
    }

    /// Creates an authenticated session that only sends `server_hello`.
    ///
    /// The `identity` parameter is the authenticated remote identity.
    /// The `now` parameter is the session creation time.
    /// The return value is the session waiting for `client_hello`.
    pub fn server_hello(identity: RemoteIdentity, now: OffsetDateTime) -> Self {
        let session_id = Uuid::new_v4();
        let outbox = vec![ServerMessage::ServerHello {
            session_id,
            client_identity: identity.client_identity.clone(),
            log_event_filter_mode: LogEventFilterMode::Remote,
            log_event_filter_conditions: serde_json::json!({}),
            filter_config_version: 0,
        }];

        Self {
            session_id,
            remote_identity: Some(identity),
            client_store_id: None,
            connection_state: ConnectionStateForSession::Handshaking,
            control_state: ControlState::NotEstablished,
            bound_targets: HashSet::new(),
            last_sequences: HashMap::new(),
            outbox,
            created_at: now,
            last_seen_at: now,
        }
    }

    /// Accepts `client_hello` and opens business data.
    ///
    /// The `hello` parameter is the first client message.
    /// The `now` parameter is the handshake time.
    /// The return value is empty when handshake succeeds.
    pub fn accept_client_hello(
        &mut self,
        hello: ClientHello,
        now: OffsetDateTime,
    ) -> RelayResult<()> {
        if hello.client_store_id.trim().is_empty() {
            return Err(RelayError::new(
                "invalid_message_schema",
                "session",
                None,
                "client_store_id must not be empty",
                false,
            ));
        }

        if self.connection_state != ConnectionStateForSession::Handshaking {
            return Err(RelayError::new(
                "protocol_error",
                "session",
                None,
                "client_hello is only valid during handshaking",
                false,
            ));
        }

        self.client_store_id = Some(hello.client_store_id);
        self.connection_state = ConnectionStateForSession::Established;
        self.control_state = ControlState::Established;
        self.last_seen_at = now;
        Ok(())
    }

    /// Publishes the target list after `client_hello`.
    ///
    /// The `targets` parameter is the current active target set.
    pub fn publish_target_list(&mut self, targets: Vec<VisibleTarget>) {
        self.outbox.push(ServerMessage::TargetList { targets });
    }

    /// Establishes an authenticated control session.
    ///
    /// The `identity` parameter is the authenticated remote identity.
    /// The `registry` parameter is the target process registry.
    /// The `transport` parameter is the remote connection security level.
    /// The `now` parameter is the session establishment time.
    /// The return value is the established session whose first payload is `session_established`.
    pub fn establish(
        identity: RemoteIdentity,
        registry: &TargetProcessRegistry,
        transport: TransportSecurity,
        now: OffsetDateTime,
    ) -> RelayResult<Self> {
        if transport != TransportSecurity::Wss {
            return Err(RelayError::new(
                "insecure_transport",
                "session",
                None,
                "full control session requires wss://",
                false,
            ));
        }

        let mut session = Self::server_hello(identity, now);
        session.accept_client_hello(
            ClientHello {
                client_store_id: "volatile-session".to_owned(),
                resume_cursor: ResumeCursor::default(),
            },
            now,
        )?;
        let targets = registry.active_targets(now);
        session.publish_target_list(targets);

        Ok(session)
    }

    /// Binds one target process and triggers IPC state and subscription.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The `registry` parameter is the mutable target registry.
    /// The `ipc` parameter is the abstracted IPC port.
    /// The `now` parameter is the binding time.
    /// The return value is empty when binding succeeds.
    pub fn bind_target(
        &mut self,
        target_id: &str,
        registry: &mut TargetProcessRegistry,
        ipc: &impl TargetIpcPort,
        now: OffsetDateTime,
    ) -> RelayResult<()> {
        self.ensure_control_established()?;
        registry.ensure_target_active(target_id, now)?;
        let registration = registry.registration(target_id)?.clone();

        if self.bound_targets.contains(target_id) {
            return Ok(());
        }

        registry.begin_binding(target_id, now)?;
        let state = ipc.connect_state(&registration, now).inspect_err(|error| {
            registry.mark_unavailable(target_id, error.message.clone(), now);
        })?;
        registry.mark_connected(target_id, state.state_generation, now)?;
        ipc.subscribe_event_log(&registration, now)
            .inspect_err(|error| {
                registry.mark_unavailable(target_id, error.message.clone(), now);
            })?;

        self.bound_targets.insert(target_id.to_owned());
        self.outbox.push(ServerMessage::State {
            target_id: target_id.to_owned(),
            state: state.payload,
        });
        self.last_seen_at = now;
        Ok(())
    }

    /// Handles one client control command.
    ///
    /// The `command` parameter is the client command.
    /// The `registry` parameter is the mutable target registry.
    /// The `ipc` parameter is the abstracted IPC port.
    /// The `audit` parameter is the audit recorder.
    /// The `now` parameter is the command processing time.
    /// The return value is the target process command result.
    pub fn handle_command(
        &mut self,
        command: ClientCommand,
        registry: &mut TargetProcessRegistry,
        ipc: &impl TargetIpcPort,
        audit: &mut AuditRecorder,
        now: OffsetDateTime,
    ) -> RelayResult<ControlCommandResult> {
        self.ensure_control_established()?;
        let identity = self.remote_identity.clone().ok_or_else(|| {
            RelayError::new(
                "session_not_established",
                "session",
                None,
                "control session is not established",
                false,
            )
        })?;

        if !self.bound_targets.contains(&command.target_id) {
            return Err(RelayError::for_target(
                "target_not_bound",
                "session",
                command.target_id,
                "target must be bound before command forwarding",
                false,
            ));
        }

        registry.ensure_target_active(&command.target_id, now)?;
        registry.ensure_command_supported(&command.target_id, command.command)?;
        let registration = registry.registration(&command.target_id)?.clone();
        let prepared = prepare_client_command(command, &identity, now)?;
        audit.record_accepted(&identity, &prepared, now);
        let result = ipc
            .forward_command(&registration, &prepared, now)
            .inspect_err(|error| {
                audit.record_rejected(&identity, &prepared, error.message.clone(), now);
            })?;
        audit.record_completed(&identity, &prepared, result.status.clone(), now);
        self.outbox.push(ServerMessage::CommandResult {
            target_id: result.target_id.clone(),
            result: result.clone(),
        });
        if result.accepted && result.status == "completed" {
            let target_id = result.target_id.clone();
            if self
                .refresh_target_state_after_command(&target_id, registry, ipc, now)
                .is_err()
            {
                let _ = self.accept_connection_state(&target_id, ConnectionState::Unavailable);
            }
        }
        Ok(result)
    }

    fn refresh_target_state_after_command(
        &mut self,
        target_id: &str,
        registry: &mut TargetProcessRegistry,
        ipc: &impl TargetIpcPort,
        now: OffsetDateTime,
    ) -> RelayResult<()> {
        let registration = registry.registration(target_id)?.clone();
        let state = ipc.connect_state(&registration, now).inspect_err(|error| {
            registry.mark_unavailable(target_id, error.message.clone(), now);
        })?;
        registry.mark_connected(target_id, state.state_generation, now)?;
        self.outbox.push(ServerMessage::State {
            target_id: target_id.to_owned(),
            state: state.payload,
        });
        Ok(())
    }

    /// Reads session output messages.
    ///
    /// This method has no parameters because it reads the current session output queue.
    /// The return value is the server message slice.
    pub fn outbox(&self) -> &[ServerMessage] {
        &self.outbox
    }

    /// Takes and clears the session output queue.
    ///
    /// This method has no parameters because it moves the current output queue.
    /// The return value is the server messages pending delivery.
    pub fn drain_outbox(&mut self) -> Vec<ServerMessage> {
        std::mem::take(&mut self.outbox)
    }

    /// Reads the session id.
    ///
    /// This method has no parameters because it reads the current session state.
    /// The return value is the UUID generated by the relay.
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Reads the session creation time.
    ///
    /// This method has no parameters because it reads the current session state.
    /// The return value is the creation time.
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Determines whether the target is already bound.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The return value indicates whether the session has triggered IPC binding for this target.
    pub fn is_bound(&self, target_id: &str) -> bool {
        self.bound_targets.contains(target_id)
    }

    /// Reads the visible target count from the first session payload.
    ///
    /// This method has no parameters because it reads the first payload in the current output queue.
    /// The return value is the visible target count.
    pub fn visible_target_count(&self) -> usize {
        self.outbox
            .iter()
            .find_map(|message| match message {
                ServerMessage::TargetList { targets } => Some(targets.len()),
                _ => None,
            })
            .unwrap_or(0)
    }

    /// Handles a target event and preserves sequence-order diagnostics.
    ///
    /// The `event` parameter is the target process event.
    /// The return value is the message set that should be sent to the dashboard.
    pub fn accept_event(&mut self, event: EventRecord) -> RelayResult<Vec<ServerMessage>> {
        if !self.bound_targets.contains(&event.target_id) {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        if let Some(previous) = self.last_sequences.get(&event.target_id).copied() {
            if event.sequence <= previous {
                let error = RelayError::for_target(
                    "sequence_not_monotonic",
                    "stream",
                    event.target_id.clone(),
                    "event sequence must be monotonic for each target",
                    false,
                );
                messages.push(ServerMessage::Error { error });
                return Ok(messages);
            }
            if event.sequence > previous + 1 {
                messages.push(ServerMessage::DroppedCount {
                    target_id: event.target_id.clone(),
                    dropped_event_count: event.sequence - previous - 1,
                });
            }
        }

        self.last_sequences
            .insert(event.target_id.clone(), event.sequence);
        messages.push(ServerMessage::Event {
            target_id: event.target_id.clone(),
            event,
        });
        self.outbox.extend(messages.clone());
        Ok(messages)
    }

    /// Handles a target log.
    ///
    /// The `log` parameter is the target process log.
    /// The return value is the message set that should be sent to the dashboard.
    pub fn accept_log(&mut self, log: LogRecord) -> RelayResult<Vec<ServerMessage>> {
        if !self.bound_targets.contains(&log.target_id) {
            return Ok(Vec::new());
        }
        let message = ServerMessage::Log {
            target_id: log.target_id.clone(),
            log,
        };
        self.outbox.push(message.clone());
        Ok(vec![message])
    }

    /// Handles a target state delta.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The `delta` parameter is the state-change payload.
    /// The return value is the message set that should be sent to the dashboard.
    pub fn accept_state_delta(
        &mut self,
        target_id: &str,
        delta: serde_json::Value,
    ) -> RelayResult<Vec<ServerMessage>> {
        if !self.bound_targets.contains(target_id) {
            return Ok(Vec::new());
        }
        let message = ServerMessage::StateDelta {
            target_id: target_id.to_owned(),
            delta,
        };
        self.outbox.push(message.clone());
        Ok(vec![message])
    }

    /// Handles a dropped-count diagnostic.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The `dropped_event_count` parameter is the dropped event count.
    /// The return value is the message set that should be sent to the dashboard.
    pub fn accept_dropped_count(
        &mut self,
        target_id: &str,
        dropped_event_count: u64,
    ) -> RelayResult<Vec<ServerMessage>> {
        if !self.bound_targets.contains(target_id) {
            return Ok(Vec::new());
        }
        let message = ServerMessage::DroppedCount {
            target_id: target_id.to_owned(),
            dropped_event_count,
        };
        self.outbox.push(message.clone());
        Ok(vec![message])
    }

    /// Handles a connection state change.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The `state` parameter is the new connection state.
    /// The return value is the message set that should be sent to the dashboard.
    pub fn accept_connection_state(
        &mut self,
        target_id: &str,
        state: ConnectionState,
    ) -> RelayResult<Vec<ServerMessage>> {
        if !self.bound_targets.contains(target_id) {
            return Ok(Vec::new());
        }
        let message = ServerMessage::ConnectionState {
            target_id: target_id.to_owned(),
            state,
        };
        self.outbox.push(message.clone());
        Ok(vec![message])
    }

    /// Confirms that the control session has been established.
    ///
    /// This method has no parameters because the check reads the current session state.
    /// The return value is empty when the session can trigger IPC.
    fn ensure_control_established(&self) -> RelayResult<()> {
        if self.connection_state == ConnectionStateForSession::Established
            && self.control_state == ControlState::Established
            && self.remote_identity.is_some()
        {
            return Ok(());
        }

        Err(RelayError::new(
            "session_not_established",
            "session",
            None,
            "control session must be established before IPC binding or command forwarding",
            false,
        ))
    }
}
