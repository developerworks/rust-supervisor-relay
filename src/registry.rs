//! The registry module maintains target process active registrations and connection state.
//!
//! Registration only places targets into the visible list. IPC connection is allowed only after an authenticated session binds the target.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::command::ControlCommandName;
use crate::config::RegistrationPolicy;
use crate::error::{RelayError, RelayResult};
use crate::registration::{RegistrationRequest, SupportedCommand};

/// `RegistrationState` represents the state of a target process registration lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    /// `Active` indicates that the registration lease is still valid.
    Active,
    /// `Rejected` indicates that the registration payload did not enter the active table.
    Rejected,
    /// `Expired` indicates that the lease has expired.
    Expired,
}

/// `ConnectionState` represents the lifecycle between the relay and target IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// `Registered` indicates that the target only entered the registry and IPC has not connected yet.
    Registered,
    /// `Disconnected` indicates that the target has no active IPC connection.
    Disconnected,
    /// `Connecting` indicates that an authenticated session is triggering IPC connection.
    Connecting,
    /// `Connected` indicates that IPC handshake and state read succeeded.
    Connected,
    /// `Reconnecting` indicates that retry is in progress after connection failure.
    Reconnecting,
    /// `Unavailable` indicates that target IPC is currently unreachable.
    Unavailable,
    /// `Expired` indicates that the target registration lease has expired.
    Expired,
}

/// `TargetProcessRegistration` is the active record stored by the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetProcessRegistration {
    /// `target_id` is the stable target process identity.
    pub target_id: String,
    /// `display_name` is the dashboard display name.
    pub display_name: String,
    /// `ipc_path` is the target process local socket path.
    pub ipc_path: PathBuf,
    /// `ipc_path_key` is the normalized conflict detection key.
    pub ipc_path_key: String,
    /// `owner_identity` is the local process identity that submitted registration.
    pub owner_identity: String,
    /// `lease_seconds` is the registration validity duration.
    pub lease_seconds: u64,
    /// `supported_commands` is the command set declared executable by the target.
    pub supported_commands: Vec<SupportedCommand>,
    /// `registered_at` is the time when the record first entered the registry.
    pub registered_at: OffsetDateTime,
    /// `renewed_at` is the latest renewal time.
    pub renewed_at: OffsetDateTime,
    /// `expires_at` is the current lease expiration time.
    pub expires_at: OffsetDateTime,
    /// `registration_state` is the current lease state.
    pub registration_state: RegistrationState,
    /// `last_rejection` stores the latest rejection reason.
    pub last_rejection: Option<String>,
}

/// `TargetProcessConnection` stores IPC connection state for one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetProcessConnection {
    /// `target_id` is the stable target process identity.
    pub target_id: String,
    /// `ipc_path` is the target process local socket path.
    pub ipc_path: PathBuf,
    /// `state` is the current connection lifecycle state.
    pub state: ConnectionState,
    /// `last_error` stores the latest structured error.
    pub last_error: Option<String>,
    /// `last_state_generation` stores the state generation that has been sent.
    pub last_state_generation: Option<u64>,
    /// `last_sequence` stores the forwarded event sequence.
    pub last_sequence: Option<u64>,
    /// `connected_at` stores the latest successful connection time.
    pub connected_at: Option<OffsetDateTime>,
    /// `updated_at` stores the latest state change time.
    pub updated_at: OffsetDateTime,
}

/// `VisibleTarget` is the target summary sent to the dashboard in the first session payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisibleTarget {
    /// `target_id` is the stable target process identity.
    pub target_id: String,
    /// `display_name` is the dashboard display name.
    pub display_name: String,
    /// `registration_state` expresses whether the lease is active.
    pub registration_state: RegistrationState,
    /// `connection_state` expresses whether the relay has connected IPC.
    pub connection_state: ConnectionState,
    /// `supported_commands` is the command set declared executable by the target.
    pub supported_commands: Vec<SupportedCommand>,
}

/// `AvailabilitySummary` stores partial availability state across multiple targets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilitySummary {
    /// `total` is the number of all targets in the registry.
    pub total: usize,
    /// `registered` is the number of targets that have not yet bound a connection.
    pub registered: usize,
    /// `connected` is the number of targets with connected IPC.
    pub connected: usize,
    /// `reconnecting` is the number of targets currently reconnecting.
    pub reconnecting: usize,
    /// `unavailable` is the number of currently unreachable targets.
    pub unavailable: usize,
    /// `expired` is the number of targets with expired leases.
    pub expired: usize,
}

/// `TargetProcessRegistry` stores active registrations and connection state.
pub struct TargetProcessRegistry {
    /// `policy` stores the registration path, IPC prefixes, and lease limits.
    policy: RegistrationPolicy,
    /// `registrations` looks up active records by target id.
    registrations: HashMap<String, TargetProcessRegistration>,
    /// `connections` looks up connection lifecycles by target id.
    connections: HashMap<String, TargetProcessConnection>,
}

impl TargetProcessRegistry {
    /// Creates a target process registry.
    ///
    /// The `policy` parameter is the registration policy.
    /// The return value is an empty registry.
    pub fn new(policy: RegistrationPolicy) -> Self {
        Self {
            policy,
            registrations: HashMap::new(),
            connections: HashMap::new(),
        }
    }

    /// Registers one target process.
    ///
    /// The `request` parameter is the dynamic registration request submitted by the target process.
    /// The `owner_identity` parameter is the local process identity that submitted registration.
    /// The `now` parameter is the time when the relay receives registration.
    /// The return value is the active registration record, or a structured rejection error.
    pub fn register(
        &mut self,
        request: RegistrationRequest,
        owner_identity: impl Into<String>,
        now: OffsetDateTime,
    ) -> RelayResult<TargetProcessRegistration> {
        self.validate_request(&request)?;
        let owner_identity = owner_identity.into();
        let ipc_path_key = normalize_ipc_path_key(&request.ipc_path)?;

        if let Some(existing) = self.registrations.get(&request.target_id) {
            if existing.owner_identity != owner_identity {
                return Err(RelayError::for_target(
                    "target_id_owner_mismatch",
                    "registration",
                    request.target_id,
                    "target id is owned by another supervisor identity",
                    false,
                ));
            }
        }

        if self.registrations.iter().any(|(target_id, registration)| {
            target_id != &request.target_id && registration.ipc_path_key == ipc_path_key
        }) {
            return Err(RelayError::new(
                "ipc_path_conflict",
                "registration",
                None,
                "ipc path is already used by another target",
                false,
            ));
        }

        if self.registrations.contains_key(&request.target_id) {
            return self.upsert_existing_registration(request, owner_identity, ipc_path_key, now);
        }

        let expires_at = now + Duration::seconds(request.lease_seconds as i64);
        let registration = TargetProcessRegistration {
            target_id: request.target_id.clone(),
            display_name: request.display_name,
            ipc_path: request.ipc_path.clone(),
            ipc_path_key,
            owner_identity,
            lease_seconds: request.lease_seconds,
            supported_commands: request.supported_commands,
            registered_at: now,
            renewed_at: now,
            expires_at,
            registration_state: RegistrationState::Active,
            last_rejection: None,
        };
        let connection = TargetProcessConnection {
            target_id: request.target_id.clone(),
            ipc_path: request.ipc_path,
            state: ConnectionState::Registered,
            last_error: None,
            last_state_generation: None,
            last_sequence: None,
            connected_at: None,
            updated_at: now,
        };

        self.connections
            .insert(request.target_id.clone(), connection);
        self.registrations
            .insert(request.target_id, registration.clone());
        Ok(registration)
    }

    fn upsert_existing_registration(
        &mut self,
        request: RegistrationRequest,
        owner_identity: String,
        ipc_path_key: String,
        now: OffsetDateTime,
    ) -> RelayResult<TargetProcessRegistration> {
        let existing = self.registrations.get(&request.target_id).ok_or_else(|| {
            RelayError::for_target(
                "target_not_registered",
                "registration",
                request.target_id.clone(),
                "target is not registered",
                true,
            )
        })?;
        let path_changed = existing.ipc_path_key != ipc_path_key;
        let registered_at = existing.registered_at;
        let expires_at = now + Duration::seconds(request.lease_seconds as i64);
        let registration = TargetProcessRegistration {
            target_id: request.target_id.clone(),
            display_name: request.display_name,
            ipc_path: request.ipc_path.clone(),
            ipc_path_key,
            owner_identity,
            lease_seconds: request.lease_seconds,
            supported_commands: request.supported_commands,
            registered_at,
            renewed_at: now,
            expires_at,
            registration_state: RegistrationState::Active,
            last_rejection: None,
        };

        if let Some(connection) = self.connections.get_mut(&request.target_id) {
            connection.ipc_path = request.ipc_path;
            connection.updated_at = now;
            if path_changed {
                connection.state = ConnectionState::Reconnecting;
                connection.last_error = Some("ipc_path_changed".to_owned());
                connection.connected_at = None;
            }
        }
        self.registrations
            .insert(request.target_id.clone(), registration.clone());
        Ok(registration)
    }

    /// Renews one registered target.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The `now` parameter is the renewal time.
    /// The return value is empty when renewal succeeds.
    pub fn renew(&mut self, target_id: &str, now: OffsetDateTime) -> RelayResult<()> {
        let registration = self.registrations.get_mut(target_id).ok_or_else(|| {
            RelayError::for_target(
                "target_not_registered",
                "registration_renew",
                target_id,
                "target is not registered",
                true,
            )
        })?;
        registration.renewed_at = now;
        registration.expires_at = now + Duration::seconds(registration.lease_seconds as i64);
        registration.registration_state = RegistrationState::Active;
        Ok(())
    }

    /// Marks expired registrations.
    ///
    /// The `now` parameter is the current time.
    /// The return value is the number of targets marked expired by this call.
    pub fn expire_leases(&mut self, now: OffsetDateTime) -> usize {
        let mut expired = 0;
        for registration in self.registrations.values_mut() {
            if registration.registration_state == RegistrationState::Active
                && registration.expires_at <= now
            {
                registration.registration_state = RegistrationState::Expired;
                if let Some(connection) = self.connections.get_mut(&registration.target_id) {
                    connection.state = ConnectionState::Expired;
                    connection.updated_at = now;
                }
                expired += 1;
            }
        }
        expired
    }

    /// Returns the active registration count.
    ///
    /// The `now` parameter is the current time.
    /// The return value is the number of non-expired registrations whose state is active.
    pub fn active_registration_count(&self, now: OffsetDateTime) -> usize {
        self.registrations
            .values()
            .filter(|registration| {
                registration.registration_state == RegistrationState::Active
                    && registration.expires_at > now
            })
            .count()
    }

    /// Returns current active targets.
    ///
    /// The `now` parameter is the current time.
    /// The return value is the active target list automatically bound by the current session.
    pub fn active_targets(&self, now: OffsetDateTime) -> Vec<VisibleTarget> {
        self.registrations
            .values()
            .filter(|registration| {
                registration.registration_state == RegistrationState::Active
                    && registration.expires_at > now
            })
            .map(|registration| VisibleTarget {
                target_id: registration.target_id.clone(),
                display_name: registration.display_name.clone(),
                registration_state: registration.registration_state,
                connection_state: self
                    .connections
                    .get(&registration.target_id)
                    .map(|connection| connection.state)
                    .unwrap_or(ConnectionState::Unavailable),
                supported_commands: registration.supported_commands.clone(),
            })
            .collect()
    }

    /// Reads one active registration.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The return value is the target registration record, or a not-registered error.
    pub fn registration(&self, target_id: &str) -> RelayResult<&TargetProcessRegistration> {
        self.registrations.get(target_id).ok_or_else(|| {
            RelayError::for_target(
                "target_not_registered",
                "registry",
                target_id,
                "target is not registered",
                true,
            )
        })
    }

    /// Determines whether the target is active.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The `now` parameter is the current time.
    /// The return value is successful when the target is active.
    pub fn ensure_target_active(&self, target_id: &str, now: OffsetDateTime) -> RelayResult<()> {
        let registration = self.registration(target_id)?;
        if registration.registration_state != RegistrationState::Active
            || registration.expires_at <= now
        {
            return Err(RelayError::for_target(
                "target_unavailable",
                "registry",
                target_id,
                "target registration is not active",
                true,
            ));
        }

        Ok(())
    }

    /// Determines whether the target declares support for a command.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The `command` parameter is the control command name.
    /// The return value is successful when the command is supported.
    pub fn ensure_command_supported(
        &self,
        target_id: &str,
        command: ControlCommandName,
    ) -> RelayResult<()> {
        let registration = self.registration(target_id)?;
        let command_name = command.wire_name();
        if registration
            .supported_commands
            .iter()
            .any(|supported| supported.name == command_name)
        {
            return Ok(());
        }

        Err(RelayError::for_target(
            "unsupported_command",
            "command_validate",
            target_id,
            "target does not declare support for this command",
            false,
        ))
    }

    /// Marks that a target starts binding IPC.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The `now` parameter is the state change time.
    /// The return value is empty when the state change succeeds.
    pub fn begin_binding(&mut self, target_id: &str, now: OffsetDateTime) -> RelayResult<()> {
        let connection = self.connection_mut(target_id)?;
        connection.state = ConnectionState::Connecting;
        connection.updated_at = now;
        Ok(())
    }

    /// Marks target IPC as connected.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The `state_generation` parameter is the state generation read after connection.
    /// The `now` parameter is the state change time.
    /// The return value is empty when the state change succeeds.
    pub fn mark_connected(
        &mut self,
        target_id: &str,
        state_generation: u64,
        now: OffsetDateTime,
    ) -> RelayResult<()> {
        let connection = self.connection_mut(target_id)?;
        connection.state = ConnectionState::Connected;
        connection.last_state_generation = Some(state_generation);
        connection.connected_at = Some(now);
        connection.updated_at = now;
        connection.last_error = None;
        Ok(())
    }

    /// Marks target IPC as reconnecting.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The `reason` parameter is the reconnection reason.
    /// The `now` parameter is the state change time.
    /// The return value is empty when the state change succeeds.
    pub fn mark_reconnecting(
        &mut self,
        target_id: &str,
        reason: impl Into<String>,
        now: OffsetDateTime,
    ) {
        if let Ok(connection) = self.connection_mut(target_id) {
            connection.state = ConnectionState::Reconnecting;
            connection.last_error = Some(reason.into());
            connection.updated_at = now;
        }
    }

    /// Marks target IPC as unavailable.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The `reason` parameter is the unavailable reason.
    /// The `now` parameter is the state change time.
    pub fn mark_unavailable(
        &mut self,
        target_id: &str,
        reason: impl Into<String>,
        now: OffsetDateTime,
    ) {
        if let Ok(connection) = self.connection_mut(target_id) {
            connection.state = ConnectionState::Unavailable;
            connection.last_error = Some(reason.into());
            connection.updated_at = now;
        }
    }

    /// Reads the target connection state.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The return value is the connection state, or empty when the target does not exist.
    pub fn connection_state(&self, target_id: &str) -> Option<ConnectionState> {
        self.connections
            .get(target_id)
            .map(|connection| connection.state)
    }

    /// Summarizes partial availability state for all targets.
    ///
    /// This method has no parameters because it reads connection state from the registry.
    /// The return value is the connection state count summary.
    pub fn availability_summary(&self) -> AvailabilitySummary {
        let mut summary = AvailabilitySummary {
            total: self.connections.len(),
            ..AvailabilitySummary::default()
        };
        for connection in self.connections.values() {
            match connection.state {
                ConnectionState::Registered
                | ConnectionState::Disconnected
                | ConnectionState::Connecting => {
                    summary.registered += 1;
                }
                ConnectionState::Connected => summary.connected += 1,
                ConnectionState::Reconnecting => summary.reconnecting += 1,
                ConnectionState::Unavailable => summary.unavailable += 1,
                ConnectionState::Expired => summary.expired += 1,
            }
        }
        summary
    }

    /// Updates the latest received sequence for a target.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The `sequence` parameter is the event sequence.
    /// The return value is the previous sequence, or empty when no record exists.
    pub fn update_sequence(&mut self, target_id: &str, sequence: u64) -> Option<u64> {
        self.connections.get_mut(target_id).and_then(|connection| {
            let previous = connection.last_sequence;
            connection.last_sequence = Some(sequence);
            previous
        })
    }

    /// Validates a registration request.
    ///
    /// The `request` parameter is the registration payload submitted by the target process.
    /// The return value is empty when the registration payload satisfies the security policy.
    fn validate_request(&self, request: &RegistrationRequest) -> RelayResult<()> {
        if request.target_id.trim().is_empty() {
            return Err(RelayError::new(
                "empty_target_id",
                "registration",
                None,
                "target id must not be empty",
                false,
            ));
        }

        if !request.ipc_path.is_absolute() {
            return Err(RelayError::for_target(
                "relative_ipc_path",
                "registration",
                request.target_id.clone(),
                "IPC path must be absolute",
                false,
            ));
        }

        if !self.policy.ipc_path_is_allowed(&request.ipc_path) {
            return Err(RelayError::for_target(
                "ipc_path_not_allowed",
                "registration",
                request.target_id.clone(),
                "IPC path is outside allowed prefixes",
                false,
            ));
        }

        if request.lease_seconds == 0 || request.lease_seconds > self.policy.max_lease_seconds {
            return Err(RelayError::for_target(
                "invalid_lease_seconds",
                "registration",
                request.target_id.clone(),
                "lease seconds must be positive and must not exceed policy max",
                false,
            ));
        }

        for command in &request.supported_commands {
            if command.name.trim().is_empty() || command.timeout_seconds == 0 {
                return Err(RelayError::for_target(
                    "unsupported_command_schema",
                    "registration",
                    request.target_id.clone(),
                    "supported command name and timeout must be valid",
                    false,
                ));
            }
        }

        Ok(())
    }

    /// Reads a mutable connection record.
    ///
    /// The `target_id` parameter is the target process identifier.
    /// The return value is the mutable connection record, or a not-registered error.
    fn connection_mut(&mut self, target_id: &str) -> RelayResult<&mut TargetProcessConnection> {
        self.connections.get_mut(target_id).ok_or_else(|| {
            RelayError::for_target(
                "target_not_registered",
                "registry",
                target_id,
                "target connection is not registered",
                true,
            )
        })
    }
}

fn normalize_ipc_path_key(path: &Path) -> RelayResult<String> {
    if path
        .symlink_metadata()
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(RelayError::new(
            "invalid_ipc_path",
            "registration",
            None,
            "ipc path must not be a symlink",
            false,
        ));
    }

    let parent = path.parent().ok_or_else(|| {
        RelayError::new(
            "invalid_ipc_path",
            "registration",
            None,
            "ipc path must have a parent directory",
            false,
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        RelayError::new(
            "invalid_ipc_path",
            "registration",
            None,
            "ipc path must have a file name",
            false,
        )
    })?;
    let parent = parent.canonicalize().map_err(|error| {
        RelayError::new(
            "invalid_ipc_path",
            "registration",
            None,
            format!("ipc path parent could not be normalized: {error}"),
            false,
        )
    })?;

    Ok(parent.join(file_name).display().to_string())
}
