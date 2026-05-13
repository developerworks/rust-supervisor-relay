//! The registration module defines runtime registration payloads submitted by target processes to the relay.
//!
//! A target process can submit dynamic registration in this module's format after local IPC is ready.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::config::RegistrationPolicy;
use crate::error::{RelayError, RelayResult};

/// `SupportedCommand` describes a command that a target can execute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportedCommand {
    /// `name` is the wire command name.
    pub name: String,
    /// `idempotent` indicates whether the command allows automatic retry or identifier reuse.
    pub idempotent: bool,
    /// `timeout_seconds` is the time the relay waits for the command result.
    pub timeout_seconds: u64,
}

impl SupportedCommand {
    /// Creates a supported command declaration.
    ///
    /// The `name` parameter is the wire command name.
    /// The `idempotent` parameter indicates whether the command is idempotent.
    /// The `timeout_seconds` parameter is the command timeout in seconds.
    /// The return value is the `SupportedCommand`.
    pub fn new(name: impl Into<String>, idempotent: bool, timeout_seconds: u64) -> Self {
        Self {
            name: name.into(),
            idempotent,
            timeout_seconds,
        }
    }
}

/// `RegistrationRequest` represents the runtime registration payload for one target process.
///
/// # Examples
///
/// ```
/// use rust_supervisor_relay::registration::RegistrationRequest;
///
/// let request = RegistrationRequest::new(
///     "payments-worker-a",
///     "payments worker a",
///     "/run/rust-supervisor/payments-worker-a.sock",
///     30,
///     Vec::new(),
/// );
///
/// assert_eq!(request.target_id, "payments-worker-a");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    /// `target_id` is the stable target process identity.
    pub target_id: String,
    /// `display_name` is the name that the dashboard shows to operators.
    pub display_name: String,
    /// `ipc_path` is the Unix domain socket path already opened by the target process.
    pub ipc_path: PathBuf,
    /// `lease_seconds` is the validity window for this registration.
    pub lease_seconds: u64,
    /// `supported_commands` is the command set that the target declares as executable.
    pub supported_commands: Vec<SupportedCommand>,
}

impl RegistrationRequest {
    /// Creates a target process registration request.
    ///
    /// The `target_id` parameter is the stable target process identity.
    /// The `display_name` parameter is the dashboard display name.
    /// The `ipc_path` parameter is the target process local IPC path.
    /// The `lease_seconds` parameter is the registration lease duration in seconds.
    /// The `supported_commands` parameter is the command set supported by the target.
    /// The return value is the `RegistrationRequest`.
    pub fn new(
        target_id: impl Into<String>,
        display_name: impl Into<String>,
        ipc_path: impl Into<PathBuf>,
        lease_seconds: u64,
        supported_commands: Vec<SupportedCommand>,
    ) -> Self {
        Self {
            target_id: target_id.into(),
            display_name: display_name.into(),
            ipc_path: ipc_path.into(),
            lease_seconds,
            supported_commands,
        }
    }
}

/// Decodes a registration request from newline-delimited JSON.
///
/// The `line` parameter is one line of JSON text.
/// The return value is the registration request, or a structured parse error.
pub fn decode_registration_line(line: &str) -> RelayResult<RegistrationRequest> {
    serde_json::from_str(line).map_err(|error| {
        RelayError::new(
            "invalid_registration_json",
            "registration_parse",
            None,
            format!("registration line could not be parsed: {error}"),
            false,
        )
    })
}

/// `RegistrationListener` receives dynamic registrations from target processes.
pub struct RegistrationListener {
    /// `listener` is the local Unix domain socket listener.
    listener: UnixListener,
}

/// `AcceptedRegistration` stores the registration payload and local submitter identity.
pub struct AcceptedRegistration {
    /// `request` is the registration declaration submitted by the target process.
    pub request: RegistrationRequest,
    /// `owner_identity` is derived from the Unix peer credential.
    pub owner_identity: String,
    /// `stream` is used to write the registration acknowledgement.
    pub stream: UnixStream,
}

impl RegistrationListener {
    /// Binds the registration entry point at the path specified by the registration policy.
    ///
    /// The `policy` parameter is the registration policy.
    /// The return value is the bound `RegistrationListener`.
    pub async fn bind(policy: &RegistrationPolicy) -> RelayResult<Self> {
        if policy.listen_path.exists() {
            std::fs::remove_file(&policy.listen_path).map_err(|error| {
                RelayError::new(
                    "registration_socket_remove_failed",
                    "registration_bind",
                    None,
                    format!("old registration socket could not be removed: {error}"),
                    true,
                )
            })?;
        }

        let listener = UnixListener::bind(&policy.listen_path).map_err(|error| {
            RelayError::new(
                "registration_bind_failed",
                "registration_bind",
                None,
                format!("registration socket could not be bound: {error}"),
                true,
            )
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(mode) = u32::from_str_radix(policy.permissions.trim_start_matches('0'), 8) {
                let _ = std::fs::set_permissions(
                    &policy.listen_path,
                    std::fs::Permissions::from_mode(mode),
                );
            }
        }

        Ok(Self { listener })
    }

    /// Accepts one registration request.
    ///
    /// This method has no parameters because the listener already stores the registration entry point.
    /// The return value is the next `RegistrationRequest`.
    pub async fn accept_once(&self) -> RelayResult<RegistrationRequest> {
        let (stream, _) = self.listener.accept().await.map_err(|error| {
            RelayError::new(
                "registration_accept_failed",
                "registration_accept",
                None,
                format!("registration connection could not be accepted: {error}"),
                true,
            )
        })?;
        read_registration_from_stream(stream).await
    }

    /// Accepts one registration request and preserves the response stream.
    ///
    /// This method has no parameters because the listener already stores the registration entry point.
    /// The return value is the registration request, local owner identity, and response stream.
    pub async fn accept_registration(&self) -> RelayResult<AcceptedRegistration> {
        let (stream, _) = self.listener.accept().await.map_err(|error| {
            RelayError::new(
                "registration_accept_failed",
                "registration_accept",
                None,
                format!("registration connection could not be accepted: {error}"),
                true,
            )
        })?;
        let owner_identity = owner_identity_from_stream(&stream);
        let (request, stream) = read_registration_request_and_stream(stream).await?;
        Ok(AcceptedRegistration {
            request,
            owner_identity,
            stream,
        })
    }
}

/// Reads one registration request from a `UnixStream`.
///
/// The `stream` parameter is the local connection where the target process writes registration JSON.
/// The return value is the decoded registration request.
pub async fn read_registration_from_stream(stream: UnixStream) -> RelayResult<RegistrationRequest> {
    read_registration_request_and_stream(stream)
        .await
        .map(|(request, _)| request)
}

async fn read_registration_request_and_stream(
    stream: UnixStream,
) -> RelayResult<(RegistrationRequest, UnixStream)> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.map_err(|error| {
        RelayError::new(
            "registration_read_failed",
            "registration_accept",
            None,
            format!("registration line could not be read: {error}"),
            true,
        )
    })?;
    let request = decode_registration_line(line.trim())?;
    Ok((request, reader.into_inner()))
}

fn owner_identity_from_stream(stream: &UnixStream) -> String {
    #[cfg(unix)]
    {
        if let Ok(credential) = stream.peer_cred() {
            return format!("unix_uid:{}", credential.uid());
        }
    }
    "unix_uid:unknown".to_owned()
}
