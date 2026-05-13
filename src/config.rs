//! The config module defines the relay YAML input and security validation.
//!
//! Relay configuration only describes `wss://` listening, mTLS, trusted proxy,
//! registration entry points, and lease rules. Target process lists must enter runtime through dynamic registration.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{RelayError, RelayResult};

/// `DashboardRelayConfig` is the root relay configuration.
///
/// # Examples
///
/// ```
/// use rust_supervisor_relay::config::DashboardRelayConfig;
///
/// let yaml = r#"
/// listen:
///   bind: "127.0.0.1:9443"
///   public_url: "wss://localhost:9443/supervisor"
/// tls:
///   certificate_path: "./certs/relay.crt"
///   private_key_path: "./certs/relay.key"
///   client_ca_path: "./certs/operators-ca.crt"
/// trusted_proxy:
///   enabled: false
///   allowed_remote_addrs: []
///   identity_header: "x-verified-client-subject"
/// registration:
///   listen_path: /run/rust-supervisor/dashboard-relay-registration.sock
///   permissions: "0600"
///   allowed_ipc_path_prefixes:
///     - /run/rust-supervisor/
///   default_lease_seconds: 30
///   max_lease_seconds: 120
/// "#;
///
/// let config = DashboardRelayConfig::from_yaml_str(yaml).unwrap();
/// assert!(config.validate().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardRelayConfig {
    /// `listen` stores the external `wss://` address.
    pub listen: ListenConfig,
    /// `tls` stores the server certificate and client certificate trust root.
    pub tls: TlsConfig,
    /// `trusted_proxy` stores identity source rules when a proxy terminates TLS.
    pub trusted_proxy: TrustedProxyConfig,
    /// `registration` stores the target process registration entry point and lease policy.
    pub registration: RegistrationPolicy,
}

impl DashboardRelayConfig {
    /// Reads relay configuration from a YAML string.
    ///
    /// The `yaml` parameter is the full configuration text.
    /// The return value is the parsed `DashboardRelayConfig`, or a structured parse error.
    pub fn from_yaml_str(yaml: &str) -> RelayResult<Self> {
        serde_yaml::from_str(yaml).map_err(|error| {
            RelayError::new(
                "invalid_config_yaml",
                "config_parse",
                None,
                format!("relay config yaml could not be parsed: {error}"),
                false,
            )
        })
    }

    /// Reads relay configuration from the file system.
    ///
    /// The `path` parameter is the configuration file path.
    /// The return value is the parsed `DashboardRelayConfig`, or a structured read error.
    pub fn load_from_path(path: &Path) -> RelayResult<Self> {
        let yaml = std::fs::read_to_string(path).map_err(|error| {
            RelayError::new(
                "config_read_failed",
                "config_parse",
                None,
                format!("relay config could not be read: {error}"),
                false,
            )
        })?;
        Self::from_yaml_str(&yaml)
    }

    /// Validates the security shape of relay configuration.
    ///
    /// This method has no parameters because validation only reads the current configuration object.
    /// The return value is successful when configuration satisfies `wss://`, mTLS, trusted-proxy, and registration rules.
    pub fn validate(&self) -> RelayResult<()> {
        self.listen.validate()?;
        self.trusted_proxy.validate()?;
        self.tls.validate(self.trusted_proxy.enabled)?;
        self.registration.validate_policy()?;
        Ok(())
    }
}

/// `ListenConfig` stores the relay network bind address and public address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    /// `bind` is the local listening address.
    pub bind: String,
    /// `public_url` must use `wss://`.
    pub public_url: String,
}

impl ListenConfig {
    /// Validates the listen configuration.
    ///
    /// This method has no parameters because validation only reads the current listen configuration.
    /// The return value is successful when the address can be parsed and the public address uses `wss://`.
    pub fn validate(&self) -> RelayResult<()> {
        self.bind.parse::<SocketAddr>().map_err(|error| {
            RelayError::new(
                "invalid_bind_address",
                "config",
                None,
                format!("listen.bind must be socket address: {error}"),
                false,
            )
        })?;

        let url = Url::parse(&self.public_url).map_err(|error| {
            RelayError::new(
                "invalid_public_url",
                "config",
                None,
                format!("listen.public_url could not be parsed: {error}"),
                false,
            )
        })?;

        if url.scheme() != "wss" {
            return Err(RelayError::new(
                "invalid_public_url",
                "config",
                None,
                "listen.public_url must use wss://",
                false,
            ));
        }

        Ok(())
    }
}

/// `TlsConfig` stores relay certificate paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// `certificate_path` points to the relay server certificate.
    pub certificate_path: PathBuf,
    /// `private_key_path` points to the relay server private key.
    pub private_key_path: PathBuf,
    /// `client_ca_path` points to the certificate authority that verifies operator certificates.
    pub client_ca_path: PathBuf,
}

impl TlsConfig {
    /// Validates the TLS configuration shape.
    ///
    /// The `trusted_proxy_enabled` parameter indicates whether a trusted proxy provides verified identity.
    /// The return value is successful when certificate fields satisfy mTLS or trusted-proxy rules.
    pub fn validate(&self, trusted_proxy_enabled: bool) -> RelayResult<()> {
        if self.certificate_path.as_os_str().is_empty()
            || self.private_key_path.as_os_str().is_empty()
        {
            return Err(RelayError::new(
                "missing_tls_identity",
                "config",
                None,
                "tls.certificate_path and tls.private_key_path must be configured",
                false,
            ));
        }

        if !trusted_proxy_enabled && self.client_ca_path.as_os_str().is_empty() {
            return Err(RelayError::new(
                "missing_client_ca",
                "config",
                None,
                "tls.client_ca_path must be configured when trusted proxy mode is disabled",
                false,
            ));
        }

        Ok(())
    }
}

/// `TrustedProxyConfig` stores the trust boundary for proxy identity headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedProxyConfig {
    /// `enabled` indicates whether the relay accepts verified identities passed by the proxy.
    pub enabled: bool,
    /// `allowed_remote_addrs` contains proxy IP addresses allowed to provide identity headers.
    pub allowed_remote_addrs: Vec<String>,
    /// `identity_header` is the HTTP header where the proxy writes the verified subject.
    pub identity_header: String,
}

impl TrustedProxyConfig {
    /// Validates trusted-proxy configuration.
    ///
    /// This method has no parameters because validation only reads the current proxy configuration.
    /// The return value is successful when addresses and identity headers are valid while proxy mode is enabled.
    pub fn validate(&self) -> RelayResult<()> {
        if !self.enabled {
            return Ok(());
        }

        if self.allowed_remote_addrs.is_empty() {
            return Err(RelayError::new(
                "empty_trusted_proxy_addrs",
                "config",
                None,
                "trusted_proxy.allowed_remote_addrs must not be empty when trusted proxy mode is enabled",
                false,
            ));
        }

        for addr in &self.allowed_remote_addrs {
            addr.parse::<IpAddr>().map_err(|error| {
                RelayError::new(
                    "invalid_trusted_proxy_addr",
                    "config",
                    None,
                    format!("trusted proxy address could not be parsed: {error}"),
                    false,
                )
            })?;
        }

        if self.identity_header.trim().is_empty() {
            return Err(RelayError::new(
                "empty_identity_header",
                "config",
                None,
                "trusted_proxy.identity_header must not be empty",
                false,
            ));
        }

        Ok(())
    }

    /// Determines whether the remote address is a trusted proxy.
    ///
    /// The `remote_addr` parameter is the connection source IP address.
    /// The return value indicates whether the address is in the allow list.
    pub fn is_allowed_remote_addr(&self, remote_addr: IpAddr) -> bool {
        self.enabled
            && self
                .allowed_remote_addrs
                .iter()
                .filter_map(|addr| addr.parse::<IpAddr>().ok())
                .any(|allowed| allowed == remote_addr)
    }
}

/// `RegistrationPolicy` stores the local entry point and lease rules for target process dynamic registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationPolicy {
    /// `listen_path` is the Unix domain socket where target processes submit registration.
    pub listen_path: PathBuf,
    /// `permissions` is the registration socket file mode.
    pub permissions: String,
    /// `allowed_ipc_path_prefixes` limits target IPC paths to local safe directories.
    pub allowed_ipc_path_prefixes: Vec<PathBuf>,
    /// `default_lease_seconds` is the default lease when a target does not override it.
    pub default_lease_seconds: u64,
    /// `max_lease_seconds` is the longest registration lease accepted by the relay.
    pub max_lease_seconds: u64,
}

impl RegistrationPolicy {
    /// Validates the security shape of the registration policy itself.
    ///
    /// This method has no parameters because validation only reads the current registration policy.
    /// The return value is successful when the registration entry point and IPC path prefixes are valid.
    pub fn validate_policy(&self) -> RelayResult<()> {
        if !self.listen_path.is_absolute() {
            return Err(RelayError::new(
                "relative_registration_path",
                "config",
                None,
                "registration.listen_path must be absolute",
                false,
            ));
        }

        if self.allowed_ipc_path_prefixes.is_empty() {
            return Err(RelayError::new(
                "empty_allowed_ipc_path_prefixes",
                "config",
                None,
                "registration.allowed_ipc_path_prefixes must not be empty",
                false,
            ));
        }

        if self
            .allowed_ipc_path_prefixes
            .iter()
            .any(|path| !path.is_absolute())
        {
            return Err(RelayError::new(
                "relative_allowed_ipc_path_prefix",
                "config",
                None,
                "each allowed IPC path prefix must be absolute",
                false,
            ));
        }

        if self.default_lease_seconds == 0
            || self.max_lease_seconds == 0
            || self.default_lease_seconds > self.max_lease_seconds
        {
            return Err(RelayError::new(
                "invalid_registration_lease_policy",
                "config",
                None,
                "registration lease values must be positive and default must not exceed max",
                false,
            ));
        }

        Ok(())
    }

    /// Determines whether the target IPC path is inside the allowed prefixes.
    ///
    /// The `ipc_path` parameter is the local path reported by target process registration.
    /// The return value indicates whether the path is allowed by the registration policy.
    pub fn ipc_path_is_allowed(&self, ipc_path: &Path) -> bool {
        ipc_path.is_absolute()
            && self
                .allowed_ipc_path_prefixes
                .iter()
                .any(|prefix| ipc_path.starts_with(prefix))
    }
}
