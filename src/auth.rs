//! The auth module converts mTLS and trusted-proxy inputs into `RemoteIdentity`.
//!
//! The relay only trusts verified client certificates or identity headers from configured trusted proxy addresses.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::config::TrustedProxyConfig;
use crate::error::{RelayError, RelayResult};

/// `IdentitySource` indicates whether the remote identity comes from mTLS or a trusted proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    /// `Mtls` indicates that the identity comes from a client certificate.
    Mtls,
    /// `TrustedProxy` indicates that the identity comes from a verified header passed by a trusted proxy.
    TrustedProxy,
}

/// `RemoteIdentity` stores an authenticated operator or service identity.
///
/// # Examples
///
/// ```
/// use rust_supervisor_relay::auth::RemoteIdentity;
/// use time::OffsetDateTime;
///
/// let identity = RemoteIdentity::from_verified_mtls_subject(
///     "CN=operator@example.test",
///     "CN=operators-ca",
///     "01",
///     OffsetDateTime::UNIX_EPOCH,
///     OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
///     OffsetDateTime::UNIX_EPOCH,
/// ).unwrap();
///
/// assert_eq!(identity.principal, "CN=operator@example.test");
/// assert!(identity.client_identity.starts_with("mtls_cert_fingerprint:"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteIdentity {
    /// `client_identity` is the stable client key derived by the relay.
    pub client_identity: String,
    /// `subject` is the certificate subject or the verified subject passed by the proxy.
    pub subject: String,
    /// `issuer` is the certificate issuer. Proxy mode uses the `trusted-proxy` marker.
    pub issuer: String,
    /// `serial_number` is the certificate serial number. Proxy mode uses a header summary.
    pub serial_number: String,
    /// `principal` is the operator or service identity derived by the relay.
    pub principal: String,
    /// `source` indicates the identity source.
    pub source: IdentitySource,
    /// `not_before` is the start of the identity validity window.
    pub not_before: OffsetDateTime,
    /// `not_after` is the end of the identity validity window.
    pub not_after: OffsetDateTime,
}

impl RemoteIdentity {
    /// Creates an identity from verified mTLS certificate fields.
    ///
    /// The `subject` parameter is the certificate subject.
    /// The `issuer` parameter is the certificate issuer.
    /// The `serial_number` parameter is the certificate serial number.
    /// The `not_before` parameter is the certificate validity start time.
    /// The `not_after` parameter is the certificate validity end time.
    /// The `now` parameter is the validation time.
    /// The return value is the `RemoteIdentity` usable for sessions and audits.
    pub fn from_verified_mtls_subject(
        subject: impl Into<String>,
        issuer: impl Into<String>,
        serial_number: impl Into<String>,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
        now: OffsetDateTime,
    ) -> RelayResult<Self> {
        let subject = subject.into();
        let issuer = issuer.into();
        let serial_number = serial_number.into();
        if subject.trim().is_empty() {
            return Err(RelayError::new(
                "empty_certificate_subject",
                "auth",
                None,
                "client certificate subject must not be empty",
                false,
            ));
        }

        if now < not_before || now > not_after {
            return Err(RelayError::new(
                "certificate_expired",
                "auth",
                None,
                "client certificate is outside its validity window",
                false,
            ));
        }

        Ok(Self {
            client_identity: fingerprint_identity_from_parts(
                subject.as_bytes(),
                issuer.as_bytes(),
                serial_number.as_bytes(),
            ),
            principal: subject.clone(),
            subject,
            issuer,
            serial_number,
            source: IdentitySource::Mtls,
            not_before,
            not_after,
        })
    }

    /// Creates an identity from a verified trusted-proxy header.
    ///
    /// The `subject` parameter is the verified subject asserted by the proxy.
    /// The `now` parameter is the creation time.
    /// The return value is the `RemoteIdentity` usable for sessions and audits.
    pub fn from_trusted_proxy_subject(
        subject: impl Into<String>,
        now: OffsetDateTime,
    ) -> RelayResult<Self> {
        let subject = subject.into();
        if subject.trim().is_empty() {
            return Err(RelayError::new(
                "empty_proxy_subject",
                "auth",
                None,
                "trusted proxy identity header must not be empty",
                false,
            ));
        }

        Ok(Self {
            client_identity: format!("trusted_proxy:{subject}"),
            principal: subject.clone(),
            subject,
            issuer: "trusted-proxy".to_owned(),
            serial_number: "trusted-proxy-header".to_owned(),
            source: IdentitySource::TrustedProxy,
            not_before: now,
            not_after: now + time::Duration::days(1),
        })
    }
}

/// `AuthContext` provides mTLS and trusted-proxy identity derivation functions.
pub struct AuthContext;

impl AuthContext {
    /// Parses an mTLS identity from DER certificate bytes.
    ///
    /// The `certificate_der` parameter contains the client certificate DER bytes.
    /// The `now` parameter is the validation time.
    /// The return value is the remote identity, or a structured certificate error.
    pub fn identity_from_mtls_der(
        certificate_der: &[u8],
        now: OffsetDateTime,
    ) -> RelayResult<RemoteIdentity> {
        if certificate_der.is_empty() {
            return Err(RelayError::new(
                "missing_client_certificate",
                "auth",
                None,
                "client certificate must be present for mTLS mode",
                false,
            ));
        }

        let (_, certificate) =
            x509_parser::parse_x509_certificate(certificate_der).map_err(|error| {
                RelayError::new(
                    "certificate_parse_failed",
                    "auth",
                    None,
                    format!("client certificate could not be parsed: {error}"),
                    false,
                )
            })?;

        let mut identity = RemoteIdentity::from_verified_mtls_subject(
            certificate.subject().to_string(),
            certificate.issuer().to_string(),
            certificate.raw_serial_as_string(),
            now - time::Duration::seconds(1),
            now + time::Duration::days(1),
            now,
        )?;
        identity.client_identity = fingerprint_identity(certificate_der);
        Ok(identity)
    }

    /// Derives a remote identity from a trusted-proxy connection.
    ///
    /// The `config` parameter is the trusted-proxy configuration.
    /// The `remote_addr` parameter is the actual connection source IP address.
    /// The `headers` parameter contains the HTTP headers passed by the proxy.
    /// The `now` parameter is the creation time.
    /// The return value is the remote identity, or a structured trust-boundary error.
    pub fn identity_from_trusted_proxy(
        config: &TrustedProxyConfig,
        remote_addr: IpAddr,
        headers: &HashMap<String, String>,
        now: OffsetDateTime,
    ) -> RelayResult<RemoteIdentity> {
        if !config.enabled {
            return Err(RelayError::new(
                "trusted_proxy_disabled",
                "auth",
                None,
                "trusted proxy mode is disabled",
                false,
            ));
        }

        if !config.is_allowed_remote_addr(remote_addr) {
            return Err(RelayError::new(
                "untrusted_proxy",
                "auth",
                None,
                "identity header came from an untrusted remote address",
                false,
            ));
        }

        let header_key = config.identity_header.to_ascii_lowercase();
        let subject = headers
            .iter()
            .find(|(key, _)| key.to_ascii_lowercase() == header_key)
            .map(|(_, value)| value.trim().to_owned())
            .ok_or_else(|| {
                RelayError::new(
                    "missing_proxy_identity",
                    "auth",
                    None,
                    "trusted proxy identity header is missing",
                    false,
                )
            })?;

        RemoteIdentity::from_trusted_proxy_subject(subject, now)
    }
}

fn fingerprint_identity(certificate_der: &[u8]) -> String {
    let digest = Sha256::digest(certificate_der);
    format!("mtls_cert_fingerprint:{}", lowercase_hex(&digest))
}

fn fingerprint_identity_from_parts(subject: &[u8], issuer: &[u8], serial: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(subject);
    hasher.update([0]);
    hasher.update(issuer);
    hasher.update([0]);
    hasher.update(serial);
    let digest = hasher.finalize();
    format!("mtls_cert_fingerprint:{}", lowercase_hex(&digest))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
