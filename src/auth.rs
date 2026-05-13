//! auth(认证) 模块把 mTLS(双向传输层安全协议认证) 和 trusted proxy(可信代理) 输入转换为 RemoteIdentity(远程身份).
//!
//! relay(中继) 只信任已经验证的客户端证书, 或者来自配置内可信代理地址的身份 header(标头).

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::config::TrustedProxyConfig;
use crate::error::{RelayError, RelayResult};

/// `IdentitySource`(身份来源) 表示远程身份来自 mTLS(双向传输层安全协议认证) 还是 trusted proxy(可信代理).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySource {
    /// `Mtls`(双向传输层安全协议认证) 表示身份来自客户端证书.
    Mtls,
    /// `TrustedProxy`(可信代理) 表示身份来自可信代理传入的已验证 header(标头).
    TrustedProxy,
}

/// `RemoteIdentity`(远程身份) 保存已认证操作者或服务身份.
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
    /// `client_identity`(客户端身份) 是 relay(中继) 派生的稳定客户端键.
    pub client_identity: String,
    /// `subject`(主体) 是证书主体或代理传入的已验证主体.
    pub subject: String,
    /// `issuer`(签发者) 是证书签发者, 代理模式使用 trusted-proxy(可信代理) 标记.
    pub issuer: String,
    /// `serial_number`(序列号) 是证书序列号, 代理模式使用 header(标头) 摘要.
    pub serial_number: String,
    /// `principal`(主体身份) 是 relay(中继) 派生的操作者或服务身份.
    pub principal: String,
    /// `source`(来源) 表示身份来源.
    pub source: IdentitySource,
    /// `not_before`(生效时间) 是身份有效期开始时间.
    pub not_before: OffsetDateTime,
    /// `not_after`(失效时间) 是身份有效期结束时间.
    pub not_after: OffsetDateTime,
}

impl RemoteIdentity {
    /// 从已经验证的 mTLS(双向传输层安全协议认证) 证书字段创建身份.
    ///
    /// 参数 `subject` 是证书主体.
    /// 参数 `issuer` 是证书签发者.
    /// 参数 `serial_number` 是证书序列号.
    /// 参数 `not_before` 是证书生效时间.
    /// 参数 `not_after` 是证书失效时间.
    /// 参数 `now` 是校验时间.
    /// 返回值是可用于会话和审计的 `RemoteIdentity`(远程身份).
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

    /// 从 trusted proxy(可信代理) 已验证 header(标头) 创建身份.
    ///
    /// 参数 `subject` 是代理声明已验证的主体.
    /// 参数 `now` 是创建时间.
    /// 返回值是可用于会话和审计的 `RemoteIdentity`(远程身份).
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

/// `AuthContext`(认证上下文) 提供 mTLS(双向传输层安全协议认证) 和 trusted proxy(可信代理) 身份派生函数.
pub struct AuthContext;

impl AuthContext {
    /// 从 DER(可分辨编码规则) 证书字节解析 mTLS(双向传输层安全协议认证) 身份.
    ///
    /// 参数 `certificate_der` 是客户端证书 DER(可分辨编码规则) 字节.
    /// 参数 `now` 是校验时间.
    /// 返回值是远程身份, 或者结构化证书错误.
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

    /// 从 trusted proxy(可信代理) 连接派生远程身份.
    ///
    /// 参数 `config` 是可信代理配置.
    /// 参数 `remote_addr` 是实际连接来源 IP(网际协议地址).
    /// 参数 `headers` 是代理传入的 HTTP(超文本传输协议) header(标头).
    /// 参数 `now` 是创建时间.
    /// 返回值是远程身份, 或者结构化信任边界错误.
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
