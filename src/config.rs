//! config(配置) 模块定义 relay(中继) 的 YAML(配置文件格式) 输入和安全校验.
//!
//! relay(中继) 配置只描述 `wss://` 监听, mTLS(双向传输层安全协议认证), trusted proxy(可信代理),
//! registration(注册) 入口和租约规则. 目标进程列表必须通过 dynamic registration(动态注册) 进入运行时.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{RelayError, RelayResult};

/// `DashboardRelayConfig`(看板中继配置) 是 relay(中继) 的根配置.
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
    /// `listen`(监听) 保存对外 `wss://` 地址.
    pub listen: ListenConfig,
    /// `tls`(传输层安全协议) 保存服务端证书和客户端证书信任根.
    pub tls: TlsConfig,
    /// `trusted_proxy`(可信代理) 保存代理终止 TLS(传输层安全协议) 时的身份来源规则.
    pub trusted_proxy: TrustedProxyConfig,
    /// `registration`(注册) 保存目标进程注册入口和租约策略.
    pub registration: RegistrationPolicy,
}

impl DashboardRelayConfig {
    /// 从 YAML(配置文件格式) 字符串读取 relay(中继) 配置.
    ///
    /// 参数 `yaml` 是完整配置文本.
    /// 返回值是解析后的 `DashboardRelayConfig`(看板中继配置), 或者结构化解析错误.
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

    /// 从文件系统读取 relay(中继) 配置.
    ///
    /// 参数 `path` 是配置文件路径.
    /// 返回值是解析后的 `DashboardRelayConfig`(看板中继配置), 或者结构化读取错误.
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

    /// 校验 relay(中继) 配置的安全形状.
    ///
    /// 参数为空, 因为校验只读取当前配置对象.
    /// 返回值在配置满足 `wss://`, mTLS(双向传输层安全协议认证), trusted proxy(可信代理) 和注册规则时为成功.
    pub fn validate(&self) -> RelayResult<()> {
        self.listen.validate()?;
        self.trusted_proxy.validate()?;
        self.tls.validate(self.trusted_proxy.enabled)?;
        self.registration.validate_policy()?;
        Ok(())
    }
}

/// `ListenConfig`(监听配置) 保存 relay(中继) 的网络监听地址和公开地址.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    /// `bind`(绑定地址) 是本机监听地址.
    pub bind: String,
    /// `public_url`(公开地址) 必须使用 `wss://`.
    pub public_url: String,
}

impl ListenConfig {
    /// 校验监听配置.
    ///
    /// 参数为空, 因为校验只读取当前监听配置.
    /// 返回值在地址可解析且公开地址使用 `wss://` 时为成功.
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

/// `TlsConfig`(传输层安全协议配置) 保存 relay(中继) 的证书路径.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// `certificate_path`(证书路径) 指向 relay(中继) 服务端证书.
    pub certificate_path: PathBuf,
    /// `private_key_path`(私钥路径) 指向 relay(中继) 服务端私钥.
    pub private_key_path: PathBuf,
    /// `client_ca_path`(客户端证书根路径) 指向可验证操作者证书的 CA(证书颁发机构).
    pub client_ca_path: PathBuf,
}

impl TlsConfig {
    /// 校验 TLS(传输层安全协议) 配置的形状.
    ///
    /// 参数 `trusted_proxy_enabled` 表示是否由可信代理提供已验证身份.
    /// 返回值在证书字段满足 mTLS(双向传输层安全协议认证) 或可信代理规则时为成功.
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

/// `TrustedProxyConfig`(可信代理配置) 保存代理身份头的信任边界.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedProxyConfig {
    /// `enabled`(是否启用) 表示 relay(中继) 是否接受代理传入的已验证身份.
    pub enabled: bool,
    /// `allowed_remote_addrs`(允许的远端地址) 是可以提供身份头的代理 IP(网际协议地址).
    pub allowed_remote_addrs: Vec<String>,
    /// `identity_header`(身份头) 是代理写入已验证主体的 HTTP(超文本传输协议) header(标头).
    pub identity_header: String,
}

impl TrustedProxyConfig {
    /// 校验 trusted proxy(可信代理) 配置.
    ///
    /// 参数为空, 因为校验只读取当前代理配置.
    /// 返回值在启用代理时地址和身份头都有效时为成功.
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

    /// 判断远端地址是否是受信任代理.
    ///
    /// 参数 `remote_addr` 是连接来源 IP(网际协议地址).
    /// 返回值表示该地址是否在允许列表中.
    pub fn is_allowed_remote_addr(&self, remote_addr: IpAddr) -> bool {
        self.enabled
            && self
                .allowed_remote_addrs
                .iter()
                .filter_map(|addr| addr.parse::<IpAddr>().ok())
                .any(|allowed| allowed == remote_addr)
    }
}

/// `RegistrationPolicy`(注册策略) 保存目标进程 dynamic registration(动态注册) 的本机入口和租约规则.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationPolicy {
    /// `listen_path`(监听路径) 是目标进程提交注册的 Unix domain socket(Unix 域套接字).
    pub listen_path: PathBuf,
    /// `permissions`(权限) 是注册 socket(套接字) 文件权限.
    pub permissions: String,
    /// `allowed_ipc_path_prefixes`(允许的进程间通信路径前缀) 限制目标 IPC(进程间通信) 路径只能位于本机安全目录.
    pub allowed_ipc_path_prefixes: Vec<PathBuf>,
    /// `default_lease_seconds`(默认租约秒数) 是目标未覆盖租约时的默认值.
    pub default_lease_seconds: u64,
    /// `max_lease_seconds`(最大租约秒数) 是 relay(中继) 接受的最长注册租约.
    pub max_lease_seconds: u64,
}

impl RegistrationPolicy {
    /// 校验注册策略自身的安全形状.
    ///
    /// 参数为空, 因为校验只读取当前注册策略.
    /// 返回值在注册入口和 IPC(进程间通信) 路径前缀有效时为成功.
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

    /// 判断目标 IPC path(进程间通信路径) 是否位于允许前缀中.
    ///
    /// 参数 `ipc_path` 是目标进程注册上报的本机路径.
    /// 返回值表示路径是否被注册策略允许.
    pub fn ipc_path_is_allowed(&self, ipc_path: &Path) -> bool {
        ipc_path.is_absolute()
            && self
                .allowed_ipc_path_prefixes
                .iter()
                .any(|prefix| ipc_path.starts_with(prefix))
    }
}
