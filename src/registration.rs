//! registration(注册) 模块定义目标进程提交给 relay(中继) 的运行时注册载荷.
//!
//! 目标进程完成本机 IPC(进程间通信) 就绪后, 才能通过本模块的格式提交 dynamic registration(动态注册).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::config::RegistrationPolicy;
use crate::error::{RelayError, RelayResult};

/// `RegistrationRequest`(注册请求) 表达一个目标进程的运行时注册载荷.
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
///     "payments:operate",
///     30,
/// );
///
/// assert_eq!(request.target_id, "payments-worker-a");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    /// `target_id`(目标标识) 是目标进程稳定身份.
    pub target_id: String,
    /// `display_name`(显示名称) 是 dashboard(看板) 展示给操作者的名称.
    pub display_name: String,
    /// `ipc_path`(进程间通信路径) 是目标进程已经打开的 Unix domain socket(Unix 域套接字) 路径.
    pub ipc_path: PathBuf,
    /// `authorization_scope`(授权范围) 是远程身份访问该目标需要具备的 scope(授权范围).
    pub authorization_scope: String,
    /// `lease_seconds`(租约秒数) 是本次注册的有效时间.
    pub lease_seconds: u64,
}

impl RegistrationRequest {
    /// 创建一个目标进程注册请求.
    ///
    /// 参数 `target_id` 是目标进程稳定身份.
    /// 参数 `display_name` 是 dashboard(看板) 显示名称.
    /// 参数 `ipc_path` 是目标进程本机 IPC path(进程间通信路径).
    /// 参数 `authorization_scope` 是访问该目标需要的授权范围.
    /// 参数 `lease_seconds` 是注册租约秒数.
    /// 返回值是 `RegistrationRequest`(注册请求).
    pub fn new(
        target_id: impl Into<String>,
        display_name: impl Into<String>,
        ipc_path: impl Into<PathBuf>,
        authorization_scope: impl Into<String>,
        lease_seconds: u64,
    ) -> Self {
        Self {
            target_id: target_id.into(),
            display_name: display_name.into(),
            ipc_path: ipc_path.into(),
            authorization_scope: authorization_scope.into(),
            lease_seconds,
        }
    }
}

/// 从 newline-delimited JSON(按行分隔的 JSON 数据) 解析注册请求.
///
/// 参数 `line` 是单行 JSON(数据交换格式) 文本.
/// 返回值是注册请求, 或者结构化解析错误.
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

/// `RegistrationListener`(注册监听器) 接收目标进程 dynamic registration(动态注册).
pub struct RegistrationListener {
    /// `listener`(监听器) 是本机 Unix domain socket(Unix 域套接字) 监听对象.
    listener: UnixListener,
}

impl RegistrationListener {
    /// 在注册策略指定的路径上绑定注册入口.
    ///
    /// 参数 `policy` 是注册策略.
    /// 返回值是已经绑定的 `RegistrationListener`(注册监听器).
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

    /// 接收一个注册请求.
    ///
    /// 参数为空, 因为监听器已经保存注册入口.
    /// 返回值是下一条 `RegistrationRequest`(注册请求).
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
}

/// 从 UnixStream(Unix 流) 读取一条注册请求.
///
/// 参数 `stream` 是目标进程写入注册 JSON(数据交换格式) 的本机连接.
/// 返回值是解析后的注册请求.
pub async fn read_registration_from_stream(stream: UnixStream) -> RelayResult<RegistrationRequest> {
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
    decode_registration_line(line.trim())
}
