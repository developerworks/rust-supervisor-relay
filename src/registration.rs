//! registration(注册) 模块定义目标进程提交给 relay(中继) 的运行时注册载荷.
//!
//! 目标进程完成本机 IPC(进程间通信) 就绪后, 才能通过本模块的格式提交 dynamic registration(动态注册).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::config::RegistrationPolicy;
use crate::error::{RelayError, RelayResult};

/// `SupportedCommand`(支持的命令) 描述 target(目标) 可以执行的命令.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportedCommand {
    /// `name`(名称) 是 wire(传输层) 命令名称.
    pub name: String,
    /// `idempotent`(幂等) 表示命令是否允许自动重试或复用标识.
    pub idempotent: bool,
    /// `timeout_seconds`(超时秒数) 是 relay(中继) 等待命令结果的时间.
    pub timeout_seconds: u64,
}

impl SupportedCommand {
    /// 创建一个支持命令声明.
    ///
    /// 参数 `name` 是 wire(传输层) 命令名称.
    /// 参数 `idempotent` 表示命令是否幂等.
    /// 参数 `timeout_seconds` 是命令超时秒数.
    /// 返回值是 `SupportedCommand`(支持的命令).
    pub fn new(name: impl Into<String>, idempotent: bool, timeout_seconds: u64) -> Self {
        Self {
            name: name.into(),
            idempotent,
            timeout_seconds,
        }
    }
}

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
///     30,
///     Vec::new(),
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
    /// `lease_seconds`(租约秒数) 是本次注册的有效时间.
    pub lease_seconds: u64,
    /// `supported_commands`(支持的命令) 是 target(目标) 声明可执行的命令集合.
    pub supported_commands: Vec<SupportedCommand>,
}

impl RegistrationRequest {
    /// 创建一个目标进程注册请求.
    ///
    /// 参数 `target_id` 是目标进程稳定身份.
    /// 参数 `display_name` 是 dashboard(看板) 显示名称.
    /// 参数 `ipc_path` 是目标进程本机 IPC path(进程间通信路径).
    /// 参数 `lease_seconds` 是注册租约秒数.
    /// 参数 `supported_commands` 是 target(目标) 支持的命令.
    /// 返回值是 `RegistrationRequest`(注册请求).
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

/// `AcceptedRegistration`(已接收注册) 保存注册载荷和本机提交者身份.
pub struct AcceptedRegistration {
    /// `request`(请求) 是目标进程提交的注册声明.
    pub request: RegistrationRequest,
    /// `owner_identity`(所有者身份) 是 Unix peer credential(Unix 对端凭据) 派生值.
    pub owner_identity: String,
    /// `stream`(流) 用于写回 registration ack(注册确认响应).
    pub stream: UnixStream,
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

    /// 接收一个注册请求并保留响应 stream(流).
    ///
    /// 参数为空, 因为监听器已经保存注册入口.
    /// 返回值是注册请求, 本机 owner identity(所有者身份) 和响应流.
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

/// 从 UnixStream(Unix 流) 读取一条注册请求.
///
/// 参数 `stream` 是目标进程写入注册 JSON(数据交换格式) 的本机连接.
/// 返回值是解析后的注册请求.
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
