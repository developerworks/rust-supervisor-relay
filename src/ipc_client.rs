//! ipc_client(进程间通信客户端) 模块封装 relay(中继) 到目标进程的本机 IPC(进程间通信) 边界.
//!
//! 生产路径可以使用 Unix domain socket(Unix 域套接字) 加 newline-delimited JSON(按行分隔的 JSON 数据).

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

/// `DashboardState`(看板状态) 是 relay(中继) 从目标 IPC(进程间通信) 读取并转发的最小状态模型.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardState {
    /// `target_id`(目标标识) 是目标进程身份.
    pub target_id: String,
    /// `state_generation`(状态代次) 是目标进程内单调增长的状态版本.
    pub state_generation: u64,
    /// `generated_at`(生成时间) 是状态生成时间.
    pub generated_at: OffsetDateTime,
    /// `payload`(载荷) 保存目标侧完整监督树和运行时状态.
    pub payload: serde_json::Value,
}

/// `TargetIpcPort`(目标进程通信端口) 定义 relay(中继) 需要的 IPC(进程间通信) 能力.
pub trait TargetIpcPort {
    /// 连接目标 IPC(进程间通信) 并读取 state(状态).
    ///
    /// 参数 `registration` 是目标进程活动注册.
    /// 参数 `now` 是连接时间.
    /// 返回值是目标进程状态, 或者结构化 IPC(进程间通信) 错误.
    fn connect_state(
        &self,
        registration: &TargetProcessRegistration,
        now: OffsetDateTime,
    ) -> RelayResult<DashboardState>;

    /// 在目标 IPC(进程间通信) 上建立 event/log subscription(事件日志订阅).
    ///
    /// 参数 `registration` 是目标进程活动注册.
    /// 参数 `now` 是订阅时间.
    /// 返回值在订阅建立成功时为空.
    fn subscribe_event_log(
        &self,
        registration: &TargetProcessRegistration,
        now: OffsetDateTime,
    ) -> RelayResult<()>;

    /// 转发控制命令到目标 IPC(进程间通信).
    ///
    /// 参数 `command` 是已经校验并绑定身份的控制命令.
    /// 参数 `now` 是转发时间.
    /// 返回值是目标进程命令结果.
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

/// `UnixNdjsonIpcClient`(Unix 按行 JSON 进程间通信客户端) 提供真实目标 IPC(进程间通信) 的最小请求响应能力.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnixNdjsonIpcClient;

impl UnixNdjsonIpcClient {
    /// 发送一条 IPC(进程间通信) 请求并读取一行响应.
    ///
    /// 参数 `ipc_path` 是目标进程 Unix domain socket(Unix 域套接字) 路径.
    /// 参数 `request` 是要写入的 JSON(数据交换格式) 对象.
    /// 返回值是目标进程响应 JSON(数据交换格式).
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

    /// 发送一条 IPC(进程间通信) 请求并同步等待响应.
    ///
    /// 参数 `ipc_path` 是目标进程 Unix domain socket(Unix 域套接字) 路径.
    /// 参数 `request` 是要写入的 JSON(数据交换格式) 对象.
    /// 返回值是目标进程响应 JSON(数据交换格式).
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

    /// 发送订阅请求到目标 IPC(进程间通信).
    ///
    /// 参数 `ipc_path` 是目标进程 Unix domain socket(Unix 域套接字) 路径.
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `method` 是订阅方法.
    /// 返回值在订阅成功时为空.
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

    /// 转发控制命令到目标 IPC(进程间通信).
    ///
    /// 参数 `command` 是已经校验并绑定身份的控制命令.
    /// 参数 `now` 是转发时间.
    /// 返回值是目标进程响应 JSON(数据交换格式).
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

/// 创建 IPC(进程间通信) 请求标识.
///
/// 参数为空, 因为请求标识由 relay(中继) 本地生成.
/// 返回值是字符串形式的 UUID(通用唯一标识).
fn request_id() -> String {
    Uuid::new_v4().to_string()
}

/// 解析目标 IPC(进程间通信) 响应中的成功结果.
///
/// 参数 `response` 是目标进程响应 JSON(数据交换格式).
/// 返回值是 `result` 字段, 或者结构化错误.
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

/// 返回控制命令对应的 IPC(进程间通信) 方法.
///
/// 参数 `command` 是 relay(中继) 已接受的命令名称.
/// 返回值是目标进程 IPC(进程间通信) 方法名.
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
