//! ipc_client(进程间通信客户端) 模块封装 relay(中继) 到目标进程的本机 IPC(进程间通信) 边界.
//!
//! 生产路径可以使用 Unix domain socket(Unix 域套接字) 加 newline-delimited JSON(按行分隔的 JSON 数据).
//! 测试路径使用 `RecordingIpcClient`(记录型进程间通信客户端) 证明 session gating(会话门控) 不会提前连接目标.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::command::{ControlCommandResult, PreparedCommand};
use crate::error::{RelayError, RelayResult};
use crate::registry::TargetProcessRegistration;

/// `DashboardSnapshot`(看板快照) 是 relay(中继) 从目标 IPC(进程间通信) 读取并转发的最小快照模型.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    /// `target_id`(目标标识) 是目标进程身份.
    pub target_id: String,
    /// `snapshot_generation`(快照代次) 是目标进程内单调增长的快照版本.
    pub snapshot_generation: u64,
    /// `generated_at`(生成时间) 是快照生成时间.
    pub generated_at: OffsetDateTime,
    /// `payload`(载荷) 保存目标侧完整监督树和运行时状态.
    pub payload: serde_json::Value,
}

/// `TargetIpcPort`(目标进程通信端口) 定义 relay(中继) 需要的可模拟 IPC(进程间通信) 能力.
pub trait TargetIpcPort {
    /// 连接目标 IPC(进程间通信) 并读取 snapshot(快照).
    ///
    /// 参数 `registration` 是目标进程活动注册.
    /// 参数 `now` 是连接时间.
    /// 返回值是目标进程快照, 或者结构化 IPC(进程间通信) 错误.
    fn connect_snapshot(
        &self,
        registration: &TargetProcessRegistration,
        now: OffsetDateTime,
    ) -> RelayResult<DashboardSnapshot>;

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
        command: &PreparedCommand,
        now: OffsetDateTime,
    ) -> RelayResult<ControlCommandResult>;
}

/// `RecordingIpcClient`(记录型进程间通信客户端) 用于测试会话顺序和命令转发边界.
#[derive(Debug, Default, Clone)]
pub struct RecordingIpcClient {
    /// `inner`(内部状态) 保存每个目标的连接, 订阅和命令计数.
    inner: Arc<Mutex<HashMap<String, IpcCounters>>>,
}

/// `IpcCounters`(进程间通信计数器) 保存一个目标的调用次数.
#[derive(Debug, Default, Clone, Copy)]
struct IpcCounters {
    /// `connects`(连接次数) 是 snapshot(快照) 连接次数.
    connects: usize,
    /// `subscriptions`(订阅次数) 是事件日志订阅次数.
    subscriptions: usize,
    /// `commands`(命令次数) 是命令转发次数.
    commands: usize,
}

impl RecordingIpcClient {
    /// 读取指定目标的连接次数.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 返回值是连接次数.
    pub fn connect_count(&self, target_id: &str) -> usize {
        self.count(target_id, |counters| counters.connects)
    }

    /// 读取指定目标的订阅次数.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 返回值是订阅次数.
    pub fn subscription_count(&self, target_id: &str) -> usize {
        self.count(target_id, |counters| counters.subscriptions)
    }

    /// 读取指定目标的命令转发次数.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 返回值是命令转发次数.
    pub fn command_count(&self, target_id: &str) -> usize {
        self.count(target_id, |counters| counters.commands)
    }

    /// 读取所有目标的连接次数.
    ///
    /// 参数为空, 因为该方法汇总内部状态.
    /// 返回值是所有目标的连接次数总和.
    pub fn total_connect_count(&self) -> usize {
        self.total(|counters| counters.connects)
    }

    /// 读取所有目标的命令转发次数.
    ///
    /// 参数为空, 因为该方法汇总内部状态.
    /// 返回值是所有目标的命令次数总和.
    pub fn total_command_count(&self) -> usize {
        self.total(|counters| counters.commands)
    }

    /// 更新一个目标的计数器.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `update` 是计数器更新函数.
    fn update(&self, target_id: &str, update: impl FnOnce(&mut IpcCounters)) {
        let mut guard = self
            .inner
            .lock()
            .expect("recording IPC mutex should not poison");
        let counters = guard.entry(target_id.to_owned()).or_default();
        update(counters);
    }

    /// 读取一个目标的计数器.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `read` 是计数器读取函数.
    /// 返回值是读取到的计数值.
    fn count(&self, target_id: &str, read: impl FnOnce(IpcCounters) -> usize) -> usize {
        let guard = self
            .inner
            .lock()
            .expect("recording IPC mutex should not poison");
        guard.get(target_id).copied().map(read).unwrap_or(0)
    }

    /// 汇总所有目标的计数器.
    ///
    /// 参数 `read` 是计数器读取函数.
    /// 返回值是所有目标计数值总和.
    fn total(&self, read: impl Fn(IpcCounters) -> usize) -> usize {
        let guard = self
            .inner
            .lock()
            .expect("recording IPC mutex should not poison");
        guard.values().copied().map(read).sum()
    }
}

impl TargetIpcPort for RecordingIpcClient {
    fn connect_snapshot(
        &self,
        registration: &TargetProcessRegistration,
        now: OffsetDateTime,
    ) -> RelayResult<DashboardSnapshot> {
        self.update(&registration.target_id, |counters| counters.connects += 1);
        Ok(DashboardSnapshot {
            target_id: registration.target_id.clone(),
            snapshot_generation: 1,
            generated_at: now,
            payload: json!({
                "target_id": registration.target_id,
                "display_name": registration.display_name,
                "topology": {"root": "/root"},
                "runtime_state": []
            }),
        })
    }

    fn subscribe_event_log(
        &self,
        registration: &TargetProcessRegistration,
        _now: OffsetDateTime,
    ) -> RelayResult<()> {
        self.update(&registration.target_id, |counters| {
            counters.subscriptions += 1
        });
        Ok(())
    }

    fn forward_command(
        &self,
        command: &PreparedCommand,
        now: OffsetDateTime,
    ) -> RelayResult<ControlCommandResult> {
        self.update(&command.target_id, |counters| counters.commands += 1);
        Ok(ControlCommandResult {
            command_id: command.command_id.clone(),
            target_id: command.target_id.clone(),
            accepted: true,
            status: "completed".to_owned(),
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
}
