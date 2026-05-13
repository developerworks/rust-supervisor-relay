//! command(命令) 模块校验 dashboard(看板) 发来的控制命令.
//!
//! relay(中继) 会派生 requested_by(请求者), 拒绝历史命令别名, 并在危险命令缺少确认时拒绝转发.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::auth::RemoteIdentity;
use crate::error::{RelayError, RelayResult};

/// `ControlCommandName`(控制命令名称) 枚举列出第一版允许的命令.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlCommandName {
    /// `RestartChild`(重启子任务) 重启一个 child task(子任务).
    RestartChild,
    /// `PauseChild`(暂停子任务) 暂停一个 child task(子任务).
    PauseChild,
    /// `ResumeChild`(恢复子任务) 恢复一个 child task(子任务).
    ResumeChild,
    /// `QuarantineChild`(隔离子任务) 隔离一个 child task(子任务).
    QuarantineChild,
    /// `RemoveChild`(移除子任务) 移除一个 child task(子任务).
    RemoveChild,
    /// `AddChild`(添加子任务) 添加一个 child task(子任务).
    AddChild,
    /// `ShutdownTree`(关闭监督树) 关闭整个 supervisor tree(监督树).
    ShutdownTree,
}

impl ControlCommandName {
    /// 从 wire(传输层) 字符串解析控制命令名称.
    ///
    /// 参数 `value` 是客户端消息中的命令名称.
    /// 返回值是允许的命令枚举, 或者旧别名和未知命令的结构化拒绝错误.
    pub fn from_wire(value: &str) -> RelayResult<Self> {
        match value {
            "restart_child" => Ok(Self::RestartChild),
            "pause_child" => Ok(Self::PauseChild),
            "resume_child" => Ok(Self::ResumeChild),
            "quarantine_child" => Ok(Self::QuarantineChild),
            "remove_child" => Ok(Self::RemoveChild),
            "add_child" => Ok(Self::AddChild),
            "shutdown_tree" => Ok(Self::ShutdownTree),
            _ => Err(RelayError::new(
                "unsupported_method",
                "command_parse",
                None,
                "unknown command or historical command alias is not supported",
                false,
            )),
        }
    }

    /// 返回命令在 wire(传输层) 中使用的稳定名称.
    ///
    /// 参数为空, 因为名称只依赖当前枚举值.
    /// 返回值是命令名称.
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::RestartChild => "restart_child",
            Self::PauseChild => "pause_child",
            Self::ResumeChild => "resume_child",
            Self::QuarantineChild => "quarantine_child",
            Self::RemoveChild => "remove_child",
            Self::AddChild => "add_child",
            Self::ShutdownTree => "shutdown_tree",
        }
    }

    /// 判断命令是否需要二次确认.
    ///
    /// 参数为空, 因为判断只读取当前命令枚举.
    /// 返回值表示命令是否属于危险命令.
    pub fn requires_confirmation(self) -> bool {
        matches!(
            self,
            Self::ShutdownTree | Self::RemoveChild | Self::AddChild
        )
    }
}

/// `CommandTarget`(命令目标) 保存控制命令作用的 child path(子任务路径).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandTarget {
    /// `child_path`(子任务路径) 是目标 child task(子任务) 的路径, 关闭监督树时可以为空.
    pub child_path: Option<String>,
}

/// `ClientCommand`(客户端命令) 表示 dashboard(看板) 发来的原始控制消息.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientCommand {
    /// `command_id`(命令标识) 是客户端生成的幂等标识.
    pub command_id: String,
    /// `correlation_id`(关联标识) 只用于链路追踪或 UI(用户界面) 展示.
    pub correlation_id: Option<String>,
    /// `target_id`(目标标识) 是目标进程身份.
    pub target_id: String,
    /// `command`(命令) 是允许的控制命令名称.
    pub command: ControlCommandName,
    /// `target`(目标) 是命令作用的 child task(子任务) 或监督树.
    pub target: CommandTarget,
    /// `reason`(原因) 是操作者填写的非空原因.
    pub reason: String,
    /// `confirmed`(已确认) 表示危险命令是否完成二次确认.
    pub confirmed: bool,
    /// `requested_by`(请求者) 是客户端不得提供的字段, relay(中继) 会拒绝覆盖.
    pub requested_by: Option<String>,
}

/// `PreparedCommand`(已准备命令) 是 relay(中继) 校验并绑定身份后的控制命令.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedCommand {
    /// `command_id`(命令标识) 是客户端生成的幂等标识.
    pub command_id: String,
    /// `correlation_id`(关联标识) 只用于链路追踪或 UI(用户界面) 展示.
    pub correlation_id: Option<String>,
    /// `target_id`(目标标识) 是目标进程身份.
    pub target_id: String,
    /// `command`(命令) 是允许的控制命令名称.
    pub command: ControlCommandName,
    /// `target`(目标) 是命令作用的 child task(子任务) 或监督树.
    pub target: CommandTarget,
    /// `reason`(原因) 是操作者填写的非空原因.
    pub reason: String,
    /// `requested_by`(请求者) 是 relay(中继) 从 RemoteIdentity(远程身份) 派生的身份.
    pub requested_by: String,
    /// `confirmed`(已确认) 表示危险命令是否完成二次确认.
    pub confirmed: bool,
    /// `requested_at`(请求时间) 是 relay(中继) 接受命令的时间.
    pub requested_at: OffsetDateTime,
}

/// `ControlCommandResult`(控制命令结果) 保存目标 IPC(进程间通信) 返回的执行结果.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlCommandResult {
    /// `command_id`(命令标识) 是客户端命令标识.
    pub command_id: String,
    /// `correlation_id`(关联标识) 只用于链路追踪或 UI(用户界面) 展示.
    pub correlation_id: Option<String>,
    /// `target_id`(目标标识) 是目标进程身份.
    pub target_id: String,
    /// `accepted`(是否接受) 表示目标进程是否接受命令.
    pub accepted: bool,
    /// `status`(状态) 是 accepted(已接受), rejected(已拒绝), completed(已完成) 或 failed(失败).
    pub status: String,
    /// `requested_by`(请求者) 是 relay(中继) 派生的身份.
    pub requested_by: String,
    /// `completed_at`(完成时间) 是命令结果时间.
    pub completed_at: OffsetDateTime,
}

/// 校验客户端命令并派生 requested_by(请求者).
///
/// 参数 `command` 是 dashboard(看板) 发来的原始命令.
/// 参数 `identity` 是已认证远程身份.
/// 参数 `now` 是请求时间.
/// 返回值是可以转发到目标 IPC(进程间通信) 的命令, 或者结构化拒绝错误.
pub fn prepare_client_command(
    command: ClientCommand,
    identity: &RemoteIdentity,
    now: OffsetDateTime,
) -> RelayResult<PreparedCommand> {
    if command.command_id.trim().is_empty() {
        return Err(RelayError::for_target(
            "invalid_message_schema",
            "command_validate",
            command.target_id,
            "command_id must not be empty",
            false,
        ));
    }

    if command.requested_by.is_some() {
        return Err(RelayError::for_target(
            "requested_by_override",
            "command_validate",
            command.target_id,
            "client must not provide requested_by",
            false,
        ));
    }

    if command.reason.trim().is_empty() {
        return Err(RelayError::for_target(
            "empty_reason",
            "command_validate",
            command.target_id,
            "command reason must not be empty",
            false,
        ));
    }

    if command.command.requires_confirmation() && !command.confirmed {
        return Err(RelayError::for_target(
            "confirmation_required",
            "command_validate",
            command.target_id,
            "dangerous command requires confirmed=true",
            false,
        ));
    }

    Ok(PreparedCommand {
        command_id: command.command_id,
        correlation_id: command.correlation_id,
        target_id: command.target_id,
        command: command.command,
        target: command.target,
        reason: command.reason,
        requested_by: identity.principal.clone(),
        confirmed: command.confirmed,
        requested_at: now,
    })
}
