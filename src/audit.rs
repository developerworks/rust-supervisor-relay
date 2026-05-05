//! audit(审计) 模块记录控制命令 accepted(已接受), rejected(已拒绝) 和 completed(已完成) 事实.
//!
//! 第一版不引入持久化数据库, 所以审计事件保存在内存记录器中, 并可通过事件流继续分发.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::RemoteIdentity;
use crate::command::PreparedCommand;

/// `AuditResult`(审计结果) 表示命令在某个阶段的审计事实.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    /// `Accepted`(已接受) 表示 relay(中继) 接受并准备转发命令.
    Accepted,
    /// `Rejected`(已拒绝) 表示 relay(中继) 或目标进程拒绝命令.
    Rejected,
    /// `Completed`(已完成) 表示目标进程返回完成结果.
    Completed,
}

/// `AuditEvent`(审计事件) 保存控制命令的身份, 目标, 原因和结果.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// `audit_id`(审计标识) 是 relay(中继) 生成的唯一标识.
    pub audit_id: Uuid,
    /// `identity_principal`(身份主体) 是执行命令的操作者或服务身份.
    pub identity_principal: String,
    /// `target_id`(目标标识) 是目标进程身份.
    pub target_id: String,
    /// `command_id`(命令标识) 是客户端命令标识.
    pub command_id: String,
    /// `command`(命令) 是控制命令名称.
    pub command: String,
    /// `target`(目标) 是命令作用对象.
    pub target: Option<String>,
    /// `reason`(原因) 是操作者填写的原因.
    pub reason: String,
    /// `result`(结果) 是 accepted(已接受), rejected(已拒绝) 或 completed(已完成).
    pub result: AuditResult,
    /// `detail`(详情) 保存拒绝原因或完成摘要.
    pub detail: String,
    /// `occurred_at`(发生时间) 是审计事件时间.
    pub occurred_at: OffsetDateTime,
}

/// `AuditRecorder`(审计记录器) 保存内存审计事件.
#[derive(Debug, Default)]
pub struct AuditRecorder {
    /// `events`(事件) 保存已记录审计事件.
    events: Vec<AuditEvent>,
}

impl AuditRecorder {
    /// 记录 accepted(已接受) 审计事件.
    ///
    /// 参数 `identity` 是已认证远程身份.
    /// 参数 `command` 是已经校验的控制命令.
    /// 参数 `now` 是审计时间.
    pub fn record_accepted(
        &mut self,
        identity: &RemoteIdentity,
        command: &PreparedCommand,
        now: OffsetDateTime,
    ) {
        self.record(identity, command, AuditResult::Accepted, "accepted", now);
    }

    /// 记录 rejected(已拒绝) 审计事件.
    ///
    /// 参数 `identity` 是已认证远程身份.
    /// 参数 `command` 是已经校验的控制命令.
    /// 参数 `detail` 是拒绝原因.
    /// 参数 `now` 是审计时间.
    pub fn record_rejected(
        &mut self,
        identity: &RemoteIdentity,
        command: &PreparedCommand,
        detail: impl Into<String>,
        now: OffsetDateTime,
    ) {
        self.record(identity, command, AuditResult::Rejected, detail, now);
    }

    /// 记录 completed(已完成) 审计事件.
    ///
    /// 参数 `identity` 是已认证远程身份.
    /// 参数 `command` 是已经校验的控制命令.
    /// 参数 `detail` 是完成摘要.
    /// 参数 `now` 是审计时间.
    pub fn record_completed(
        &mut self,
        identity: &RemoteIdentity,
        command: &PreparedCommand,
        detail: impl Into<String>,
        now: OffsetDateTime,
    ) {
        self.record(identity, command, AuditResult::Completed, detail, now);
    }

    /// 读取所有审计事件.
    ///
    /// 参数为空, 因为读取当前记录器内存.
    /// 返回值是按写入顺序保存的审计事件切片.
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// 写入一个审计事件.
    ///
    /// 参数 `identity` 是已认证远程身份.
    /// 参数 `command` 是已经校验的控制命令.
    /// 参数 `result` 是审计结果.
    /// 参数 `detail` 是审计详情.
    /// 参数 `now` 是审计时间.
    fn record(
        &mut self,
        identity: &RemoteIdentity,
        command: &PreparedCommand,
        result: AuditResult,
        detail: impl Into<String>,
        now: OffsetDateTime,
    ) {
        self.events.push(AuditEvent {
            audit_id: Uuid::new_v4(),
            identity_principal: identity.principal.clone(),
            target_id: command.target_id.clone(),
            command_id: command.command_id.clone(),
            command: format!("{:?}", command.command),
            target: command.target.child_path.clone(),
            reason: command.reason.clone(),
            result,
            detail: detail.into(),
            occurred_at: now,
        });
    }
}
