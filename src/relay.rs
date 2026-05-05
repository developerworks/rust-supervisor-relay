//! relay(中继) 模块实现按 session(会话) 和授权目标分发 event(事件), log(日志), state delta(状态增量) 和 error(错误).
//!
//! 本模块不直接连接目标 IPC(进程间通信), 它只处理已经绑定 session(会话) 的消息分发.

use time::OffsetDateTime;

use crate::error::RelayResult;
use crate::registry::{ConnectionState, TargetProcessRegistry};
use crate::session::{DashboardSession, EventRecord, LogRecord, ServerMessage};

/// `RelayHub`(中继枢纽) 提供 fan out(分发) 边界.
pub struct RelayHub;

impl RelayHub {
    /// 分发目标事件.
    ///
    /// 参数 `session` 是接收消息的 dashboard session(看板会话).
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `sequence` 是目标内事件序号.
    /// 参数 `event_type` 是事件类型.
    /// 参数 `severity` 是严重程度.
    /// 参数 `occurred_at` 是事件时间.
    /// 返回值是本次生成的服务端消息集合.
    pub fn fan_out_event(
        session: &mut DashboardSession,
        target_id: &str,
        sequence: u64,
        event_type: &str,
        severity: &str,
        occurred_at: OffsetDateTime,
    ) -> RelayResult<Vec<ServerMessage>> {
        session.accept_event(EventRecord {
            target_id: target_id.to_owned(),
            sequence,
            event_type: event_type.to_owned(),
            severity: severity.to_owned(),
            occurred_at,
        })
    }

    /// 分发目标日志.
    ///
    /// 参数 `session` 是接收消息的 dashboard session(看板会话).
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `sequence` 是可选日志序号.
    /// 参数 `severity` 是严重程度.
    /// 参数 `message` 是日志文本.
    /// 参数 `occurred_at` 是日志时间.
    /// 返回值是本次生成的服务端消息集合.
    pub fn fan_out_log(
        session: &mut DashboardSession,
        target_id: &str,
        sequence: Option<u64>,
        severity: &str,
        message: &str,
        occurred_at: OffsetDateTime,
    ) -> RelayResult<Vec<ServerMessage>> {
        session.accept_log(LogRecord {
            target_id: target_id.to_owned(),
            sequence,
            severity: severity.to_owned(),
            message: message.to_owned(),
            occurred_at,
        })
    }

    /// 分发状态增量.
    ///
    /// 参数 `session` 是接收消息的 dashboard session(看板会话).
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `delta` 是状态变化载荷.
    /// 返回值是本次生成的服务端消息集合.
    pub fn fan_out_state_delta(
        session: &mut DashboardSession,
        target_id: &str,
        delta: serde_json::Value,
    ) -> RelayResult<Vec<ServerMessage>> {
        session.accept_state_delta(target_id, delta)
    }

    /// 分发 dropped count(丢弃数量) 诊断.
    ///
    /// 参数 `session` 是接收消息的 dashboard session(看板会话).
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `dropped_event_count` 是丢弃事件数量.
    /// 返回值是本次生成的服务端消息集合.
    pub fn fan_out_dropped_count(
        session: &mut DashboardSession,
        target_id: &str,
        dropped_event_count: u64,
    ) -> RelayResult<Vec<ServerMessage>> {
        session.accept_dropped_count(target_id, dropped_event_count)
    }

    /// 处理 reconnect timeout(重连超时) 并分发 unavailable(不可用) 状态.
    ///
    /// 参数 `session` 是接收消息的 dashboard session(看板会话).
    /// 参数 `registry` 是目标进程注册表.
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `now` 是超时时间.
    /// 返回值是本次生成的服务端消息集合.
    pub fn reconnect_timeout(
        session: &mut DashboardSession,
        registry: &mut TargetProcessRegistry,
        target_id: &str,
        now: OffsetDateTime,
    ) -> RelayResult<Vec<ServerMessage>> {
        registry.mark_unavailable(target_id, "reconnect timeout after 10 seconds", now);
        session.accept_connection_state(target_id, ConnectionState::Unavailable)
    }
}
