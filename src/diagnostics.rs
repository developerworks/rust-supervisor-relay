//! diagnostics(诊断) 模块提供 relay(中继) 失败路径的结构化字段.
//!
//! 这些结构可以写入 tracing(结构化追踪), 也可以转换成 dashboard(看板) 的 error(错误) 消息.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// `DiagnosticEvent`(诊断事件) 保存一个可观察失败或状态变化.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    /// `stage`(阶段) 指出诊断来自配置, 注册, 认证, 会话, IPC(进程间通信) 或命令.
    pub stage: String,
    /// `target_id`(目标标识) 在诊断绑定目标进程时保存该目标.
    pub target_id: Option<String>,
    /// `code`(代码) 是机器可读诊断类型.
    pub code: String,
    /// `message`(消息) 是操作者可读诊断.
    pub message: String,
    /// `occurred_at`(发生时间) 是诊断生成时间.
    pub occurred_at: OffsetDateTime,
}

impl DiagnosticEvent {
    /// 创建一个诊断事件.
    ///
    /// 参数 `stage` 是失败或状态变化阶段.
    /// 参数 `target_id` 是可选目标进程标识.
    /// 参数 `code` 是机器可读诊断代码.
    /// 参数 `message` 是操作者可读诊断.
    /// 参数 `occurred_at` 是诊断生成时间.
    /// 返回值是结构化诊断事件.
    pub fn new(
        stage: impl Into<String>,
        target_id: Option<String>,
        code: impl Into<String>,
        message: impl Into<String>,
        occurred_at: OffsetDateTime,
    ) -> Self {
        Self {
            stage: stage.into(),
            target_id,
            code: code.into(),
            message: message.into(),
            occurred_at,
        }
    }
}
