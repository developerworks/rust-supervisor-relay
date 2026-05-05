//! error(错误) 模块定义 relay(中继) 对外返回的结构化失败.
//!
//! 这个模块只保存可观察错误模型, 其他模块通过 `RelayResult`(中继结果) 传递失败.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `RelayResult`(中继结果) 是 relay(中继) 模块之间共享的结果类型.
pub type RelayResult<T> = Result<T, RelayError>;

/// `RelayError`(中继错误) 表达失败代码, 阶段, 目标和重试语义.
///
/// # Examples
///
/// ```
/// use rust_supervisor_relay::error::RelayError;
///
/// let error = RelayError::new(
///     "invalid_public_url",
///     "config",
///     None,
///     "listen.public_url must use wss://",
///     false,
/// );
///
/// assert_eq!(error.code, "invalid_public_url");
/// assert!(!error.retryable);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{code} at {stage}: {message}")]
pub struct RelayError {
    /// `code`(代码) 是稳定的机器可读失败类型.
    pub code: String,
    /// `stage`(阶段) 指出失败发生在配置, 注册, 认证, 会话, IPC(进程间通信) 或命令路径.
    pub stage: String,
    /// `target_id`(目标标识) 在失败绑定到目标进程时保存该目标.
    pub target_id: Option<String>,
    /// `message`(消息) 保存给操作者阅读的中文或英文诊断文本.
    pub message: String,
    /// `retryable`(可重试) 表达调用方是否可以在状态变化后重试.
    pub retryable: bool,
}

impl RelayError {
    /// 创建一个结构化 relay(中继) 错误.
    ///
    /// 参数 `code` 是稳定错误代码.
    /// 参数 `stage` 是失败阶段.
    /// 参数 `target_id` 是可选目标标识.
    /// 参数 `message` 是操作者可读诊断.
    /// 参数 `retryable` 表示失败是否可重试.
    /// 返回值是完整的 `RelayError`(中继错误).
    pub fn new(
        code: impl Into<String>,
        stage: impl Into<String>,
        target_id: Option<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            code: code.into(),
            stage: stage.into(),
            target_id,
            message: message.into(),
            retryable,
        }
    }

    /// 创建一个绑定目标进程的结构化 relay(中继) 错误.
    ///
    /// 参数 `code` 是稳定错误代码.
    /// 参数 `stage` 是失败阶段.
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `message` 是操作者可读诊断.
    /// 参数 `retryable` 表示失败是否可重试.
    /// 返回值是完整的 `RelayError`(中继错误).
    pub fn for_target(
        code: impl Into<String>,
        stage: impl Into<String>,
        target_id: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self::new(code, stage, Some(target_id.into()), message, retryable)
    }
}
