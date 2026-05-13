//! session(会话) 模块实现 `wss://` control session(控制会话), 首包顺序和 IPC(进程间通信) 绑定门控.
//!
//! session(会话) 必须先完成身份认证并发送 target process list(目标进程列表), 然后才能绑定目标 IPC(进程间通信).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::AuditRecorder;
use crate::auth::RemoteIdentity;
use crate::command::{ClientCommand, ControlCommandResult, prepare_client_command};
use crate::error::{RelayError, RelayResult};
use crate::ipc_client::{DashboardState, TargetIpcPort};
use crate::registry::{ConnectionState, TargetProcessRegistry, VisibleTarget};

/// `TransportSecurity`(传输安全) 表示远程连接的外部协议安全级别.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSecurity {
    /// `Wss`(安全网络套接字协议) 表示 TLS(传输层安全协议) 已在 WebSocket(网络套接字协议) 前完成.
    Wss,
    /// `Ws`(明文网络套接字协议) 表示不允许完整控制的明文连接.
    Ws,
}

/// `ConnectionStateForSession`(会话连接状态) 表达远程连接生命周期.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStateForSession {
    /// `Handshaking`(握手中) 表示身份尚未建立.
    Handshaking,
    /// `Established`(已建立) 表示 control session(控制会话) 已建立.
    Established,
    /// `Closing`(关闭中) 表示连接正在关闭.
    Closing,
    /// `Closed`(已关闭) 表示连接已关闭.
    Closed,
}

/// `ControlState`(控制状态) 表示 session(会话) 是否允许控制目标.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlState {
    /// `NotEstablished`(未建立) 表示不得触发 IPC(进程间通信).
    NotEstablished,
    /// `Established`(已建立) 表示认证和控制会话已经完成.
    Established,
    /// `Revoked`(已撤销) 表示授权被撤销.
    Revoked,
}

/// `EventRecord`(事件记录) 是 relay(中继) 对外分发的最小事件模型.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    /// `target_id`(目标标识) 是事件所属目标进程.
    pub target_id: String,
    /// `sequence`(序号) 是目标进程内单调事件序号.
    pub sequence: u64,
    /// `event_type`(事件类型) 是监督事件名称.
    pub event_type: String,
    /// `severity`(严重程度) 是事件严重级别.
    pub severity: String,
    /// `occurred_at`(发生时间) 是事件时间.
    pub occurred_at: OffsetDateTime,
}

/// `LogRecord`(日志记录) 是 relay(中继) 对外分发的最小日志模型.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    /// `target_id`(目标标识) 是日志所属目标进程.
    pub target_id: String,
    /// `sequence`(序号) 是可以关联事件的可选日志序号.
    pub sequence: Option<u64>,
    /// `severity`(严重程度) 是日志严重级别.
    pub severity: String,
    /// `message`(消息) 是日志文本.
    pub message: String,
    /// `occurred_at`(发生时间) 是日志时间.
    pub occurred_at: OffsetDateTime,
}

/// `ServerMessage`(服务端消息) 是 relay(中继) 通过 `wss://` 发送给 dashboard(看板) 的消息.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// `SessionEstablished`(会话已建立) 是首包消息.
    SessionEstablished {
        /// `session_id`(会话标识) 是 relay(中继) 生成的 UUID(通用唯一标识).
        session_id: Uuid,
        /// `identity`(身份) 是已认证远程身份.
        identity: RemoteIdentity,
        /// `targets`(目标列表) 是当前可见 active registration(活动注册).
        targets: Vec<VisibleTarget>,
        /// `authorization_scopes`(授权范围) 是该 session(会话) 的授权范围.
        authorization_scopes: Vec<String>,
    },
    /// `State`(状态) 在目标绑定或重连后发送.
    State {
        /// `target_id`(目标标识) 是目标进程身份.
        target_id: String,
        /// `state`(状态) 是目标进程当前视图.
        state: DashboardState,
    },
    /// `Event`(事件) 是目标进程主动事件.
    Event {
        /// `target_id`(目标标识) 是目标进程身份.
        target_id: String,
        /// `event`(事件) 是监督事件记录.
        event: EventRecord,
    },
    /// `Log`(日志) 是目标进程主动日志.
    Log {
        /// `target_id`(目标标识) 是目标进程身份.
        target_id: String,
        /// `log`(日志) 是目标日志记录.
        log: LogRecord,
    },
    /// `StateDelta`(状态增量) 是目标状态变化.
    StateDelta {
        /// `target_id`(目标标识) 是目标进程身份.
        target_id: String,
        /// `delta`(增量) 是状态变化载荷.
        delta: serde_json::Value,
    },
    /// `DroppedCount`(丢弃数量) 是事件缺口或缓冲区丢弃诊断.
    DroppedCount {
        /// `target_id`(目标标识) 是目标进程身份.
        target_id: String,
        /// `dropped_event_count`(丢弃事件数量) 是丢弃或缺口数量.
        dropped_event_count: u64,
    },
    /// `CommandResult`(命令结果) 是目标进程控制命令结果.
    CommandResult {
        /// `target_id`(目标标识) 是目标进程身份.
        target_id: String,
        /// `result`(结果) 是控制命令结果.
        result: ControlCommandResult,
    },
    /// `ConnectionState`(连接状态) 是目标 IPC(进程间通信) 可用性变化.
    ConnectionState {
        /// `target_id`(目标标识) 是目标进程身份.
        target_id: String,
        /// `state`(状态) 是目标连接状态.
        state: ConnectionState,
    },
    /// `Error`(错误) 是结构化错误消息.
    Error {
        /// `error`(错误) 是结构化 relay(中继) 错误.
        error: RelayError,
    },
}

/// `DashboardSession`(看板会话) 保存一个已认证远程连接的状态.
#[derive(Debug)]
pub struct DashboardSession {
    /// `session_id`(会话标识) 是 relay(中继) 生成的 UUID(通用唯一标识).
    session_id: Uuid,
    /// `remote_identity`(远程身份) 在认证成功后保存身份.
    remote_identity: Option<RemoteIdentity>,
    /// `authorization_scopes`(授权范围) 保存 session(会话) 可访问的 scope(授权范围).
    authorization_scopes: Vec<String>,
    /// `connection_state`(连接状态) 保存远程连接生命周期.
    connection_state: ConnectionStateForSession,
    /// `control_state`(控制状态) 保存是否允许触发 IPC(进程间通信).
    control_state: ControlState,
    /// `bound_targets`(已绑定目标) 保存已经触发 IPC(进程间通信) 绑定的目标.
    bound_targets: HashSet<String>,
    /// `last_sequences`(最近序号) 保存每个目标最近转发事件序号.
    last_sequences: HashMap<String, u64>,
    /// `outbox`(输出队列) 保存按顺序生成的服务端消息.
    outbox: Vec<ServerMessage>,
    /// `created_at`(创建时间) 是 session(会话) 创建时间.
    created_at: OffsetDateTime,
    /// `last_seen_at`(最近时间) 是 session(会话) 最近活动时间.
    last_seen_at: OffsetDateTime,
}

impl DashboardSession {
    /// 创建一个未认证 session(会话).
    ///
    /// 参数 `now` 是创建时间.
    /// 返回值是不允许触发 IPC(进程间通信) 的 session(会话).
    pub fn unauthenticated(now: OffsetDateTime) -> Self {
        Self {
            session_id: Uuid::new_v4(),
            remote_identity: None,
            authorization_scopes: Vec::new(),
            connection_state: ConnectionStateForSession::Handshaking,
            control_state: ControlState::NotEstablished,
            bound_targets: HashSet::new(),
            last_sequences: HashMap::new(),
            outbox: Vec::new(),
            created_at: now,
            last_seen_at: now,
        }
    }

    /// 建立一个已认证 control session(控制会话).
    ///
    /// 参数 `identity` 是已认证远程身份.
    /// 参数 `registry` 是目标进程注册表.
    /// 参数 `transport` 是远程连接安全级别.
    /// 参数 `now` 是会话建立时间.
    /// 返回值是已建立 session(会话), 首包为 `session_established`.
    pub fn establish(
        identity: RemoteIdentity,
        registry: &TargetProcessRegistry,
        transport: TransportSecurity,
        now: OffsetDateTime,
    ) -> RelayResult<Self> {
        if transport != TransportSecurity::Wss {
            return Err(RelayError::new(
                "insecure_transport",
                "session",
                None,
                "full control session requires wss://",
                false,
            ));
        }

        let targets = registry.visible_targets_for_scopes(&identity.authorization_scopes, now);
        let session_id = Uuid::new_v4();
        let authorization_scopes = identity.authorization_scopes.clone();
        let outbox = vec![ServerMessage::SessionEstablished {
            session_id,
            identity: identity.clone(),
            targets,
            authorization_scopes: authorization_scopes.clone(),
        }];

        Ok(Self {
            session_id,
            remote_identity: Some(identity),
            authorization_scopes,
            connection_state: ConnectionStateForSession::Established,
            control_state: ControlState::Established,
            bound_targets: HashSet::new(),
            last_sequences: HashMap::new(),
            outbox,
            created_at: now,
            last_seen_at: now,
        })
    }

    /// 绑定一个目标进程并触发 IPC(进程间通信) state(状态) 和 subscription(订阅).
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `registry` 是可变目标注册表.
    /// 参数 `ipc` 是可模拟 IPC(进程间通信) 端口.
    /// 参数 `now` 是绑定时间.
    /// 返回值在绑定成功时为空.
    pub fn bind_target(
        &mut self,
        target_id: &str,
        registry: &mut TargetProcessRegistry,
        ipc: &impl TargetIpcPort,
        now: OffsetDateTime,
    ) -> RelayResult<()> {
        self.ensure_control_established()?;
        registry.ensure_authorized(target_id, &self.authorization_scopes, now)?;
        let registration = registry.registration(target_id)?.clone();

        if self.bound_targets.contains(target_id) {
            return Ok(());
        }

        registry.begin_binding(target_id, now)?;
        let state = ipc.connect_state(&registration, now).inspect_err(|error| {
            registry.mark_unavailable(target_id, error.message.clone(), now);
        })?;
        registry.mark_connected(target_id, state.state_generation, now)?;
        ipc.subscribe_event_log(&registration, now)
            .inspect_err(|error| {
                registry.mark_unavailable(target_id, error.message.clone(), now);
            })?;

        self.bound_targets.insert(target_id.to_owned());
        self.outbox.push(ServerMessage::State {
            target_id: target_id.to_owned(),
            state,
        });
        self.last_seen_at = now;
        Ok(())
    }

    /// 处理一个客户端控制命令.
    ///
    /// 参数 `command` 是客户端命令.
    /// 参数 `registry` 是可变目标注册表.
    /// 参数 `ipc` 是可模拟 IPC(进程间通信) 端口.
    /// 参数 `audit` 是审计记录器.
    /// 参数 `now` 是命令处理时间.
    /// 返回值是目标进程命令结果.
    pub fn handle_command(
        &mut self,
        command: ClientCommand,
        registry: &mut TargetProcessRegistry,
        ipc: &impl TargetIpcPort,
        audit: &mut AuditRecorder,
        now: OffsetDateTime,
    ) -> RelayResult<ControlCommandResult> {
        self.ensure_control_established()?;
        let identity = self.remote_identity.clone().ok_or_else(|| {
            RelayError::new(
                "session_not_established",
                "session",
                None,
                "control session is not established",
                false,
            )
        })?;

        if !self.bound_targets.contains(&command.target_id) {
            return Err(RelayError::for_target(
                "target_not_bound",
                "session",
                command.target_id,
                "target must be bound before command forwarding",
                false,
            ));
        }

        registry.ensure_authorized(&command.target_id, &self.authorization_scopes, now)?;
        let registration = registry.registration(&command.target_id)?.clone();
        let prepared = prepare_client_command(command, &identity, now)?;
        audit.record_accepted(&identity, &prepared, now);
        let result = ipc
            .forward_command(&registration, &prepared, now)
            .inspect_err(|error| {
                audit.record_rejected(&identity, &prepared, error.message.clone(), now);
            })?;
        audit.record_completed(&identity, &prepared, result.status.clone(), now);
        self.outbox.push(ServerMessage::CommandResult {
            target_id: result.target_id.clone(),
            result: result.clone(),
        });
        Ok(result)
    }

    /// 读取 session(会话) 输出消息.
    ///
    /// 参数为空, 因为该方法读取当前 session(会话) 输出队列.
    /// 返回值是服务端消息切片.
    pub fn outbox(&self) -> &[ServerMessage] {
        &self.outbox
    }

    /// 读取 session id(会话标识).
    ///
    /// 参数为空, 因为该方法读取当前 session(会话) 状态.
    /// 返回值是 relay(中继) 生成的 UUID(通用唯一标识).
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// 读取 session(会话) 创建时间.
    ///
    /// 参数为空, 因为该方法读取当前 session(会话) 状态.
    /// 返回值是创建时间.
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// 判断目标是否已经绑定.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 返回值表示 session(会话) 是否已经触发该目标 IPC(进程间通信) 绑定.
    pub fn is_bound(&self, target_id: &str) -> bool {
        self.bound_targets.contains(target_id)
    }

    /// 读取 session(会话) 首包可见目标数量.
    ///
    /// 参数为空, 因为该方法读取当前输出队列中的首包.
    /// 返回值是可见目标数量.
    pub fn visible_target_count(&self) -> usize {
        self.outbox
            .iter()
            .find_map(|message| match message {
                ServerMessage::SessionEstablished { targets, .. } => Some(targets.len()),
                _ => None,
            })
            .unwrap_or(0)
    }

    /// 处理目标事件并保持 sequence(序号) 顺序诊断.
    ///
    /// 参数 `event` 是目标进程事件.
    /// 返回值是应该发送给 dashboard(看板) 的消息集合.
    pub fn accept_event(&mut self, event: EventRecord) -> RelayResult<Vec<ServerMessage>> {
        if !self.bound_targets.contains(&event.target_id) {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        if let Some(previous) = self.last_sequences.get(&event.target_id).copied() {
            if event.sequence <= previous {
                let error = RelayError::for_target(
                    "sequence_not_monotonic",
                    "stream",
                    event.target_id.clone(),
                    "event sequence must be monotonic for each target",
                    false,
                );
                messages.push(ServerMessage::Error { error });
                return Ok(messages);
            }
            if event.sequence > previous + 1 {
                messages.push(ServerMessage::DroppedCount {
                    target_id: event.target_id.clone(),
                    dropped_event_count: event.sequence - previous - 1,
                });
            }
        }

        self.last_sequences
            .insert(event.target_id.clone(), event.sequence);
        messages.push(ServerMessage::Event {
            target_id: event.target_id.clone(),
            event,
        });
        self.outbox.extend(messages.clone());
        Ok(messages)
    }

    /// 处理目标日志.
    ///
    /// 参数 `log` 是目标进程日志.
    /// 返回值是应该发送给 dashboard(看板) 的消息集合.
    pub fn accept_log(&mut self, log: LogRecord) -> RelayResult<Vec<ServerMessage>> {
        if !self.bound_targets.contains(&log.target_id) {
            return Ok(Vec::new());
        }
        let message = ServerMessage::Log {
            target_id: log.target_id.clone(),
            log,
        };
        self.outbox.push(message.clone());
        Ok(vec![message])
    }

    /// 处理目标状态增量.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `delta` 是状态变化载荷.
    /// 返回值是应该发送给 dashboard(看板) 的消息集合.
    pub fn accept_state_delta(
        &mut self,
        target_id: &str,
        delta: serde_json::Value,
    ) -> RelayResult<Vec<ServerMessage>> {
        if !self.bound_targets.contains(target_id) {
            return Ok(Vec::new());
        }
        let message = ServerMessage::StateDelta {
            target_id: target_id.to_owned(),
            delta,
        };
        self.outbox.push(message.clone());
        Ok(vec![message])
    }

    /// 处理 dropped count(丢弃数量) 诊断.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `dropped_event_count` 是丢弃事件数量.
    /// 返回值是应该发送给 dashboard(看板) 的消息集合.
    pub fn accept_dropped_count(
        &mut self,
        target_id: &str,
        dropped_event_count: u64,
    ) -> RelayResult<Vec<ServerMessage>> {
        if !self.bound_targets.contains(target_id) {
            return Ok(Vec::new());
        }
        let message = ServerMessage::DroppedCount {
            target_id: target_id.to_owned(),
            dropped_event_count,
        };
        self.outbox.push(message.clone());
        Ok(vec![message])
    }

    /// 处理连接状态变化.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `state` 是新的连接状态.
    /// 返回值是应该发送给 dashboard(看板) 的消息集合.
    pub fn accept_connection_state(
        &mut self,
        target_id: &str,
        state: ConnectionState,
    ) -> RelayResult<Vec<ServerMessage>> {
        if !self.bound_targets.contains(target_id) {
            return Ok(Vec::new());
        }
        let message = ServerMessage::ConnectionState {
            target_id: target_id.to_owned(),
            state,
        };
        self.outbox.push(message.clone());
        Ok(vec![message])
    }

    /// 确认 control session(控制会话) 已经建立.
    ///
    /// 参数为空, 因为检查读取当前 session(会话) 状态.
    /// 返回值在会话可触发 IPC(进程间通信) 时为空.
    fn ensure_control_established(&self) -> RelayResult<()> {
        if self.connection_state == ConnectionStateForSession::Established
            && self.control_state == ControlState::Established
            && self.remote_identity.is_some()
        {
            return Ok(());
        }

        Err(RelayError::new(
            "session_not_established",
            "session",
            None,
            "control session must be established before IPC binding or command forwarding",
            false,
        ))
    }
}
