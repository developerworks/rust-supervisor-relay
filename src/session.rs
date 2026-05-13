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

/// `LogEventFilterMode`(日志事件筛选模式) 表示 relay(中继) 或客户端本地负责筛选.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogEventFilterMode {
    /// `Remote`(远程过滤) 表示 relay(中继) 按条件减少下发.
    Remote,
    /// `Local`(本地过滤) 表示 relay(中继) 下发完整后续数据.
    Local,
}

/// `ResumeCursorEntry`(恢复游标条目) 表示单个 target(目标) 和 stream(流) 的恢复点.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeCursorEntry {
    /// `delivery_mode`(交付模式) 是 remote(远程过滤) 或 local(本地过滤).
    pub delivery_mode: String,
    /// `filter_config_version`(筛选配置版本) 是 relay(中继) 下发的配置版本.
    pub filter_config_version: u64,
    /// `stream_epoch`(流世代) 隔离 target(目标) 重启后的序列.
    pub stream_epoch: String,
    /// `sequence`(序列) 是 next_sequence_inclusive(下一条包含边界的序列).
    pub sequence: u64,
}

/// `ResumeCursor`(恢复游标) 保存 event/log(事件和日志) 两个流的恢复请求.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeCursor {
    /// `events`(事件) 保存事件流恢复点.
    #[serde(default)]
    pub events: HashMap<String, ResumeCursorEntry>,
    /// `logs`(日志) 保存日志流恢复点.
    #[serde(default)]
    pub logs: HashMap<String, ResumeCursorEntry>,
}

/// `ClientHello`(客户端握手) 是客户端建立 session(会话) 后发送的第一条消息.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    /// `client_store_id`(客户端存储标识) 是本地数据库分区键.
    pub client_store_id: String,
    /// `resume_cursor`(恢复游标) 是本地持久化库提供的恢复请求.
    #[serde(default)]
    pub resume_cursor: ResumeCursor,
}

/// `LogEventFilterConditionsMessage`(日志事件筛选条件消息) 表达客户端当前筛选条件.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEventFilterConditionsMessage {
    /// `target_ids`(目标标识集合) 限定目标.
    #[serde(default)]
    pub target_ids: Vec<String>,
    /// `child_paths`(子任务路径集合) 限定子任务.
    #[serde(default)]
    pub child_paths: Vec<String>,
    /// `lifecycle_states`(生命周期状态集合) 限定状态.
    #[serde(default)]
    pub lifecycle_states: Vec<String>,
    /// `event_types`(事件类型集合) 限定事件类型.
    #[serde(default)]
    pub event_types: Vec<String>,
    /// `severities`(严重程度集合) 限定严重程度.
    #[serde(default)]
    pub severities: Vec<String>,
    /// `sequence_min`(最小序列) 表示客户端筛选的最小序列.
    pub sequence_min: Option<u64>,
    /// `correlation_id`(关联标识) 表示关联筛选文本.
    pub correlation_id: Option<String>,
}

/// `ClientMessage`(客户端消息) 是当前协议接受的入站消息.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// `ClientHello`(客户端握手) 必须是客户端第一条消息.
    ClientHello(ClientHello),
    /// `Command`(命令) 是握手后的控制命令.
    Command(ClientCommand),
    /// `LogEventFilterConditions`(日志事件筛选条件) 是当前协议的筛选更新消息.
    LogEventFilterConditions(LogEventFilterConditionsMessage),
}

/// `ServerMessage`(服务端消息) 是 relay(中继) 通过 `wss://` 发送给 dashboard(看板) 的消息.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// `ServerHello`(服务端握手) 是 relay(中继) 在业务数据前发送的身份引导.
    ServerHello {
        /// `session_id`(会话标识) 是 relay(中继) 生成的 UUID(通用唯一标识).
        session_id: Uuid,
        /// `client_identity`(客户端身份) 是 mTLS(双向传输层安全) 证书身份键.
        client_identity: String,
        /// `log_event_filter_mode`(日志事件筛选模式) 是当前身份的筛选模式.
        log_event_filter_mode: LogEventFilterMode,
        /// `log_event_filter_conditions`(日志事件筛选条件) 是当前身份的筛选条件.
        log_event_filter_conditions: serde_json::Value,
        /// `filter_config_version`(筛选配置版本) 是当前身份配置版本.
        filter_config_version: u64,
    },
    /// `TargetList`(目标列表) 是 client_hello(客户端握手) 成功后的业务数据.
    TargetList {
        /// `targets`(目标列表) 是当前活动 target(目标).
        targets: Vec<VisibleTarget>,
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

/// 解码客户端消息并拒绝历史协议字段.
///
/// 参数 `raw` 是 WebSocket(网络套接字) 文本消息.
/// 返回值是当前协议客户端消息, 或者结构化拒绝错误.
pub fn decode_client_message(raw: &str) -> RelayResult<ClientMessage> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|error| {
        RelayError::new(
            "invalid_message_json",
            "session_decode",
            None,
            format!("client message could not be parsed: {error}"),
            false,
        )
    })?;

    let message_type = value.get("type").and_then(serde_json::Value::as_str);
    if message_type == Some("client_hello") {
        let object = value.as_object().ok_or_else(|| {
            RelayError::new(
                "invalid_message_schema",
                "session_decode",
                None,
                "client message must be a JSON object",
                false,
            )
        })?;
        let allowed = ["type", "client_store_id", "resume_cursor"];
        if object.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(RelayError::new(
                "unsupported_field",
                "session_decode",
                None,
                "message field is not supported by the current protocol",
                false,
            ));
        }
    } else if !matches!(
        message_type,
        Some("command" | "log_event_filter_conditions")
    ) {
        return Err(RelayError::new(
            "unsupported_message_type",
            "session_decode",
            None,
            "message type is not supported by the current protocol",
            false,
        ));
    }

    serde_json::from_value(value).map_err(|error| {
        RelayError::new(
            "invalid_message_schema",
            "session_decode",
            None,
            format!("client message schema is invalid: {error}"),
            false,
        )
    })
}

/// `DashboardSession`(看板会话) 保存一个已认证远程连接的状态.
#[derive(Debug)]
pub struct DashboardSession {
    /// `session_id`(会话标识) 是 relay(中继) 生成的 UUID(通用唯一标识).
    session_id: Uuid,
    /// `remote_identity`(远程身份) 在认证成功后保存身份.
    remote_identity: Option<RemoteIdentity>,
    /// `client_store_id`(客户端存储标识) 在 client_hello(客户端握手) 后保存.
    client_store_id: Option<String>,
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
            client_store_id: None,
            connection_state: ConnectionStateForSession::Handshaking,
            control_state: ControlState::NotEstablished,
            bound_targets: HashSet::new(),
            last_sequences: HashMap::new(),
            outbox: Vec::new(),
            created_at: now,
            last_seen_at: now,
        }
    }

    /// 创建只发送 server_hello(服务端握手) 的已认证 session(会话).
    ///
    /// 参数 `identity` 是已认证远程身份.
    /// 参数 `now` 是会话创建时间.
    /// 返回值是等待 client_hello(客户端握手) 的 session(会话).
    pub fn server_hello(identity: RemoteIdentity, now: OffsetDateTime) -> Self {
        let session_id = Uuid::new_v4();
        let outbox = vec![ServerMessage::ServerHello {
            session_id,
            client_identity: identity.client_identity.clone(),
            log_event_filter_mode: LogEventFilterMode::Remote,
            log_event_filter_conditions: serde_json::json!({}),
            filter_config_version: 0,
        }];

        Self {
            session_id,
            remote_identity: Some(identity),
            client_store_id: None,
            connection_state: ConnectionStateForSession::Handshaking,
            control_state: ControlState::NotEstablished,
            bound_targets: HashSet::new(),
            last_sequences: HashMap::new(),
            outbox,
            created_at: now,
            last_seen_at: now,
        }
    }

    /// 接受 client_hello(客户端握手) 并开放业务数据.
    ///
    /// 参数 `hello` 是客户端第一条消息.
    /// 参数 `now` 是握手时间.
    /// 返回值在握手成功时为空.
    pub fn accept_client_hello(
        &mut self,
        hello: ClientHello,
        now: OffsetDateTime,
    ) -> RelayResult<()> {
        if hello.client_store_id.trim().is_empty() {
            return Err(RelayError::new(
                "invalid_message_schema",
                "session",
                None,
                "client_store_id must not be empty",
                false,
            ));
        }

        if self.connection_state != ConnectionStateForSession::Handshaking {
            return Err(RelayError::new(
                "protocol_error",
                "session",
                None,
                "client_hello is only valid during handshaking",
                false,
            ));
        }

        self.client_store_id = Some(hello.client_store_id);
        self.connection_state = ConnectionStateForSession::Established;
        self.control_state = ControlState::Established;
        self.last_seen_at = now;
        Ok(())
    }

    /// 在 client_hello(客户端握手) 后发布 target list(目标列表).
    ///
    /// 参数 `targets` 是当前活动目标集合.
    pub fn publish_target_list(&mut self, targets: Vec<VisibleTarget>) {
        self.outbox.push(ServerMessage::TargetList { targets });
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

        let mut session = Self::server_hello(identity, now);
        session.accept_client_hello(
            ClientHello {
                client_store_id: "volatile-session".to_owned(),
                resume_cursor: ResumeCursor::default(),
            },
            now,
        )?;
        let targets = registry.active_targets(now);
        session.publish_target_list(targets);

        Ok(session)
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
        registry.ensure_target_active(target_id, now)?;
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

        registry.ensure_target_active(&command.target_id, now)?;
        registry.ensure_command_supported(&command.target_id, command.command)?;
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

    /// 取出并清空 session(会话) 输出队列.
    ///
    /// 参数为空, 因为该方法移动当前输出队列.
    /// 返回值是待发送服务端消息.
    pub fn drain_outbox(&mut self) -> Vec<ServerMessage> {
        std::mem::take(&mut self.outbox)
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
                ServerMessage::TargetList { targets } => Some(targets.len()),
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
