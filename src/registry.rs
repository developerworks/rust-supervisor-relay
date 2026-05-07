//! registry(注册表) 模块维护目标进程 active registration(活动注册) 和连接状态.
//!
//! 注册只把目标放入可见列表. 只有已认证 session(会话) 绑定目标后, 才允许进入 IPC(进程间通信) 连接.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::config::RegistrationPolicy;
use crate::error::{RelayError, RelayResult};
use crate::registration::RegistrationRequest;

/// `RegistrationState`(注册状态) 表示目标进程注册租约的状态.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    /// `Active`(活动) 表示注册租约仍然有效.
    Active,
    /// `Rejected`(已拒绝) 表示注册载荷没有进入活动表.
    Rejected,
    /// `Expired`(已过期) 表示租约已经失效.
    Expired,
}

/// `ConnectionState`(连接状态) 表示 relay(中继) 与目标 IPC(进程间通信) 的生命周期.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// `Registered`(已注册) 表示目标只进入注册表, 尚未连接 IPC(进程间通信).
    Registered,
    /// `Disconnected`(已断开) 表示目标没有活动 IPC(进程间通信) 连接.
    Disconnected,
    /// `Connecting`(连接中) 表示已认证 session(会话) 正在触发 IPC(进程间通信) 连接.
    Connecting,
    /// `Connected`(已连接) 表示 IPC(进程间通信) 握手和 state(状态) 读取成功.
    Connected,
    /// `Reconnecting`(重连中) 表示连接失败后正在重试.
    Reconnecting,
    /// `Unavailable`(不可用) 表示目标 IPC(进程间通信) 当前不可达.
    Unavailable,
    /// `Expired`(已过期) 表示目标注册租约已经失效.
    Expired,
}

/// `TargetProcessRegistration`(目标进程注册) 是注册表保存的活动记录.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetProcessRegistration {
    /// `target_id`(目标标识) 是目标进程稳定身份.
    pub target_id: String,
    /// `display_name`(显示名称) 是 dashboard(看板) 展示名称.
    pub display_name: String,
    /// `ipc_path`(进程间通信路径) 是目标进程本机 socket(套接字) 路径.
    pub ipc_path: PathBuf,
    /// `authorization_scope`(授权范围) 是访问该目标需要的 scope(授权范围).
    pub authorization_scope: String,
    /// `lease_seconds`(租约秒数) 是注册有效期.
    pub lease_seconds: u64,
    /// `registered_at`(注册时间) 是首次进入注册表的时间.
    pub registered_at: OffsetDateTime,
    /// `renewed_at`(续约时间) 是最近一次续约时间.
    pub renewed_at: OffsetDateTime,
    /// `expires_at`(过期时间) 是当前租约失效时间.
    pub expires_at: OffsetDateTime,
    /// `registration_state`(注册状态) 是当前租约状态.
    pub registration_state: RegistrationState,
    /// `last_rejection`(最近拒绝) 保存最近一次拒绝原因.
    pub last_rejection: Option<String>,
}

/// `TargetProcessConnection`(目标进程连接) 保存一个目标的 IPC(进程间通信) 连接状态.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetProcessConnection {
    /// `target_id`(目标标识) 是目标进程稳定身份.
    pub target_id: String,
    /// `ipc_path`(进程间通信路径) 是目标进程本机 socket(套接字) 路径.
    pub ipc_path: PathBuf,
    /// `state`(状态) 是当前连接生命周期.
    pub state: ConnectionState,
    /// `last_error`(最近错误) 保存最近一次结构化错误.
    pub last_error: Option<String>,
    /// `last_state_generation`(最近状态代次) 保存已发送的 state(状态) 代次.
    pub last_state_generation: Option<u64>,
    /// `last_sequence`(最近序号) 保存已转发的事件 sequence(序号).
    pub last_sequence: Option<u64>,
    /// `connected_at`(连接时间) 保存最近成功连接时间.
    pub connected_at: Option<OffsetDateTime>,
    /// `updated_at`(更新时间) 保存状态最近变化时间.
    pub updated_at: OffsetDateTime,
}

/// `VisibleTarget`(可见目标) 是 session(会话) 首包发送给 dashboard(看板) 的目标摘要.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisibleTarget {
    /// `target_id`(目标标识) 是目标进程稳定身份.
    pub target_id: String,
    /// `display_name`(显示名称) 是 dashboard(看板) 展示名称.
    pub display_name: String,
    /// `registration_state`(注册状态) 表达租约是否活动.
    pub registration_state: RegistrationState,
    /// `connection_state`(连接状态) 表达 relay(中继) 是否已经连接 IPC(进程间通信).
    pub connection_state: ConnectionState,
    /// `authorization_scope`(授权范围) 是访问该目标需要的 scope(授权范围).
    pub authorization_scope: String,
}

/// `AvailabilitySummary`(可用性汇总) 保存多目标 partial availability(部分可用) 状态.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilitySummary {
    /// `total`(总数) 是注册表中所有目标数量.
    pub total: usize,
    /// `registered`(已注册数量) 是尚未绑定连接的目标数量.
    pub registered: usize,
    /// `connected`(已连接数量) 是 IPC(进程间通信) 已连接的目标数量.
    pub connected: usize,
    /// `reconnecting`(重连中数量) 是正在重连的目标数量.
    pub reconnecting: usize,
    /// `unavailable`(不可用数量) 是当前不可达的目标数量.
    pub unavailable: usize,
    /// `expired`(已过期数量) 是租约过期的目标数量.
    pub expired: usize,
}

/// `TargetProcessRegistry`(目标进程注册表) 保存 active registration(活动注册) 和连接状态.
pub struct TargetProcessRegistry {
    /// `policy`(策略) 保存注册路径, IPC(进程间通信) 前缀和租约限制.
    policy: RegistrationPolicy,
    /// `registrations`(注册记录) 通过 target id(目标标识) 查找活动记录.
    registrations: HashMap<String, TargetProcessRegistration>,
    /// `connections`(连接记录) 通过 target id(目标标识) 查找连接生命周期.
    connections: HashMap<String, TargetProcessConnection>,
}

impl TargetProcessRegistry {
    /// 创建目标进程注册表.
    ///
    /// 参数 `policy` 是注册策略.
    /// 返回值是空的注册表.
    pub fn new(policy: RegistrationPolicy) -> Self {
        Self {
            policy,
            registrations: HashMap::new(),
            connections: HashMap::new(),
        }
    }

    /// 注册一个目标进程.
    ///
    /// 参数 `request` 是目标进程提交的 dynamic registration(动态注册) 请求.
    /// 参数 `now` 是 relay(中继) 接收注册的时间.
    /// 返回值是活动注册记录, 或者结构化拒绝错误.
    pub fn register(
        &mut self,
        request: RegistrationRequest,
        now: OffsetDateTime,
    ) -> RelayResult<TargetProcessRegistration> {
        self.validate_request(&request)?;

        if self.registrations.contains_key(&request.target_id) {
            return Err(RelayError::for_target(
                "duplicate_target_id",
                "registration",
                request.target_id,
                "target id is already registered",
                false,
            ));
        }

        if self
            .registrations
            .values()
            .any(|registration| registration.ipc_path == request.ipc_path)
        {
            return Err(RelayError::new(
                "duplicate_ipc_path",
                "registration",
                None,
                "IPC path is already registered",
                false,
            ));
        }

        let expires_at = now + Duration::seconds(request.lease_seconds as i64);
        let registration = TargetProcessRegistration {
            target_id: request.target_id.clone(),
            display_name: request.display_name,
            ipc_path: request.ipc_path.clone(),
            authorization_scope: request.authorization_scope,
            lease_seconds: request.lease_seconds,
            registered_at: now,
            renewed_at: now,
            expires_at,
            registration_state: RegistrationState::Active,
            last_rejection: None,
        };
        let connection = TargetProcessConnection {
            target_id: request.target_id.clone(),
            ipc_path: request.ipc_path,
            state: ConnectionState::Registered,
            last_error: None,
            last_state_generation: None,
            last_sequence: None,
            connected_at: None,
            updated_at: now,
        };

        self.connections
            .insert(request.target_id.clone(), connection);
        self.registrations
            .insert(request.target_id, registration.clone());
        Ok(registration)
    }

    /// 续期一个已注册目标.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `now` 是续期时间.
    /// 返回值在续期成功时为空.
    pub fn renew(&mut self, target_id: &str, now: OffsetDateTime) -> RelayResult<()> {
        let registration = self.registrations.get_mut(target_id).ok_or_else(|| {
            RelayError::for_target(
                "target_not_registered",
                "registration_renew",
                target_id,
                "target is not registered",
                true,
            )
        })?;
        registration.renewed_at = now;
        registration.expires_at = now + Duration::seconds(registration.lease_seconds as i64);
        registration.registration_state = RegistrationState::Active;
        Ok(())
    }

    /// 标记已经过期的注册.
    ///
    /// 参数 `now` 是当前时间.
    /// 返回值是本次被标记为 expired(已过期) 的目标数量.
    pub fn expire_leases(&mut self, now: OffsetDateTime) -> usize {
        let mut expired = 0;
        for registration in self.registrations.values_mut() {
            if registration.registration_state == RegistrationState::Active
                && registration.expires_at <= now
            {
                registration.registration_state = RegistrationState::Expired;
                if let Some(connection) = self.connections.get_mut(&registration.target_id) {
                    connection.state = ConnectionState::Expired;
                    connection.updated_at = now;
                }
                expired += 1;
            }
        }
        expired
    }

    /// 返回 active registration(活动注册) 的数量.
    ///
    /// 参数 `now` 是当前时间.
    /// 返回值是未过期且状态为 active(活动) 的注册数量.
    pub fn active_registration_count(&self, now: OffsetDateTime) -> usize {
        self.registrations
            .values()
            .filter(|registration| {
                registration.registration_state == RegistrationState::Active
                    && registration.expires_at > now
            })
            .count()
    }

    /// 根据授权范围返回可见目标.
    ///
    /// 参数 `authorization_scopes` 是 session(会话) 拥有的授权范围.
    /// 参数 `now` 是当前时间.
    /// 返回值是该 session(会话) 可以看到的活动目标列表.
    pub fn visible_targets_for_scopes(
        &self,
        authorization_scopes: &[String],
        now: OffsetDateTime,
    ) -> Vec<VisibleTarget> {
        self.registrations
            .values()
            .filter(|registration| {
                registration.registration_state == RegistrationState::Active
                    && registration.expires_at > now
                    && authorization_scopes.contains(&registration.authorization_scope)
            })
            .map(|registration| VisibleTarget {
                target_id: registration.target_id.clone(),
                display_name: registration.display_name.clone(),
                registration_state: registration.registration_state,
                connection_state: self
                    .connections
                    .get(&registration.target_id)
                    .map(|connection| connection.state)
                    .unwrap_or(ConnectionState::Unavailable),
                authorization_scope: registration.authorization_scope.clone(),
            })
            .collect()
    }

    /// 读取一个活动注册.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 返回值是目标注册记录, 或者未注册错误.
    pub fn registration(&self, target_id: &str) -> RelayResult<&TargetProcessRegistration> {
        self.registrations.get(target_id).ok_or_else(|| {
            RelayError::for_target(
                "target_not_registered",
                "registry",
                target_id,
                "target is not registered",
                true,
            )
        })
    }

    /// 判断 session(会话) 是否有权限访问目标.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `authorization_scopes` 是 session(会话) 拥有的授权范围.
    /// 参数 `now` 是当前时间.
    /// 返回值在目标活动且 scope(授权范围) 匹配时为成功.
    pub fn ensure_authorized(
        &self,
        target_id: &str,
        authorization_scopes: &[String],
        now: OffsetDateTime,
    ) -> RelayResult<()> {
        let registration = self.registration(target_id)?;
        if registration.registration_state != RegistrationState::Active
            || registration.expires_at <= now
        {
            return Err(RelayError::for_target(
                "target_registration_expired",
                "authorization",
                target_id,
                "target registration is not active",
                true,
            ));
        }

        if !authorization_scopes.contains(&registration.authorization_scope) {
            return Err(RelayError::for_target(
                "unauthorized_target",
                "authorization",
                target_id,
                "remote identity does not have target authorization scope",
                false,
            ));
        }

        Ok(())
    }

    /// 标记目标开始绑定 IPC(进程间通信).
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `now` 是状态变化时间.
    /// 返回值在状态变化成功时为空.
    pub fn begin_binding(&mut self, target_id: &str, now: OffsetDateTime) -> RelayResult<()> {
        let connection = self.connection_mut(target_id)?;
        connection.state = ConnectionState::Connecting;
        connection.updated_at = now;
        Ok(())
    }

    /// 标记目标 IPC(进程间通信) 已连接.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `state_generation` 是连接后读取到的 state(状态) 代次.
    /// 参数 `now` 是状态变化时间.
    /// 返回值在状态变化成功时为空.
    pub fn mark_connected(
        &mut self,
        target_id: &str,
        state_generation: u64,
        now: OffsetDateTime,
    ) -> RelayResult<()> {
        let connection = self.connection_mut(target_id)?;
        connection.state = ConnectionState::Connected;
        connection.last_state_generation = Some(state_generation);
        connection.connected_at = Some(now);
        connection.updated_at = now;
        connection.last_error = None;
        Ok(())
    }

    /// 标记目标 IPC(进程间通信) 正在重连.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `reason` 是重连原因.
    /// 参数 `now` 是状态变化时间.
    /// 返回值在状态变化成功时为空.
    pub fn mark_reconnecting(
        &mut self,
        target_id: &str,
        reason: impl Into<String>,
        now: OffsetDateTime,
    ) {
        if let Ok(connection) = self.connection_mut(target_id) {
            connection.state = ConnectionState::Reconnecting;
            connection.last_error = Some(reason.into());
            connection.updated_at = now;
        }
    }

    /// 标记目标 IPC(进程间通信) 不可用.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `reason` 是不可用原因.
    /// 参数 `now` 是状态变化时间.
    pub fn mark_unavailable(
        &mut self,
        target_id: &str,
        reason: impl Into<String>,
        now: OffsetDateTime,
    ) {
        if let Ok(connection) = self.connection_mut(target_id) {
            connection.state = ConnectionState::Unavailable;
            connection.last_error = Some(reason.into());
            connection.updated_at = now;
        }
    }

    /// 读取目标连接状态.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 返回值是连接状态, 或者在目标不存在时返回空.
    pub fn connection_state(&self, target_id: &str) -> Option<ConnectionState> {
        self.connections
            .get(target_id)
            .map(|connection| connection.state)
    }

    /// 汇总所有目标的 partial availability(部分可用) 状态.
    ///
    /// 参数为空, 因为汇总读取注册表中的连接状态.
    /// 返回值是连接状态数量汇总.
    pub fn availability_summary(&self) -> AvailabilitySummary {
        let mut summary = AvailabilitySummary {
            total: self.connections.len(),
            ..AvailabilitySummary::default()
        };
        for connection in self.connections.values() {
            match connection.state {
                ConnectionState::Registered
                | ConnectionState::Disconnected
                | ConnectionState::Connecting => {
                    summary.registered += 1;
                }
                ConnectionState::Connected => summary.connected += 1,
                ConnectionState::Reconnecting => summary.reconnecting += 1,
                ConnectionState::Unavailable => summary.unavailable += 1,
                ConnectionState::Expired => summary.expired += 1,
            }
        }
        summary
    }

    /// 更新目标最近收到的 sequence(序号).
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 参数 `sequence` 是事件序号.
    /// 返回值是上一条序号, 或者在没有记录时返回空.
    pub fn update_sequence(&mut self, target_id: &str, sequence: u64) -> Option<u64> {
        self.connections.get_mut(target_id).and_then(|connection| {
            let previous = connection.last_sequence;
            connection.last_sequence = Some(sequence);
            previous
        })
    }

    /// 校验注册请求.
    ///
    /// 参数 `request` 是目标进程提交的注册载荷.
    /// 返回值在注册载荷满足安全策略时为空.
    fn validate_request(&self, request: &RegistrationRequest) -> RelayResult<()> {
        if request.target_id.trim().is_empty() {
            return Err(RelayError::new(
                "empty_target_id",
                "registration",
                None,
                "target id must not be empty",
                false,
            ));
        }

        if !request.ipc_path.is_absolute() {
            return Err(RelayError::for_target(
                "relative_ipc_path",
                "registration",
                request.target_id.clone(),
                "IPC path must be absolute",
                false,
            ));
        }

        if !self.policy.ipc_path_is_allowed(&request.ipc_path) {
            return Err(RelayError::for_target(
                "ipc_path_not_allowed",
                "registration",
                request.target_id.clone(),
                "IPC path is outside allowed prefixes",
                false,
            ));
        }

        if request.authorization_scope.trim().is_empty() {
            return Err(RelayError::for_target(
                "empty_authorization_scope",
                "registration",
                request.target_id.clone(),
                "authorization scope must not be empty",
                false,
            ));
        }

        if request.lease_seconds == 0 || request.lease_seconds > self.policy.max_lease_seconds {
            return Err(RelayError::for_target(
                "invalid_lease_seconds",
                "registration",
                request.target_id.clone(),
                "lease seconds must be positive and must not exceed policy max",
                false,
            ));
        }

        Ok(())
    }

    /// 读取可变连接记录.
    ///
    /// 参数 `target_id` 是目标进程标识.
    /// 返回值是可变连接记录, 或者未注册错误.
    fn connection_mut(&mut self, target_id: &str) -> RelayResult<&mut TargetProcessConnection> {
        self.connections.get_mut(target_id).ok_or_else(|| {
            RelayError::for_target(
                "target_not_registered",
                "registry",
                target_id,
                "target connection is not registered",
                true,
            )
        })
    }
}
