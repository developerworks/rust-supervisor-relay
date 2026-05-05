# Dashboard Relay(看板中继) 运行说明

## 目录和职责

`/Users/0x00/Documents/rust-supervisor-relay` 拥有 relay(中继) binary(二进制入口), relay config(中继配置), target registry(目标注册表), mTLS identity(双向传输层安全协议认证身份), trusted proxy(可信代理), session gating(会话门控), IPC client(进程间通信客户端), fan out(分发) 和 command audit(命令审计). 当前 `rust-supervisor` 仓库只拥有目标侧 IPC(进程间通信) 和共享契约, UI(用户界面) 只通过 `wss://` 消费 relay(中继) 消息.

## 安全顺序

目标进程完成 dynamic registration(动态注册) 后, relay(中继) 只把它加入 TargetProcessRegistry(目标进程注册表). 这个动作不会连接目标 IPC(进程间通信), 不会建立 event/log subscription(事件日志订阅), 也不会触发目标进程主动推送.

远程客户端必须通过 `wss://` 建立连接. 默认模式下, relay(中继) 使用 mTLS(双向传输层安全协议认证) 校验 client certificate(客户端证书). 如果部署在 trusted proxy(可信代理) 后面, relay(中继) 只接受配置内代理地址传入的已验证身份 header(标头). `ws://` 不能建立完整 control session(控制会话).

control session(控制会话) 建立后, relay(中继) 首先发送 `session_established` 消息. 该消息包含 active registration(活动注册) 形成的 target process list(目标进程列表) 和 session(会话) 授权范围. 只有 session(会话) 后续绑定某个授权目标时, relay(中继) 才连接目标 IPC(进程间通信), 读取 snapshot(快照), 建立 event/log subscription(事件日志订阅), 并开始转发 event(事件), log(日志), state delta(状态增量) 和 dropped count(丢弃数量).

## 控制命令

relay(中继) 只接受 `restart_child`, `pause_child`, `resume_child`, `quarantine_child`, `remove_child`, `add_child` 和 `shutdown_tree`. 历史控制命令别名会返回 `unsupported_method` 结构化错误. 客户端不得提供 `requested_by`. relay(中继) 会从 RemoteIdentity(远程身份) 派生 requested_by(请求者), 并把该身份写入 ControlCommandRequest(控制命令请求) 和 AuditEvent(审计事件).

`shutdown_tree`, `remove_child` 和 `add_child` 是 dangerous command(危险命令), 必须提供 `confirmed=true`. 所有命令都必须提供非空 reason(原因). 每个 accepted(已接受), rejected(已拒绝) 和 completed(已完成) 结果都会写入 audit event(审计事件).

## 诊断

relay(中继) 对以下路径返回结构化错误: invalid public url(无效公开地址), missing client CA(缺少客户端证书颁发机构), empty allowed IPC path prefixes(空进程间通信路径前缀), duplicate target id(重复目标标识), duplicate IPC path(重复进程间通信路径), invalid lease(无效租约), untrusted proxy(不可信代理), insecure transport(不安全传输), unauthorized target(未授权目标), target not bound(目标未绑定), sequence not monotonic(序号不单调), reconnect timeout(重连超时), requested_by override(请求者覆盖) 和 unsupported method(不支持的方法).

## 命令

```bash
cargo run --manifest-path /Users/0x00/Documents/rust-supervisor-relay/Cargo.toml -- --config /Users/0x00/Documents/rust-supervisor-relay/examples/config/dashboard-relay.yaml --check
```

```bash
cargo test --manifest-path /Users/0x00/Documents/rust-supervisor-relay/Cargo.toml
```

这些命令只操作 relay(中继) 目录. 它们不会修改当前 `rust-supervisor` 仓库, 也不会修改 `rust-supervisor-ui` 目录.
