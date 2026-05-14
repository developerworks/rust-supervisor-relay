# rust-supervisor-relay

`rust-supervisor-relay` 是 supervisor dashboard(监督器看板) 的独立 relay(中继) crate(包). 它只位于 `~/rust-supervisor-relay`, 不向 `~/rust-supervisor` 或 `~/rust-supervisor-ui` 写入实现文件.

## 能力边界

本 crate(包) 实现 DashboardRelayConfig(看板中继配置), target process(目标进程) dynamic registration(动态注册), active registration(活动注册), TargetProcessRegistry(目标进程注册表), mTLS(双向传输层安全协议认证) 身份派生, trusted proxy(可信代理) 校验, `wss://` 入口配置和 TLS(传输层安全协议) listener(监听器) 启动骨架. 它只在 authenticated client session(已认证客户端会话) 建立并绑定目标后, 才连接目标 IPC(进程间通信), 读取 state(状态), 建立 event/log subscription(事件日志订阅), 并允许 command forwarding(命令转发).

目标 IPC(进程间通信) 第一版使用 Unix domain socket(Unix 域套接字) 加 newline-delimited JSON(按行分隔的 JSON 数据). `UnixNdjsonIpcClient`(Unix 按行 JSON 进程间通信客户端) 是 `TargetIpcPort`(目标进程通信端口) 的真实实现. 测试通过临时 `UnixListener`(Unix 监听器) 驱动真实 socket(套接字) 请求响应.

## 配置

示例配置位于 `examples/config/dashboard-relay.yaml`. `listen.public_url` 必须使用 `wss://`. `registration.allowed_ipc_path_prefixes` 必须非空, 并且目标进程注册上报的 IPC path(进程间通信路径) 必须是绝对路径且位于允许前缀内. relay(中继) 配置不接受静态 target list(目标列表), 所有目标都必须通过 dynamic registration(动态注册) 进入 registry(注册表).

## 运行

```bash
cargo run --manifest-path ~/rust-supervisor-relay/Cargo.toml -- --config ~/rust-supervisor-relay/examples/config/dashboard-relay.yaml --check
```

`--check` 只校验 YAML(配置文件格式) 结构和安全策略. 去掉 `--check` 后, binary(二进制入口) 会绑定 registration socket(注册套接字) 和 `wss://` TCP(传输控制协议) listener(监听器), 并等待关闭信号. 真实运行需要提供 `tls.certificate_path`, `tls.private_key_path` 和 `tls.client_ca_path` 指向的证书文件.

## 验证

```bash
cargo fmt --manifest-path ~/rust-supervisor-relay/Cargo.toml
cargo test --manifest-path ~/rust-supervisor-relay/Cargo.toml
```

测试覆盖 registration(注册) 配置, 重复 target id(目标标识), 重复 IPC path(进程间通信路径), 无效租约, `ws://` 完整控制拒绝, trusted proxy(可信代理) 伪造身份拒绝, session gating(会话门控), 事件日志绑定顺序, sequence gap(序号缺口), reconnect timeout(重连超时), command requested_by(请求者) 派生, dangerous command(危险命令) 二次确认和 command audit(命令审计).
