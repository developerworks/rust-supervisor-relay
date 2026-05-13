# ASSUMPTIONS(假设)

本实现遵守 `specs/003-supervisor-dashboard` 中 relay(中继) 的目录边界. 当前轮只写入 `/Users/0x00/Documents/rust-supervisor-relay`.

第一版 relay(中继) 不引入持久化数据库. command audit(命令审计), event(事件), log(日志) 和 dropped count(丢弃数量) 先保留在内存结构和 `wss://` 消息流中.

目标 IPC(进程间通信) 使用 Unix domain socket(Unix 域套接字) 加 newline-delimited JSON(按行分隔的 JSON 数据). 当前 crate(包) 使用 `UnixNdjsonIpcClient`(Unix 按行 JSON 进程间通信客户端) 作为 `TargetIpcPort`(目标进程通信端口) 的真实实现. 集成测试通过临时 `UnixListener`(Unix 监听器) 验证 relay(中继) 的安全顺序和转发边界.

`wss://` listener(监听器) 使用 `tokio-rustls` 和 `tokio-tungstenite`. 真实浏览器连接需要有效 server certificate(服务端证书), private key(私钥) 和 client CA(客户端证书颁发机构). relay(中继) 在业务数据前发送 `server_hello`, 并且只在 `client_hello` 校验成功后下发 target list(目标列表) 和后续业务消息.

trusted proxy(可信代理) 模式只接受配置中 `allowed_remote_addrs` 列出的 IP(网际协议地址) 传入身份 header(标头). 普通客户端伪造身份 header(标头) 会被拒绝.

relay(中继) 不持有 SupervisorHandle(监督器句柄). command forwarding(命令转发) 只能在 authenticated session(已认证会话) 建立, 目标完成 active registration(活动注册), 目标声明对应 supported_commands(支持的命令), 并且目标已经绑定 IPC(进程间通信) 后发生.
