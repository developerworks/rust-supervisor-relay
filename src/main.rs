//! relay binary(中继二进制入口) 只负责加载配置并启动 relay runtime(中继运行时).

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use rust_supervisor_relay::config::{DashboardRelayConfig, TlsConfig};
use rust_supervisor_relay::error::{RelayError, RelayResult};
use rust_supervisor_relay::registration::RegistrationListener;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};

/// 启动 relay binary(中继二进制入口).
///
/// 参数来自 process args(进程参数).
/// 返回值是 process exit code(进程退出代码).
#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{} at {}: {}", error.code, error.stage, error.message);
            ExitCode::FAILURE
        }
    }
}

/// 运行 relay(中继) 配置加载和监听入口.
///
/// 参数为空, 因为命令行参数通过 `std::env::args`(标准环境参数) 读取.
/// 返回值在配置检查或运行循环正常结束时为成功.
async fn run() -> RelayResult<()> {
    let args = Args::parse(std::env::args().skip(1).collect())?;
    let config = DashboardRelayConfig::load_from_path(&args.config_path)?;
    config.validate()?;

    if args.check_only {
        println!("relay config validated");
        return Ok(());
    }

    let _registration_listener = RegistrationListener::bind(&config.registration).await?;
    let tls_config = build_server_config(&config.tls, config.trusted_proxy.enabled)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(&config.listen.bind)
        .await
        .map_err(|error| {
            RelayError::new(
                "wss_bind_failed",
                "wss_listen",
                None,
                format!("wss listener could not bind: {error}"),
                true,
            )
        })?;

    println!("relay listening on {}", config.listen.public_url);

    loop {
        tokio::select! {
            incoming = listener.accept() => {
                let (stream, _) = incoming.map_err(|error| {
                    RelayError::new(
                        "wss_accept_failed",
                        "wss_listen",
                        None,
                        format!("wss tcp connection could not be accepted: {error}"),
                        true,
                    )
                })?;
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(tls_stream) = tls_acceptor.accept(stream).await {
                        let _ = tokio_tungstenite::accept_async(tls_stream).await;
                    }
                });
            }
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|error| {
                    RelayError::new(
                        "shutdown_signal_failed",
                        "runtime",
                        None,
                        format!("shutdown signal could not be read: {error}"),
                        true,
                    )
                })?;
                break;
            }
        }
    }

    Ok(())
}

/// 构建 mTLS(双向传输层安全协议认证) 或可信代理模式的 rustls(安全传输库) 服务端配置.
///
/// 参数 `tls` 是 TLS(传输层安全协议) 配置.
/// 参数 `trusted_proxy_enabled` 表示是否由可信代理完成客户端身份验证.
/// 返回值是可交给 `TlsAcceptor`(传输层安全协议接收器) 的服务端配置.
fn build_server_config(tls: &TlsConfig, trusted_proxy_enabled: bool) -> RelayResult<ServerConfig> {
    let certs = load_certs(&tls.certificate_path)?;
    let private_key = load_private_key(&tls.private_key_path)?;
    let builder = ServerConfig::builder();

    if trusted_proxy_enabled {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .map_err(|error| {
                RelayError::new(
                    "tls_config_failed",
                    "tls",
                    None,
                    format!("tls server config could not be built: {error}"),
                    false,
                )
            })
    } else {
        let mut roots = RootCertStore::empty();
        for cert in load_certs(&tls.client_ca_path)? {
            roots.add(cert).map_err(|error| {
                RelayError::new(
                    "client_ca_load_failed",
                    "tls",
                    None,
                    format!("client ca certificate could not be added: {error}"),
                    false,
                )
            })?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| {
                RelayError::new(
                    "client_ca_verifier_failed",
                    "tls",
                    None,
                    format!("client certificate verifier could not be built: {error}"),
                    false,
                )
            })?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, private_key)
            .map_err(|error| {
                RelayError::new(
                    "tls_config_failed",
                    "tls",
                    None,
                    format!("tls server config could not be built: {error}"),
                    false,
                )
            })
    }
}

/// 从 PEM(隐私增强邮件格式) 文件读取证书链.
///
/// 参数 `path` 是证书文件路径.
/// 返回值是 rustls(安全传输库) 证书链.
fn load_certs(
    path: &Path,
) -> RelayResult<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path).map_err(|error| {
        RelayError::new(
            "cert_read_failed",
            "tls",
            None,
            format!("certificate file could not be opened: {error}"),
            false,
        )
    })?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            RelayError::new(
                "cert_parse_failed",
                "tls",
                None,
                format!("certificate file could not be parsed: {error}"),
                false,
            )
        })
}

/// 从 PEM(隐私增强邮件格式) 文件读取私钥.
///
/// 参数 `path` 是私钥文件路径.
/// 返回值是 rustls(安全传输库) 私钥.
fn load_private_key(
    path: &Path,
) -> RelayResult<tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path).map_err(|error| {
        RelayError::new(
            "key_read_failed",
            "tls",
            None,
            format!("private key file could not be opened: {error}"),
            false,
        )
    })?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| {
            RelayError::new(
                "key_parse_failed",
                "tls",
                None,
                format!("private key file could not be parsed: {error}"),
                false,
            )
        })?
        .ok_or_else(|| {
            RelayError::new(
                "missing_private_key",
                "tls",
                None,
                "private key file does not contain a supported key",
                false,
            )
        })
}

/// `Args`(参数) 保存 relay binary(中继二进制入口) 的命令行参数.
struct Args {
    /// `config_path`(配置路径) 是 relay(中继) YAML(配置文件格式) 文件路径.
    config_path: PathBuf,
    /// `check_only`(只检查) 表示只校验配置并退出.
    check_only: bool,
}

impl Args {
    /// 解析命令行参数.
    ///
    /// 参数 `args` 是去掉程序名后的参数列表.
    /// 返回值是解析后的 `Args`(参数), 或者结构化参数错误.
    fn parse(args: Vec<String>) -> RelayResult<Self> {
        let mut config_path = None;
        let mut check_only = false;
        let mut index = 0;

        while index < args.len() {
            match args[index].as_str() {
                "--config" => {
                    let value = args.get(index + 1).ok_or_else(|| {
                        RelayError::new(
                            "missing_config_arg",
                            "args",
                            None,
                            "--config requires a path",
                            false,
                        )
                    })?;
                    config_path = Some(PathBuf::from(value));
                    index += 2;
                }
                "--check" => {
                    check_only = true;
                    index += 1;
                }
                other => {
                    return Err(RelayError::new(
                        "unknown_arg",
                        "args",
                        None,
                        format!("unknown argument: {other}"),
                        false,
                    ));
                }
            }
        }

        let config_path = config_path.ok_or_else(|| {
            RelayError::new(
                "missing_config_arg",
                "args",
                None,
                "--config is required",
                false,
            )
        })?;

        Ok(Self {
            config_path,
            check_only,
        })
    }
}
