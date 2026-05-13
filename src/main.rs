//! The relay binary only loads configuration and starts the relay runtime.

use std::collections::HashMap;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use rust_supervisor_relay::audit::AuditRecorder;
use rust_supervisor_relay::auth::{AuthContext, RemoteIdentity};
use rust_supervisor_relay::config::{DashboardRelayConfig, TlsConfig, TrustedProxyConfig};
use rust_supervisor_relay::error::{RelayError, RelayResult};
use rust_supervisor_relay::ipc_client::UnixNdjsonIpcClient;
use rust_supervisor_relay::registration::RegistrationListener;
use rust_supervisor_relay::registry::TargetProcessRegistry;
use rust_supervisor_relay::session::{
    ClientMessage, DashboardSession, ServerMessage, decode_client_message,
};
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

type SharedRegistry = Arc<Mutex<TargetProcessRegistry>>;

/// Starts the relay binary.
///
/// Parameters come from process arguments.
/// The return value is the process exit code.
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

/// Runs the relay configuration loading and listening entry point.
///
/// This function has no parameters because command-line arguments are read through `std::env::args`.
/// The return value is successful when configuration checks or the run loop finish normally.
async fn run() -> RelayResult<()> {
    let args = Args::parse(std::env::args().skip(1).collect())?;
    let config = DashboardRelayConfig::load_from_path(&args.config_path)?;
    config.validate()?;

    if args.check_only {
        println!("relay config validated");
        return Ok(());
    }

    let registry = Arc::new(Mutex::new(TargetProcessRegistry::new(
        config.registration.clone(),
    )));
    let registration_listener = RegistrationListener::bind(&config.registration).await?;
    let registration_registry = Arc::clone(&registry);
    tokio::spawn(async move {
        if let Err(error) =
            run_registration_loop(registration_listener, registration_registry).await
        {
            tracing::error!(
                code = error.code,
                stage = error.stage,
                message = error.message,
                "registration loop exited"
            );
        }
    });

    let tls_config = build_server_config(&config.tls, config.trusted_proxy.enabled)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let trusted_proxy = config.trusted_proxy.clone();
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
                let (stream, remote_addr) = incoming.map_err(|error| {
                    RelayError::new(
                        "wss_accept_failed",
                        "wss_listen",
                        None,
                        format!("wss tcp connection could not be accepted: {error}"),
                        true,
                    )
                })?;
                let tls_acceptor = tls_acceptor.clone();
                let registry = Arc::clone(&registry);
                let trusted_proxy = trusted_proxy.clone();
                tokio::spawn(async move {
                    if let Err(error) =
                        handle_wss_connection(stream, remote_addr, tls_acceptor, trusted_proxy, registry)
                            .await
                    {
                        tracing::warn!(
                            code = error.code,
                            stage = error.stage,
                            message = error.message,
                            "dashboard session ended"
                        );
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

async fn run_registration_loop(
    listener: RegistrationListener,
    registry: SharedRegistry,
) -> RelayResult<()> {
    loop {
        let accepted = listener.accept_registration().await?;
        let now = OffsetDateTime::now_utc();
        let result = {
            let mut registry = registry.lock().await;
            registry.register(accepted.request, accepted.owner_identity, now)
        };
        write_registration_ack(accepted.stream, result).await?;
    }
}

async fn write_registration_ack(
    mut stream: tokio::net::UnixStream,
    result: RelayResult<rust_supervisor_relay::registry::TargetProcessRegistration>,
) -> RelayResult<()> {
    let payload = match result {
        Ok(registration) => serde_json::json!({
            "ok": true,
            "target_id": registration.target_id,
            "status": "registered",
            "retryable": false
        }),
        Err(error) => serde_json::json!({
            "ok": false,
            "error": {
                "code": error.code,
                "message": error.message
            },
            "retryable": error.retryable
        }),
    };
    let mut line = serde_json::to_vec(&payload).map_err(|error| {
        RelayError::new(
            "registration_ack_encode_failed",
            "registration_ack",
            None,
            format!("registration ack could not be encoded: {error}"),
            false,
        )
    })?;
    line.push(b'\n');
    stream.write_all(&line).await.map_err(|error| {
        RelayError::new(
            "registration_ack_write_failed",
            "registration_ack",
            None,
            format!("registration ack could not be written: {error}"),
            true,
        )
    })
}

async fn handle_wss_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
    trusted_proxy: TrustedProxyConfig,
    registry: SharedRegistry,
) -> RelayResult<()> {
    let tls_stream = tls_acceptor.accept(stream).await.map_err(|error| {
        RelayError::new(
            "tls_accept_failed",
            "tls",
            None,
            format!("tls connection could not be accepted: {error}"),
            true,
        )
    })?;
    let peer_certificate = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .map(|certificate| certificate.as_ref().to_vec());
    let mut request_headers = HashMap::new();
    let websocket =
        tokio_tungstenite::accept_hdr_async(tls_stream, |request: &Request, response: Response| {
            for (name, value) in request.headers() {
                if let Ok(value) = value.to_str() {
                    request_headers.insert(name.as_str().to_owned(), value.to_owned());
                }
            }
            Ok(response)
        })
        .await
        .map_err(|error| {
            RelayError::new(
                "websocket_upgrade_failed",
                "wss",
                None,
                format!("websocket upgrade failed: {error}"),
                true,
            )
        })?;

    let now = OffsetDateTime::now_utc();
    let identity = if trusted_proxy.enabled {
        AuthContext::identity_from_trusted_proxy(
            &trusted_proxy,
            remote_addr.ip(),
            &request_headers,
            now,
        )?
    } else {
        let certificate = peer_certificate.ok_or_else(|| {
            RelayError::new(
                "missing_client_certificate",
                "auth",
                None,
                "client certificate must be present for mTLS mode",
                false,
            )
        })?;
        AuthContext::identity_from_mtls_der(&certificate, now)?
    };

    run_dashboard_session(websocket, identity, registry).await
}

async fn run_dashboard_session<S>(
    websocket: WebSocketStream<S>,
    identity: RemoteIdentity,
    registry: SharedRegistry,
) -> RelayResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = websocket.split();
    let now = OffsetDateTime::now_utc();
    let mut session = DashboardSession::server_hello(identity, now);
    let ipc = UnixNdjsonIpcClient;
    let mut audit = AuditRecorder::default();

    send_messages(&mut sink, session.drain_outbox()).await?;

    let first_message = next_text_message(&mut stream).await?.ok_or_else(|| {
        RelayError::new(
            "protocol_error",
            "session",
            None,
            "client_hello is required before business messages",
            false,
        )
    })?;
    let first = decode_client_message(&first_message)?;
    let ClientMessage::ClientHello(hello) = first else {
        return send_error_and_close(
            &mut sink,
            RelayError::new(
                "protocol_error",
                "session",
                None,
                "client_hello must be the first client message",
                false,
            ),
        )
        .await;
    };

    session.accept_client_hello(hello, OffsetDateTime::now_utc())?;
    {
        let registry_guard = registry.lock().await;
        session.publish_target_list(registry_guard.active_targets(OffsetDateTime::now_utc()));
    }
    auto_bind_active_targets(&mut session, &registry, &ipc).await;
    send_messages(&mut sink, session.drain_outbox()).await?;

    while let Some(raw) = next_text_message(&mut stream).await? {
        match decode_client_message(&raw) {
            Ok(ClientMessage::Command(command)) => {
                let result = {
                    let mut registry_guard = registry.lock().await;
                    session.handle_command(
                        command,
                        &mut registry_guard,
                        &ipc,
                        &mut audit,
                        OffsetDateTime::now_utc(),
                    )
                };
                if let Err(error) = result {
                    send_messages(&mut sink, vec![ServerMessage::Error { error }]).await?;
                }
                send_messages(&mut sink, session.drain_outbox()).await?;
            }
            Ok(ClientMessage::LogEventFilterConditions(_conditions)) => {
                continue;
            }
            Ok(ClientMessage::ClientHello(_)) => {
                send_messages(
                    &mut sink,
                    vec![ServerMessage::Error {
                        error: RelayError::new(
                            "protocol_error",
                            "session",
                            None,
                            "client_hello is only valid as the first client message",
                            false,
                        ),
                    }],
                )
                .await?;
            }
            Err(error) => {
                send_messages(&mut sink, vec![ServerMessage::Error { error }]).await?;
            }
        }
    }

    Ok(())
}

async fn auto_bind_active_targets(
    session: &mut DashboardSession,
    registry: &SharedRegistry,
    ipc: &UnixNdjsonIpcClient,
) {
    let target_ids = {
        let registry_guard = registry.lock().await;
        registry_guard
            .active_targets(OffsetDateTime::now_utc())
            .into_iter()
            .map(|target| target.target_id)
            .collect::<Vec<_>>()
    };

    for target_id in target_ids {
        let mut registry_guard = registry.lock().await;
        let _ = session.bind_target(
            &target_id,
            &mut registry_guard,
            ipc,
            OffsetDateTime::now_utc(),
        );
    }
}

async fn next_text_message<S>(
    stream: &mut futures_util::stream::SplitStream<WebSocketStream<S>>,
) -> RelayResult<Option<String>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(message) = stream.next().await {
        let message = message.map_err(|error| {
            RelayError::new(
                "websocket_read_failed",
                "session",
                None,
                format!("websocket message could not be read: {error}"),
                true,
            )
        })?;
        if message.is_close() {
            return Ok(None);
        }
        if message.is_text() {
            return message
                .to_text()
                .map(|text| Some(text.to_owned()))
                .map_err(|error| {
                    RelayError::new(
                        "invalid_message_text",
                        "session",
                        None,
                        format!("websocket text message could not be read: {error}"),
                        false,
                    )
                });
        }
        if message.is_binary() {
            return String::from_utf8(message.into_data().to_vec())
                .map(Some)
                .map_err(|error| {
                    RelayError::new(
                        "invalid_message_binary",
                        "session",
                        None,
                        format!("websocket binary message was not UTF-8: {error}"),
                        false,
                    )
                });
        }
    }
    Ok(None)
}

async fn send_error_and_close<S>(
    sink: &mut futures_util::stream::SplitSink<WebSocketStream<S>, Message>,
    error: RelayError,
) -> RelayResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_messages(sink, vec![ServerMessage::Error { error }]).await
}

async fn send_messages<S>(
    sink: &mut futures_util::stream::SplitSink<WebSocketStream<S>, Message>,
    messages: Vec<ServerMessage>,
) -> RelayResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for message in messages {
        let text = serde_json::to_string(&message).map_err(|error| {
            RelayError::new(
                "server_message_encode_failed",
                "session",
                None,
                format!("server message could not be encoded: {error}"),
                false,
            )
        })?;
        sink.send(Message::Text(text.into()))
            .await
            .map_err(|error| {
                RelayError::new(
                    "websocket_write_failed",
                    "session",
                    None,
                    format!("websocket message could not be written: {error}"),
                    true,
                )
            })?;
    }
    Ok(())
}

/// Builds the rustls server configuration for mTLS or trusted-proxy mode.
///
/// The `tls` parameter is the TLS configuration.
/// The `trusted_proxy_enabled` parameter indicates whether client identity verification is completed by a trusted proxy.
/// The return value is the server configuration that can be passed to `TlsAcceptor`.
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

/// Reads a certificate chain from a PEM file.
///
/// The `path` parameter is the certificate file path.
/// The return value is the rustls certificate chain.
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

/// Reads a private key from a PEM file.
///
/// The `path` parameter is the private key file path.
/// The return value is the rustls private key.
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

/// `Args` stores command-line arguments for the relay binary.
struct Args {
    /// `config_path` is the relay YAML file path.
    config_path: PathBuf,
    /// `check_only` indicates that the binary should validate configuration and exit.
    check_only: bool,
}

impl Args {
    /// Parses command-line arguments.
    ///
    /// The `args` parameter is the argument list without the program name.
    /// The return value is the parsed `Args`, or a structured argument error.
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
