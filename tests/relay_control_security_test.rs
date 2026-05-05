use std::collections::HashMap;
use std::net::IpAddr;

use rust_supervisor_relay::audit::AuditRecorder;
use rust_supervisor_relay::auth::{AuthContext, RemoteIdentity};
use rust_supervisor_relay::command::{ClientCommand, CommandTarget, ControlCommandName};
use rust_supervisor_relay::config::{DashboardRelayConfig, TrustedProxyConfig};
use rust_supervisor_relay::ipc_client::RecordingIpcClient;
use rust_supervisor_relay::registration::RegistrationRequest;
use rust_supervisor_relay::registry::TargetProcessRegistry;
use rust_supervisor_relay::session::{DashboardSession, TransportSecurity};
use time::OffsetDateTime;

fn registry() -> TargetProcessRegistry {
    let config = DashboardRelayConfig::from_yaml_str(
        r#"
listen:
  bind: "127.0.0.1:9443"
  public_url: "wss://localhost:9443/supervisor"
tls:
  certificate_path: "./certs/relay.crt"
  private_key_path: "./certs/relay.key"
  client_ca_path: "./certs/operators-ca.crt"
trusted_proxy:
  enabled: false
  allowed_remote_addrs: []
  identity_header: "x-verified-client-subject"
registration:
  listen_path: /run/rust-supervisor/dashboard-relay-registration.sock
  permissions: "0600"
  allowed_ipc_path_prefixes:
    - /run/rust-supervisor/
  default_lease_seconds: 30
  max_lease_seconds: 120
authorization_defaults:
  unknown_scope_policy: reject
"#,
    )
    .expect("config should parse");
    let mut registry = TargetProcessRegistry::new(config.registration);
    registry
        .register(
            RegistrationRequest::new(
                "payments-worker-a",
                "payments worker a",
                "/run/rust-supervisor/payments-worker-a.sock",
                "payments:operate",
                30,
            ),
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("registration should pass");
    registry
}

fn identity() -> RemoteIdentity {
    RemoteIdentity::from_verified_mtls_subject(
        "CN=operator@example.test",
        "CN=operators-ca",
        "01",
        vec!["payments:operate".to_owned()],
        OffsetDateTime::UNIX_EPOCH,
        OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("identity should validate")
}

fn restart_command() -> ClientCommand {
    ClientCommand {
        command_id: "cmd-1".to_owned(),
        target_id: "payments-worker-a".to_owned(),
        command: ControlCommandName::RestartChild,
        target: CommandTarget {
            child_path: Some("/root/payment_loop".to_owned()),
        },
        reason: "operator requested restart after upstream recovery".to_owned(),
        confirmed: false,
        requested_by: None,
    }
}

#[test]
fn ws_transport_cannot_establish_full_control_session() {
    let registry = registry();
    let error = DashboardSession::establish(
        identity(),
        &registry,
        TransportSecurity::Ws,
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect_err("ws:// must be rejected for full control");

    assert_eq!(error.code, "insecure_transport");
}

#[test]
fn unauthenticated_or_unbound_commands_do_not_forward_to_ipc() {
    let mut registry = registry();
    let ipc = RecordingIpcClient::default();
    let mut audit = AuditRecorder::default();
    let mut unauthenticated = DashboardSession::unauthenticated(OffsetDateTime::UNIX_EPOCH);

    let unauth_error = unauthenticated
        .handle_command(
            restart_command(),
            &mut registry,
            &ipc,
            &mut audit,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect_err("unauthenticated command must fail");

    assert_eq!(unauth_error.code, "session_not_established");
    assert_eq!(ipc.total_command_count(), 0);

    let mut established = DashboardSession::establish(
        identity(),
        &registry,
        TransportSecurity::Wss,
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("session should establish");
    let unbound_error = established
        .handle_command(
            restart_command(),
            &mut registry,
            &ipc,
            &mut audit,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect_err("unbound target must fail");

    assert_eq!(unbound_error.code, "target_not_bound");
    assert_eq!(ipc.total_command_count(), 0);
}

#[test]
fn trusted_proxy_identity_header_is_rejected_from_untrusted_remote_address() {
    let proxy = TrustedProxyConfig {
        enabled: true,
        allowed_remote_addrs: vec!["10.0.0.10".to_owned()],
        identity_header: "x-verified-client-subject".to_owned(),
    };
    let mut headers = HashMap::new();
    headers.insert(
        "x-verified-client-subject".to_owned(),
        "operator@example.test".to_owned(),
    );

    let error = AuthContext::identity_from_trusted_proxy(
        &proxy,
        "203.0.113.42".parse::<IpAddr>().expect("ip should parse"),
        &headers,
        vec!["payments:operate".to_owned()],
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect_err("untrusted remote address must not provide identity");

    assert_eq!(error.code, "untrusted_proxy");
}

#[test]
fn bound_command_derives_requested_by_and_never_uses_client_override() {
    let mut registry = registry();
    let ipc = RecordingIpcClient::default();
    let mut audit = AuditRecorder::default();
    let mut session = DashboardSession::establish(
        identity(),
        &registry,
        TransportSecurity::Wss,
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("session should establish");

    session
        .bind_target(
            "payments-worker-a",
            &mut registry,
            &ipc,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("target should bind");

    let result = session
        .handle_command(
            restart_command(),
            &mut registry,
            &ipc,
            &mut audit,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("authorized command should forward");

    assert_eq!(result.requested_by, "CN=operator@example.test");
    assert_eq!(ipc.command_count("payments-worker-a"), 1);

    let mut spoofed = restart_command();
    spoofed.command_id = "cmd-2".to_owned();
    spoofed.requested_by = Some("attacker@example.test".to_owned());
    let spoof_error = session
        .handle_command(
            spoofed,
            &mut registry,
            &ipc,
            &mut audit,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect_err("client requested_by override must be rejected");
    assert_eq!(spoof_error.code, "requested_by_override");
}
