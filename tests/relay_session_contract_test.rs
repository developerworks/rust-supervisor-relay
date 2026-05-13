mod support;

use rust_supervisor_relay::auth::RemoteIdentity;
use rust_supervisor_relay::config::DashboardRelayConfig;
use rust_supervisor_relay::ipc_client::UnixNdjsonIpcClient;
use rust_supervisor_relay::registration::{RegistrationRequest, SupportedCommand};
use rust_supervisor_relay::registry::{ConnectionState, TargetProcessRegistry};
use rust_supervisor_relay::session::{DashboardSession, ServerMessage, TransportSecurity};
use support::ProtocolTestTarget;
use time::OffsetDateTime;

fn config(first_prefix: &std::path::Path, second_prefix: &std::path::Path) -> DashboardRelayConfig {
    DashboardRelayConfig::from_yaml_str(&format!(
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
    - {}
    - {}
  default_lease_seconds: 30
  max_lease_seconds: 120
"#,
        first_prefix.display(),
        second_prefix.display()
    ))
    .expect("config should parse")
}

fn registry_with_two_targets(
    payments_target: &ProtocolTestTarget,
    orders_target: &ProtocolTestTarget,
) -> TargetProcessRegistry {
    let config = config(
        payments_target.allowed_prefix(),
        orders_target.allowed_prefix(),
    );
    let mut registry = TargetProcessRegistry::new(config.registration);
    let now = OffsetDateTime::UNIX_EPOCH;
    registry
        .register(
            RegistrationRequest::new(
                "payments-worker-a",
                "payments worker a",
                payments_target.path(),
                30,
                vec![SupportedCommand::new("restart_child", false, 30)],
            ),
            "uid:501",
            now,
        )
        .expect("registration should pass");
    registry
        .register(
            RegistrationRequest::new(
                "orders-worker-a",
                "orders worker a",
                orders_target.path(),
                30,
                vec![SupportedCommand::new("restart_child", false, 30)],
            ),
            "uid:501",
            now,
        )
        .expect("registration should pass");
    registry
}

fn identity() -> RemoteIdentity {
    RemoteIdentity::from_verified_mtls_subject(
        "CN=operator@example.test",
        "CN=operators-ca",
        "01",
        OffsetDateTime::UNIX_EPOCH,
        OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("identity should validate")
}

#[test]
fn active_registration_builds_target_list_after_client_hello_before_binding() {
    let payments_target = ProtocolTestTarget::start("payments-worker-a");
    let orders_target = ProtocolTestTarget::start("orders-worker-a");
    let registry = registry_with_two_targets(&payments_target, &orders_target);

    let session = DashboardSession::establish(
        identity(),
        &registry,
        TransportSecurity::Wss,
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("wss session should establish");

    assert!(matches!(
        session.outbox().first(),
        Some(ServerMessage::ServerHello { .. })
    ));
    match session
        .outbox()
        .iter()
        .find(|message| matches!(message, ServerMessage::TargetList { .. }))
        .expect("session should send target list after client hello")
    {
        ServerMessage::TargetList { targets } => {
            assert_eq!(targets.len(), 2);
            assert_eq!(targets[0].connection_state, ConnectionState::Registered);
        }
        _ => unreachable!(),
    }
}

#[test]
fn binding_connects_state_and_event_log_subscription_after_session_established() {
    let payments_target = ProtocolTestTarget::start("payments-worker-a");
    let orders_target = ProtocolTestTarget::start("orders-worker-a");
    let mut registry = registry_with_two_targets(&payments_target, &orders_target);
    let ipc = UnixNdjsonIpcClient;
    let mut session = DashboardSession::establish(
        identity(),
        &registry,
        TransportSecurity::Wss,
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("wss session should establish");

    session
        .bind_target(
            "payments-worker-a",
            &mut registry,
            &ipc,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("authorized target should bind");

    assert!(session.is_bound("payments-worker-a"));

    let state_index = session
        .outbox()
        .iter()
        .position(|message| matches!(message, ServerMessage::State { target_id, .. } if target_id == "payments-worker-a"))
        .expect("state should be sent after binding");
    assert!(state_index > 0);
}

#[test]
fn auto_bind_phase_allows_any_active_target_without_ui_permission_check() {
    let payments_target = ProtocolTestTarget::start("payments-worker-a");
    let orders_target = ProtocolTestTarget::start("orders-worker-a");
    let mut registry = registry_with_two_targets(&payments_target, &orders_target);
    let ipc = UnixNdjsonIpcClient;
    let mut session = DashboardSession::establish(
        identity(),
        &registry,
        TransportSecurity::Wss,
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("wss session should establish");

    session
        .bind_target(
            "orders-worker-a",
            &mut registry,
            &ipc,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("current phase binds any active target");

    assert!(session.is_bound("orders-worker-a"));
}
