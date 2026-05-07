use rust_supervisor_relay::auth::RemoteIdentity;
use rust_supervisor_relay::config::DashboardRelayConfig;
use rust_supervisor_relay::ipc_client::RecordingIpcClient;
use rust_supervisor_relay::registration::RegistrationRequest;
use rust_supervisor_relay::registry::{ConnectionState, TargetProcessRegistry};
use rust_supervisor_relay::session::{DashboardSession, ServerMessage, TransportSecurity};
use time::OffsetDateTime;

fn config() -> DashboardRelayConfig {
    DashboardRelayConfig::from_yaml_str(
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
    .expect("config should parse")
}

fn registry_with_two_targets() -> TargetProcessRegistry {
    let config = config();
    let mut registry = TargetProcessRegistry::new(config.registration);
    let now = OffsetDateTime::UNIX_EPOCH;
    registry
        .register(
            RegistrationRequest::new(
                "payments-worker-a",
                "payments worker a",
                "/run/rust-supervisor/payments-worker-a.sock",
                "payments:operate",
                30,
            ),
            now,
        )
        .expect("registration should pass");
    registry
        .register(
            RegistrationRequest::new(
                "orders-worker-a",
                "orders worker a",
                "/run/rust-supervisor/orders-worker-a.sock",
                "orders:read",
                30,
            ),
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
        vec!["payments:operate".to_owned()],
        OffsetDateTime::UNIX_EPOCH,
        OffsetDateTime::UNIX_EPOCH + time::Duration::hours(1),
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("identity should validate")
}

#[test]
fn active_registration_only_builds_target_list_before_binding() {
    let registry = registry_with_two_targets();
    let ipc = RecordingIpcClient::default();

    assert_eq!(ipc.total_connect_count(), 0);

    let session = DashboardSession::establish(
        identity(),
        &registry,
        TransportSecurity::Wss,
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("wss session should establish");

    assert_eq!(ipc.total_connect_count(), 0);

    match session
        .outbox()
        .first()
        .expect("session should send first message")
    {
        ServerMessage::SessionEstablished {
            targets,
            authorization_scopes,
            ..
        } => {
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].target_id, "payments-worker-a");
            assert_eq!(targets[0].connection_state, ConnectionState::Registered);
            assert_eq!(authorization_scopes, &vec!["payments:operate".to_owned()]);
        }
        _ => panic!("first message must be session_established"),
    }
}

#[test]
fn authorized_binding_connects_state_and_event_log_subscription_after_session_established() {
    let mut registry = registry_with_two_targets();
    let ipc = RecordingIpcClient::default();
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

    assert_eq!(ipc.connect_count("payments-worker-a"), 1);
    assert_eq!(ipc.subscription_count("payments-worker-a"), 1);
    assert!(session.is_bound("payments-worker-a"));

    let state_index = session
        .outbox()
        .iter()
        .position(|message| matches!(message, ServerMessage::State { target_id, .. } if target_id == "payments-worker-a"))
        .expect("state should be sent after binding");
    assert!(state_index > 0);
}

#[test]
fn unauthorized_target_cannot_bind_and_does_not_touch_ipc() {
    let mut registry = registry_with_two_targets();
    let ipc = RecordingIpcClient::default();
    let mut session = DashboardSession::establish(
        identity(),
        &registry,
        TransportSecurity::Wss,
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("wss session should establish");

    let error = session
        .bind_target(
            "orders-worker-a",
            &mut registry,
            &ipc,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect_err("missing scope must block binding");

    assert_eq!(error.code, "unauthorized_target");
    assert_eq!(ipc.total_connect_count(), 0);
}
