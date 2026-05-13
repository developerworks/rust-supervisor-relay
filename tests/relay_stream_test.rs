mod support;

use rust_supervisor_relay::auth::RemoteIdentity;
use rust_supervisor_relay::config::DashboardRelayConfig;
use rust_supervisor_relay::ipc_client::UnixNdjsonIpcClient;
use rust_supervisor_relay::registration::{RegistrationRequest, SupportedCommand};
use rust_supervisor_relay::registry::TargetProcessRegistry;
use rust_supervisor_relay::relay::RelayHub;
use rust_supervisor_relay::session::{DashboardSession, ServerMessage, TransportSecurity};
use support::ProtocolTestTarget;
use time::OffsetDateTime;

fn session_with_registry() -> (
    DashboardSession,
    TargetProcessRegistry,
    UnixNdjsonIpcClient,
    ProtocolTestTarget,
) {
    let target = ProtocolTestTarget::start("payments-worker-a");
    let config = DashboardRelayConfig::from_yaml_str(&format!(
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
  default_lease_seconds: 30
  max_lease_seconds: 120
"#,
        target.allowed_prefix().display()
    ))
    .expect("config should parse");
    let now = OffsetDateTime::UNIX_EPOCH;
    let mut registry = TargetProcessRegistry::new(config.registration);
    registry
        .register(
            RegistrationRequest::new(
                "payments-worker-a",
                "payments worker a",
                target.path(),
                30,
                vec![SupportedCommand::new("restart_child", false, 30)],
            ),
            "uid:501",
            now,
        )
        .expect("registration should pass");
    let identity = RemoteIdentity::from_verified_mtls_subject(
        "CN=operator@example.test",
        "CN=operators-ca",
        "01",
        now,
        now + time::Duration::hours(1),
        now,
    )
    .expect("identity should validate");
    let session = DashboardSession::establish(identity, &registry, TransportSecurity::Wss, now)
        .expect("session should establish");
    (session, registry, UnixNdjsonIpcClient, target)
}

#[test]
fn registration_without_session_binding_does_not_push_streams() {
    let (mut session, _registry, _ipc, _target) = session_with_registry();

    let messages = RelayHub::fan_out_event(
        &mut session,
        "payments-worker-a",
        1,
        "child_started",
        "info",
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("fan out should not fail");

    assert!(messages.is_empty());
}

#[test]
fn bound_session_receives_event_log_state_delta_and_dropped_count_in_order() {
    let (mut session, mut registry, ipc, _target) = session_with_registry();
    session
        .bind_target(
            "payments-worker-a",
            &mut registry,
            &ipc,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("target should bind");

    let event_messages = RelayHub::fan_out_event(
        &mut session,
        "payments-worker-a",
        1,
        "child_started",
        "info",
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("event should forward");
    let log_messages = RelayHub::fan_out_log(
        &mut session,
        "payments-worker-a",
        Some(1),
        "info",
        "child started",
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("log should forward");
    let delta_messages = RelayHub::fan_out_state_delta(
        &mut session,
        "payments-worker-a",
        serde_json::json!({"state":"running"}),
    )
    .expect("delta should forward");
    let dropped_messages = RelayHub::fan_out_dropped_count(&mut session, "payments-worker-a", 3)
        .expect("dropped count should forward");

    assert!(matches!(event_messages[0], ServerMessage::Event { .. }));
    assert!(matches!(log_messages[0], ServerMessage::Log { .. }));
    assert!(matches!(
        delta_messages[0],
        ServerMessage::StateDelta { .. }
    ));
    assert!(matches!(
        dropped_messages[0],
        ServerMessage::DroppedCount {
            dropped_event_count: 3,
            ..
        }
    ));
}

#[test]
fn sequence_gap_is_reported_and_reconnect_timeout_marks_target_unavailable() {
    let (mut session, mut registry, ipc, _target) = session_with_registry();
    session
        .bind_target(
            "payments-worker-a",
            &mut registry,
            &ipc,
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("target should bind");

    RelayHub::fan_out_event(
        &mut session,
        "payments-worker-a",
        1,
        "child_started",
        "info",
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("first event should forward");
    let gap_messages = RelayHub::fan_out_event(
        &mut session,
        "payments-worker-a",
        4,
        "child_restarted",
        "warning",
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("gap should produce diagnostic and event");

    assert!(matches!(
        gap_messages[0],
        ServerMessage::DroppedCount {
            dropped_event_count: 2,
            ..
        }
    ));

    let reconnect_messages = RelayHub::reconnect_timeout(
        &mut session,
        &mut registry,
        "payments-worker-a",
        OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(10),
    )
    .expect("timeout should produce diagnostic");

    assert!(matches!(
        reconnect_messages[0],
        ServerMessage::ConnectionState { .. }
    ));
}
