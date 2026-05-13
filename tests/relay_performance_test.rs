use rust_supervisor_relay::auth::RemoteIdentity;
use rust_supervisor_relay::config::DashboardRelayConfig;
use rust_supervisor_relay::registration::{RegistrationRequest, SupportedCommand};
use rust_supervisor_relay::registry::{ConnectionState, TargetProcessRegistry};
use rust_supervisor_relay::session::{DashboardSession, TransportSecurity};
use time::OffsetDateTime;

#[test]
fn registry_tracks_five_active_registrations_and_session_gating_keeps_ipc_idle_before_bind() {
    let dir = tempfile::tempdir().expect("temporary directory should exist");
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
        dir.path().display()
    ))
    .expect("config should parse");
    let mut registry = TargetProcessRegistry::new(config.registration);
    let now = OffsetDateTime::UNIX_EPOCH;

    for index in 0..5 {
        registry
            .register(
                RegistrationRequest::new(
                    format!("worker-{index}"),
                    format!("worker {index}"),
                    dir.path().join(format!("worker-{index}.sock")),
                    30,
                    vec![SupportedCommand::new("restart_child", false, 30)],
                ),
                "uid:501",
                now,
            )
            .expect("registration should pass");
    }

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

    assert_eq!(registry.active_registration_count(now), 5);
    assert_eq!(session.visible_target_count(), 5);

    registry.mark_unavailable(
        "worker-3",
        "test disconnect",
        now + time::Duration::seconds(10),
    );
    assert_eq!(
        registry.connection_state("worker-3"),
        Some(ConnectionState::Unavailable)
    );
}
