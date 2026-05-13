use rust_supervisor_relay::config::DashboardRelayConfig;
use rust_supervisor_relay::registration::{RegistrationRequest, SupportedCommand};
use rust_supervisor_relay::registry::{ConnectionState, TargetProcessRegistry};
use time::OffsetDateTime;

fn registry_for(prefix: &std::path::Path) -> TargetProcessRegistry {
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
        prefix.display()
    ))
    .expect("config should parse");
    TargetProcessRegistry::new(config.registration)
}

fn request(path: &std::path::Path) -> RegistrationRequest {
    RegistrationRequest::new(
        "payments-worker-a",
        "payments worker a",
        path,
        30,
        vec![SupportedCommand::new("restart_child", false, 30)],
    )
}

#[test]
fn same_owner_can_upsert_existing_target_and_extend_lease() {
    let dir = tempfile::tempdir().expect("temporary directory should exist");
    let socket = dir.path().join("target.sock");
    let mut registry = registry_for(dir.path());

    let first = registry
        .register(request(&socket), "uid:501", OffsetDateTime::UNIX_EPOCH)
        .expect("first registration should succeed");
    let second = registry
        .register(
            RegistrationRequest::new(
                "payments-worker-a",
                "payments worker updated",
                &socket,
                60,
                vec![SupportedCommand::new("restart_child", false, 45)],
            ),
            "uid:501",
            OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(10),
        )
        .expect("same owner upsert should succeed");

    assert_eq!(first.target_id, second.target_id);
    assert_eq!(second.display_name, "payments worker updated");
    assert_eq!(second.lease_seconds, 60);
    assert_eq!(
        second.expires_at,
        OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(70)
    );
}

#[test]
fn different_owner_cannot_replace_existing_target_id() {
    let dir = tempfile::tempdir().expect("temporary directory should exist");
    let socket = dir.path().join("target.sock");
    let mut registry = registry_for(dir.path());

    registry
        .register(request(&socket), "uid:501", OffsetDateTime::UNIX_EPOCH)
        .expect("first registration should succeed");
    let error = registry
        .register(
            RegistrationRequest::new(
                "payments-worker-a",
                "rogue worker",
                &socket,
                30,
                vec![SupportedCommand::new("restart_child", false, 30)],
            ),
            "uid:502",
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect_err("different owner must be rejected");

    assert_eq!(error.code, "target_id_owner_mismatch");
    assert!(!error.retryable);
}

#[test]
fn different_target_id_cannot_reuse_same_ipc_path() {
    let dir = tempfile::tempdir().expect("temporary directory should exist");
    let socket = dir.path().join("target.sock");
    let mut registry = registry_for(dir.path());

    registry
        .register(request(&socket), "uid:501", OffsetDateTime::UNIX_EPOCH)
        .expect("first registration should succeed");
    let error = registry
        .register(
            RegistrationRequest::new(
                "orders-worker-a",
                "orders worker a",
                &socket,
                30,
                vec![SupportedCommand::new("restart_child", false, 30)],
            ),
            "uid:501",
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect_err("same ipc path must be rejected for different target");

    assert_eq!(error.code, "ipc_path_conflict");
    assert!(!error.retryable);
}

#[test]
fn same_owner_ipc_path_change_marks_target_reconnecting() {
    let dir = tempfile::tempdir().expect("temporary directory should exist");
    let first_socket = dir.path().join("target-a.sock");
    let second_socket = dir.path().join("target-b.sock");
    let mut registry = registry_for(dir.path());

    registry
        .register(
            request(&first_socket),
            "uid:501",
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("first registration should succeed");
    registry
        .register(
            RegistrationRequest::new(
                "payments-worker-a",
                "payments worker a",
                &second_socket,
                30,
                vec![SupportedCommand::new("restart_child", false, 30)],
            ),
            "uid:501",
            OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
        )
        .expect("same owner path update should succeed");

    assert_eq!(
        registry.connection_state("payments-worker-a"),
        Some(ConnectionState::Reconnecting)
    );
}
