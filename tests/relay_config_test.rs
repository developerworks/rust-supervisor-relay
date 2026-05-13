use std::path::Path;

use rust_supervisor_relay::config::DashboardRelayConfig;
use rust_supervisor_relay::registration::{RegistrationRequest, SupportedCommand};
use rust_supervisor_relay::registry::TargetProcessRegistry;
use time::OffsetDateTime;

fn relay_yaml(public_url: &str) -> String {
    format!(
        r#"
listen:
  bind: "127.0.0.1:9443"
  public_url: "{public_url}"
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
"#
    )
}

fn registration(
    target_id: &str,
    ipc_path: impl Into<std::path::PathBuf>,
    lease_seconds: u64,
) -> RegistrationRequest {
    RegistrationRequest {
        target_id: target_id.to_owned(),
        display_name: format!("{target_id} display"),
        ipc_path: ipc_path.into(),
        lease_seconds,
        supported_commands: vec![SupportedCommand::new("restart_child", false, 30)],
    }
}

#[test]
fn config_accepts_wss_registration_policy_and_relay_directory_boundary() {
    let config =
        DashboardRelayConfig::from_yaml_str(&relay_yaml("wss://localhost:9443/supervisor"))
            .expect("config should parse");

    config.validate().expect("wss relay config should validate");

    assert!(Path::new(env!("CARGO_MANIFEST_DIR")).ends_with("rust-supervisor-relay"));
    assert!(
        !Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("targets.yaml")
            .exists()
    );
    assert!(
        config
            .registration
            .ipc_path_is_allowed(Path::new("/run/rust-supervisor/a.sock"))
    );
}

#[test]
fn config_rejects_ws_public_url_and_empty_ipc_prefixes() {
    let ws_config =
        DashboardRelayConfig::from_yaml_str(&relay_yaml("ws://localhost:9443/supervisor"))
            .expect("config should parse before validation");

    let ws_error = ws_config.validate().expect_err("ws:// must not validate");
    assert_eq!(ws_error.code, "invalid_public_url");

    let empty_prefix_yaml =
        relay_yaml("wss://localhost:9443/supervisor").replace("    - /run/rust-supervisor/\n", "");
    let empty_prefix_config =
        DashboardRelayConfig::from_yaml_str(&empty_prefix_yaml).expect("config should parse");

    let prefix_error = empty_prefix_config
        .validate()
        .expect_err("empty IPC path prefixes must not validate");
    assert_eq!(prefix_error.code, "empty_allowed_ipc_path_prefixes");
}

#[test]
fn registry_allows_owner_upsert_and_rejects_ipc_conflict_and_invalid_lease() {
    let dir = tempfile::tempdir().expect("temporary directory should exist");
    let config = DashboardRelayConfig::from_yaml_str(
        &relay_yaml("wss://localhost:9443/supervisor").replace(
            "    - /run/rust-supervisor/\n",
            &format!("    - {}\n", dir.path().display()),
        ),
    )
    .expect("config should parse");
    config.validate().expect("config should validate");

    let mut registry = TargetProcessRegistry::new(config.registration.clone());
    let now = OffsetDateTime::UNIX_EPOCH;

    registry
        .register(
            registration(
                "payments-worker-a",
                dir.path().join("payments-worker-a.sock"),
                30,
            ),
            "uid:501",
            now,
        )
        .expect("first registration should pass");

    let updated_target = registry
        .register(
            registration(
                "payments-worker-a",
                dir.path().join("payments-worker-b.sock"),
                60,
            ),
            "uid:501",
            now,
        )
        .expect("same owner target id should upsert");
    assert_eq!(updated_target.lease_seconds, 60);

    let conflicting_path = registry
        .register(
            registration(
                "payments-worker-b",
                dir.path().join("payments-worker-b.sock"),
                30,
            ),
            "uid:501",
            now,
        )
        .expect_err("same IPC path should be rejected for another target");
    assert_eq!(conflicting_path.code, "ipc_path_conflict");

    let invalid_lease = registry
        .register(
            registration(
                "payments-worker-d",
                dir.path().join("payments-worker-d.sock"),
                0,
            ),
            "uid:501",
            now,
        )
        .expect_err("invalid lease should be rejected");
    assert_eq!(invalid_lease.code, "invalid_lease_seconds");
}
