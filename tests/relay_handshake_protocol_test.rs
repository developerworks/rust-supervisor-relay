use rust_supervisor_relay::auth::RemoteIdentity;
use rust_supervisor_relay::session::{ClientHello, DashboardSession, ServerMessage};
use time::OffsetDateTime;

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
fn server_hello_is_sent_before_client_hello_and_no_business_data_is_sent() {
    let session = DashboardSession::server_hello(identity(), OffsetDateTime::UNIX_EPOCH);

    assert!(matches!(
        session.outbox().first(),
        Some(ServerMessage::ServerHello { client_identity, .. })
            if client_identity.starts_with("mtls_cert_fingerprint:")
    ));
    assert_eq!(session.outbox().len(), 1);
}

#[test]
fn client_hello_requires_client_store_id() {
    let mut session = DashboardSession::server_hello(identity(), OffsetDateTime::UNIX_EPOCH);
    let error = session
        .accept_client_hello(
            ClientHello {
                client_store_id: String::new(),
                resume_cursor: Default::default(),
            },
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect_err("missing client store id should be rejected");

    assert_eq!(error.code, "invalid_message_schema");
}
