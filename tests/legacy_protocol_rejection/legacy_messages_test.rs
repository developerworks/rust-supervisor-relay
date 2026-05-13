use rust_supervisor_relay::session::decode_client_message;

#[test]
fn old_filter_update_message_type_is_rejected() {
    let error = decode_client_message(r#"{"type":"filter_update"}"#)
        .expect_err("old filter message type should be rejected");

    assert_eq!(error.code, "unsupported_message_type");
}

#[test]
fn old_sequence_checkpoint_message_type_is_rejected() {
    let error = decode_client_message(r#"{"type":"sequence_checkpoint"}"#)
        .expect_err("old checkpoint message type should be rejected");

    assert_eq!(error.code, "unsupported_message_type");
}

#[test]
fn old_sequence_from_field_is_rejected() {
    let error = decode_client_message(
        r#"{"type":"client_hello","client_store_id":"store-a","sequence_from":{"events":{}}}"#,
    )
    .expect_err("old resume field should be rejected");

    assert_eq!(error.code, "unsupported_field");
}
