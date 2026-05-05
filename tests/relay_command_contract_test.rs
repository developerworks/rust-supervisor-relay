use rust_supervisor_relay::audit::{AuditRecorder, AuditResult};
use rust_supervisor_relay::auth::RemoteIdentity;
use rust_supervisor_relay::command::{
    ClientCommand, CommandTarget, ControlCommandName, prepare_client_command,
};
use time::OffsetDateTime;

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

fn command(command: ControlCommandName, confirmed: bool, reason: &str) -> ClientCommand {
    ClientCommand {
        command_id: format!("{command:?}-cmd"),
        target_id: "payments-worker-a".to_owned(),
        command,
        target: CommandTarget {
            child_path: Some("/root/payment_loop".to_owned()),
        },
        reason: reason.to_owned(),
        confirmed,
        requested_by: None,
    }
}

#[test]
fn all_declared_control_commands_prepare_with_derived_requested_by() {
    let all_commands = [
        ControlCommandName::RestartChild,
        ControlCommandName::PauseChild,
        ControlCommandName::ResumeChild,
        ControlCommandName::QuarantineChild,
        ControlCommandName::RemoveChild,
        ControlCommandName::AddChild,
        ControlCommandName::ShutdownTree,
    ];

    for command_name in all_commands {
        let prepared = prepare_client_command(
            command(
                command_name,
                command_name.requires_confirmation(),
                "operator supplied reason",
            ),
            &identity(),
            OffsetDateTime::UNIX_EPOCH,
        )
        .expect("declared command should prepare");

        assert_eq!(prepared.requested_by, "CN=operator@example.test");
    }
}

#[test]
fn historical_command_aliases_are_rejected_without_mapping() {
    for alias in ["restart", "pause", "resume", "remove", "shutdown"] {
        let error = ControlCommandName::from_wire(alias).expect_err("alias should be rejected");
        assert_eq!(error.code, "unsupported_method");
    }
}

#[test]
fn dangerous_commands_require_confirmation_and_every_command_requires_reason() {
    let unconfirmed_remove = prepare_client_command(
        command(
            ControlCommandName::RemoveChild,
            false,
            "remove duplicate worker",
        ),
        &identity(),
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect_err("remove_child should require confirmation");
    assert_eq!(unconfirmed_remove.code, "confirmation_required");

    let empty_reason = prepare_client_command(
        command(ControlCommandName::PauseChild, false, " "),
        &identity(),
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect_err("reason should be required");
    assert_eq!(empty_reason.code, "empty_reason");
}

#[test]
fn audit_recorder_writes_accepted_rejected_and_completed_events() {
    let identity = identity();
    let command = prepare_client_command(
        command(
            ControlCommandName::RestartChild,
            false,
            "operator supplied reason",
        ),
        &identity,
        OffsetDateTime::UNIX_EPOCH,
    )
    .expect("command should prepare");
    let mut recorder = AuditRecorder::default();

    recorder.record_accepted(&identity, &command, OffsetDateTime::UNIX_EPOCH);
    recorder.record_rejected(
        &identity,
        &command,
        "target unavailable",
        OffsetDateTime::UNIX_EPOCH,
    );
    recorder.record_completed(&identity, &command, "completed", OffsetDateTime::UNIX_EPOCH);

    let results: Vec<_> = recorder
        .events()
        .iter()
        .map(|event| event.result.clone())
        .collect();
    assert_eq!(
        results,
        vec![
            AuditResult::Accepted,
            AuditResult::Rejected,
            AuditResult::Completed
        ]
    );
}
