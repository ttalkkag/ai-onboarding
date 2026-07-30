#![cfg(feature = "m0-test-profile")]

use secure_onboard::m0::{
    Client, EvaluationMetadata, GateDecision, Invocation, M0ActionRequest, M0EventType, Sentinel,
    Severity, evaluate,
};

fn request(sentinel: Sentinel) -> M0ActionRequest {
    M0ActionRequest {
        schema_version: "m0-action-request/v1".into(),
        phase: "m0".into(),
        test_case_id: "T02".into(),
        test_run_id: "m0-run-t02-01".into(),
        test_profile_digest: "sha256:profile".into(),
        action_id: "m0-action-01".into(),
        envelope_id: "envelope-01".into(),
        client: Client::Codex,
        session_fixture_id: "m0-session-01".into(),
        native_tool_call_id: "tool-call-01".into(),
        sentinel,
        invocation: Invocation::ShellText {
            shell_executable: "/bin/zsh".into(),
            shell_flags: vec!["-lc".into()],
            dialect: "posix_sh".into(),
            command_text: "/opt/homebrew/bin/node /tmp/m0-target.mjs high /tmp/marker".into(),
            shell_resolution_source: "m0_runtime_probe".into(),
            shell_resolution_fingerprint: "sha256:effective-shell".into(),
        },
        physical_cwd_fixture: "/tmp/m0-project".into(),
        cwd_resolution_source: "m0_effective_cwd_binding".into(),
    }
}

fn metadata() -> EvaluationMetadata {
    EvaluationMetadata {
        decision_id: "m0-decision-01".into(),
        event_ids: ["m0-event-01".into(), "m0-event-02".into()],
        observed_at: "2026-07-22T00:00:00Z".into(),
    }
}

#[test]
fn high_sentinel_denies_and_emits_the_only_valid_event_sequence() {
    let output = evaluate(request(Sentinel::High), metadata()).expect("valid M0 request");

    assert_eq!(output.decision.severity, Severity::High);
    assert_eq!(output.decision.gate_decision, GateDecision::Deny);
    assert_eq!(output.decision.rule_id, "m0.sentinel.high");
    assert_eq!(output.decision.failure_code, None);
    assert_eq!(output.decision.pending_action_ref, None);
    assert_eq!(
        output
            .events
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        [M0EventType::HighDetected, M0EventType::HighBlocked]
    );
    assert!(output.events.iter().all(|event| {
        event.severity == Severity::High
            && event.rule_id == "m0.sentinel.high"
            && event.outcome.is_none()
    }));
}

#[test]
fn low_and_info_continue_without_inventing_a_result_event() {
    for (sentinel, severity, rule_id, event_type) in [
        (
            Sentinel::Low,
            Severity::Low,
            "m0.sentinel.low",
            M0EventType::WarnedLow,
        ),
        (
            Sentinel::Info,
            Severity::Info,
            "m0.sentinel.info",
            M0EventType::AllowedInfo,
        ),
    ] {
        let output = evaluate(request(sentinel), metadata()).expect("valid M0 request");

        assert_eq!(output.decision.severity, severity);
        assert_eq!(output.decision.gate_decision, GateDecision::Continue);
        assert_eq!(output.decision.rule_id, rule_id);
        assert_eq!(output.events.len(), 1);
        assert_eq!(output.events[0].event_type, event_type);
        assert_eq!(output.events[0].outcome, None);
    }
}
