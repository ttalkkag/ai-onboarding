#![cfg(feature = "m0-test-profile")]

use secure_onboard::contracts::{
    CwdAssurance, CwdResolutionSource, HookEnvelope, HookEnvelopeError, HookEvent,
};
use secure_onboard::m0::{
    Client, DecisionSource, EvaluationMetadata, FallbackFailure, GateDecision, M0ActionDecision,
    M0ActionRequest, M0Event, M0EventType, Outcome, ResultMetadata, Sentinel, Severity, evaluate,
    fallback, record_result, validate_decision, validate_event,
};
use secure_onboard::strict_json::{canonical_sha256, from_slice};
use serde_json::json;

fn request(sentinel: Sentinel) -> M0ActionRequest {
    serde_json::from_value(json!({
        "schema_version": "m0-action-request/v1",
        "phase": "m0",
        "test_case_id": "T02",
        "test_run_id": "m0-run-t02-01",
        "test_profile_digest": "sha256:profile",
        "action_id": "m0-action-01",
        "envelope_id": "envelope-01",
        "client": "codex",
        "session_fixture_id": "m0-session-01",
        "native_tool_call_id": "tool-call-01",
        "sentinel": match sentinel {
            Sentinel::High => "high",
            Sentinel::Low => "low",
            Sentinel::Info => "info",
        },
        "invocation": {
            "kind": "shell_text",
            "shell_executable": "/bin/zsh",
            "shell_flags": ["-lc"],
            "dialect": "posix_sh",
            "command_text": "/opt/homebrew/bin/node /tmp/m0-target.mjs high /tmp/marker",
            "shell_resolution_source": "m0_runtime_probe",
            "shell_resolution_fingerprint": "sha256:effective-shell"
        },
        "physical_cwd_fixture": "/tmp/m0-project",
        "cwd_resolution_source": "m0_effective_cwd_binding"
    }))
    .expect("request fixture")
}

fn metadata() -> EvaluationMetadata {
    EvaluationMetadata {
        decision_id: "m0-decision-01".into(),
        event_ids: ["m0-event-01".into(), "m0-event-02".into()],
        observed_at: "2026-07-22T00:00:00Z".into(),
    }
}

#[test]
fn strict_json_rejects_duplicate_and_unknown_fields() {
    let duplicate =
        br#"{"schema_version":"m0-action-request/v1","schema_version":"m0-action-request/v1"}"#;
    assert!(from_slice::<M0ActionRequest>(duplicate).is_err());

    let mut value = serde_json::to_value(request(Sentinel::High)).expect("serialize");
    value
        .as_object_mut()
        .expect("object")
        .insert("unexpected".into(), json!(true));
    assert!(from_slice::<M0ActionRequest>(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn decision_and_event_combinations_are_total_and_strict() {
    let output = evaluate(request(Sentinel::High), metadata()).expect("evaluate");
    validate_decision(&output.decision).expect("valid decision");
    for event in &output.events {
        validate_event(event, &output.decision).expect("valid event");
    }

    let mut invalid_decision = output.decision.clone();
    invalid_decision.gate_decision = GateDecision::Continue;
    assert!(validate_decision(&invalid_decision).is_err());

    let mut invalid_event = output.events[0].clone();
    invalid_event.outcome = Some(Outcome::Success);
    assert!(validate_event(&invalid_event, &output.decision).is_err());
}

#[test]
fn result_event_requires_same_correlation_and_only_low_or_info() {
    let output = evaluate(request(Sentinel::Low), metadata()).expect("evaluate");
    let event = record_result(
        &output.decision,
        ResultMetadata {
            event_id: "m0-event-result".into(),
            observed_at: "2026-07-22T00:00:01Z".into(),
            client: Client::Codex,
            session_fixture_id: "m0-session-01".into(),
            native_tool_call_id: "tool-call-01".into(),
            outcome: Outcome::Failure,
        },
    )
    .expect("matching result");
    assert_eq!(event.event_type, M0EventType::ToolFailed);
    assert_eq!(event.severity, Severity::Low);
    assert_eq!(event.rule_id, "m0.sentinel.low");

    let high = evaluate(request(Sentinel::High), metadata()).expect("evaluate");
    assert!(
        record_result(
            &high.decision,
            ResultMetadata {
                event_id: "m0-event-result".into(),
                observed_at: "2026-07-22T00:00:01Z".into(),
                client: Client::Codex,
                session_fixture_id: "m0-session-01".into(),
                native_tool_call_id: "tool-call-01".into(),
                outcome: Outcome::Success,
            },
        )
        .is_err()
    );
}

#[test]
fn core_failures_are_the_only_adapter_fallback_decisions() {
    for failure in [
        FallbackFailure::CoreTimeout,
        FallbackFailure::CoreNonzero,
        FallbackFailure::CoreSchemaInvalid,
    ] {
        let output = fallback(&request(Sentinel::Info), metadata(), failure);
        assert_eq!(output.decision.severity, Severity::High);
        assert_eq!(output.decision.gate_decision, GateDecision::Deny);
        assert_eq!(
            output.decision.decision_source,
            DecisionSource::AdapterFallback
        );
        assert_eq!(output.decision.rule_id, "guardrail.scan_failure");
        validate_decision(&output.decision).expect("valid fallback");
    }
}

#[test]
fn hook_envelope_is_event_tagged_and_requires_nullable_fields_to_be_present() {
    let pre: HookEnvelope = from_slice(
        br#"{"schema_version":"hook-envelope/v1","envelope_id":"e1","hook_event":"pre_tool_use","occurred_at":"2026-07-22T00:00:00Z","client":"claude","session_id":"s1","adapter_turn_id":null,"native_tool_call_id":"t1","prompt_context_id":null,"native_tool_name":"Bash","native_tool_input":{"command":"printf ok"},"tool_name":"shell_exec","tool_input":{"command_text":"printf ok"},"native_session_cwd":"/tmp/project","physical_cwd":"/tmp/project","cwd_assurance":"verified","cwd_resolution_source":"m0_effective_cwd_binding"}"#,
    )
    .expect("strict pre envelope");
    assert_eq!(pre.hook_event(), HookEvent::PreToolUse);
    pre.validate().expect("valid envelope");

    let missing_nullable = br#"{"schema_version":"hook-envelope/v1","envelope_id":"e2","hook_event":"tool_result","occurred_at":"2026-07-22T00:00:01Z","client":"claude","session_id":"s1","adapter_turn_id":null,"native_tool_call_id":"t1","prompt_context_id":null,"native_tool_response":{},"outcome":"success"}"#;
    assert!(from_slice::<HookEnvelope>(missing_nullable).is_err());

    let unverified_with_path = HookEnvelope::PreToolUse {
        schema_version: "hook-envelope/v1".into(),
        envelope_id: "e3".into(),
        occurred_at: "2026-07-22T00:00:00Z".into(),
        client: Client::Codex,
        session_id: "s1".into(),
        adapter_turn_id: Some("turn-1".into()),
        native_tool_call_id: "t1".into(),
        prompt_context_id: None,
        native_tool_name: "Bash".into(),
        native_tool_input: json!({"command":"printf ok"}),
        tool_name: "shell_exec".into(),
        tool_input: json!({"command_text":"printf ok"}),
        native_session_cwd: "/tmp/project".into(),
        physical_cwd: Some("/tmp/project".into()),
        cwd_assurance: CwdAssurance::Unverified,
        cwd_resolution_source: CwdResolutionSource::Unavailable,
    };
    assert_eq!(
        unverified_with_path.validate(),
        Err(HookEnvelopeError::CwdBinding)
    );
}

#[test]
fn canonical_digest_is_stable_across_object_key_order() {
    let a = json!({"z": 1, "a": {"y": true, "b": null}});
    let b = json!({"a": {"b": null, "y": true}, "z": 1});
    assert_eq!(canonical_sha256(&a).unwrap(), canonical_sha256(&b).unwrap());
}

#[test]
fn invalid_decision_cannot_be_deserialized_as_valid_by_using_nulls() {
    let value = json!({
        "schema_version": "m0-action-decision/v1",
        "phase": "m0",
        "test_case_id": "T02",
        "test_run_id": "r1",
        "decision_id": "d1",
        "action_id": "a1",
        "client": "codex",
        "session_fixture_id": "s1",
        "native_tool_call_id": "t1",
        "severity": "HIGH",
        "gate_decision": "deny",
        "rule_id": "guardrail.scan_failure",
        "decision_source": "core",
        "failure_code": null,
        "cache_status": "bypass",
        "pending_action_ref": null
    });
    let decision: M0ActionDecision = serde_json::from_value(value).expect("shape");
    assert!(validate_decision(&decision).is_err());
}

#[test]
fn documented_nullable_m0_fields_must_still_be_present() {
    let decision = serde_json::to_value(
        evaluate(request(Sentinel::High), metadata())
            .unwrap()
            .decision,
    )
    .expect("decision JSON");
    for field in ["failure_code", "pending_action_ref"] {
        let mut missing = decision.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            from_slice::<M0ActionDecision>(&serde_json::to_vec(&missing).unwrap()).is_err(),
            "missing {field} was accepted"
        );
    }

    let event = serde_json::to_value(
        evaluate(request(Sentinel::High), metadata())
            .unwrap()
            .events[0]
            .clone(),
    )
    .expect("event JSON");
    let mut missing = event;
    missing.as_object_mut().unwrap().remove("outcome");
    assert!(from_slice::<M0Event>(&serde_json::to_vec(&missing).unwrap()).is_err());
}

#[test]
fn standalone_event_shape_still_requires_decision_correlation() {
    let event: M0Event = serde_json::from_value(json!({
        "schema_version": "m0-event/v1",
        "phase": "m0",
        "test_case_id": "T02",
        "test_run_id": "r1",
        "event_id": "e1",
        "observed_at": "2026-07-22T00:00:00Z",
        "event_type": "tool_completed",
        "client": "codex",
        "session_fixture_id": "s1",
        "action_id": "a1",
        "native_tool_call_id": "t1",
        "severity": "LOW",
        "rule_id": "m0.sentinel.low",
        "outcome": "success"
    }))
    .expect("shape");
    let decision = M0ActionDecision {
        schema_version: "m0-action-decision/v1".into(),
        phase: "m0".into(),
        test_case_id: "T02".into(),
        test_run_id: "r1".into(),
        decision_id: "d1".into(),
        action_id: "different".into(),
        client: Client::Codex,
        session_fixture_id: "s1".into(),
        native_tool_call_id: "t1".into(),
        severity: Severity::Low,
        gate_decision: GateDecision::Continue,
        rule_id: "m0.sentinel.low".into(),
        decision_source: DecisionSource::Core,
        failure_code: None,
        cache_status: "bypass".into(),
        pending_action_ref: None,
    };
    assert!(validate_event(&event, &decision).is_err());
}
