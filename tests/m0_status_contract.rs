#![cfg(feature = "m0-test-profile")]

use secure_onboard::m0_status::{
    ClientModeEvidenceInput, M0StatusReport, StatusError, client_mode_evidence_digest,
    validate_status,
};
use secure_onboard::strict_json::from_slice;
use serde_json::{Value, json};

fn mode_input() -> ClientModeEvidenceInput {
    serde_json::from_value(json!({
        "os_string_encoding": "unix_bytes",
        "launch_argv_base64url": ["Y29kZXg="],
        "relevant_environment": [],
        "plugin_list_output_base64url": null,
        "ordered_setting_sources": [{
            "source": "codex_user_config",
            "source_bytes_base64url": "W2ZlYXR1cmVzXQpob29rcyA9IHRydWUK",
            "claim": "codex_hooks_feature_enabled"
        }]
    }))
    .expect("mode input")
}

fn claude_mode_input(
    launch_argv_base64url: Vec<&str>,
    simple_value_base64url: Option<&str>,
    claim: &str,
) -> ClientModeEvidenceInput {
    let source_bytes_base64url = match claim {
        "claude_disable_all_hooks_true" => "eyJkaXNhYmxlQWxsSG9va3MiOnRydWV9",
        "claude_disable_all_hooks_false" => "eyJkaXNhYmxlQWxsSG9va3MiOmZhbHNlfQ==",
        _ => panic!("unsupported test setting claim"),
    };
    serde_json::from_value(json!({
        "os_string_encoding": "unix_bytes",
        "launch_argv_base64url": launch_argv_base64url,
        "relevant_environment": [{
            "name_base64url": "Q0xBVURFX0NPREVfU0lNUExF",
            "value_base64url": simple_value_base64url
        }],
        "plugin_list_output_base64url": null,
        "ordered_setting_sources": [{
            "source": "claude_user_settings",
            "source_bytes_base64url": source_bytes_base64url,
            "claim": claim
        }]
    }))
    .expect("Claude mode input")
}

fn t15_value() -> Value {
    let digest = client_mode_evidence_digest(&mode_input()).expect("digest");
    json!({
        "schema_version": "m0-status-report/v1",
        "phase": "m0",
        "report_source": "test_harness",
        "test_case_id": "T15",
        "test_run_id": "m0-run-t15-01",
        "client": "codex",
        "client_version": "0.146.0",
        "plugin_version": "0.1.0",
        "os": "macos",
        "architecture": "arm64",
        "client_executable": {
            "invoked_path": "/opt/homebrew/bin/codex",
            "resolved_path": "/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js",
            "sha256": "sha256:134063e133f0b4244fa3b251acf973d4fe4b4aeeacbdc135211bf480f59f1477",
            "version_output": "codex-cli 0.146.0"
        },
        "client_runtime_artifact": {
            "role": "native_backend",
            "absolute_path": "/opt/homebrew/lib/node_modules/@openai/codex/native/codex",
            "sha256": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        },
        "artifact_kind": "test",
        "artifact_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "configured_scope_fixture": "ON",
        "plugin_installed": true,
        "hooks_enabled": true,
        "client_mode_evidence": {
            "plugin_state": "installed_enabled",
            "launch_mode": "normal",
            "explicit_plugin_supplied": null,
            "disable_all_hooks": null,
            "codex_hooks_feature": "enabled",
            "setting_evidence": [{
                "source": "codex_user_config",
                "source_digest": "sha256:d37497c3278121598a663564ab38b53f658969717f78decb661ddd11c66551ea",
                "claim": "codex_hooks_feature_enabled"
            }],
            "evidence_digest": digest
        },
        "session_fixture_id": "m0-session-new-01",
        "session_state": "new_after_review",
        "hook_evidence": [{
            "source": "codex_user_plugin",
            "definition_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "disposition": "loaded_active",
            "reason": "selected_reviewed_definition"
        }],
        "bundled_hook_definition_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "reviewed_hook_definition_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "product_hook_review": "verified",
        "heartbeat": {
            "status": "passed",
            "evidence_scope": "current",
            "session_fixture_id": "m0-session-new-01",
            "hook_source": "codex_user_plugin",
            "hook_definition_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "self_test": {
            "status": "passed",
            "evidence_scope": "current",
            "session_fixture_id": "m0-session-new-01",
            "hook_source": "codex_user_plugin",
            "hook_definition_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        },
        "client_trust": "unknown",
        "effective_protection": "VERIFIED_ACTIVE",
        "test_profile": "loaded",
        "test_profile_expected_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "test_profile_supplied_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "test_profile_rejection_reason": null,
        "sentinel_binding_result": "matched",
        "next_checks": [],
        "run_evidence": null,
        "artifact_inspection": null,
        "reasons": [],
        "limitations": ["Codex trust hash is not machine-readable"]
    })
}

fn t15_report() -> M0StatusReport {
    serde_json::from_value(t15_value()).expect("T15 shape")
}

fn not_run_check() -> Value {
    json!({
        "status": "not_run",
        "evidence_scope": "none",
        "session_fixture_id": null,
        "hook_source": null,
        "hook_definition_digest": null
    })
}

fn t13_value() -> Value {
    let mut value = t15_value();
    value["test_case_id"] = json!("T13");
    value["test_run_id"] = json!("m0-run-t13-01");
    value["session_fixture_id"] = Value::Null;
    value["session_state"] = json!("unknown");
    value["hook_evidence"][0]["disposition"] = json!("skipped");
    value["hook_evidence"][0]["reason"] = json!("unreviewed_definition");
    value["reviewed_hook_definition_digest"] = Value::Null;
    value["product_hook_review"] = json!("unverified");
    value["heartbeat"] = not_run_check();
    value["self_test"] = not_run_check();
    value["effective_protection"] = json!("UNKNOWN");
    value["sentinel_binding_result"] = json!("not_evaluated");
    value["next_checks"] = json!(["review_current_hook_definition"]);
    value
}

fn t14_value() -> Value {
    let mut value = t15_value();
    value["test_case_id"] = json!("T14");
    value["test_run_id"] = json!("m0-run-t14-01");
    value["session_fixture_id"] = json!("m0-session-existing-01");
    value["session_state"] = json!("existing_before_review");
    value["hook_evidence"][0]["disposition"] = json!("skipped");
    value["hook_evidence"][0]["reason"] = json!("session_predates_review");
    value["heartbeat"] = not_run_check();
    value["self_test"] = not_run_check();
    value["effective_protection"] = json!("UNKNOWN");
    value["sentinel_binding_result"] = json!("not_evaluated");
    value["next_checks"] = json!(["start_new_client_session"]);
    value
}

fn t16_value() -> Value {
    let mut value = t15_value();
    value["test_case_id"] = json!("T16");
    value["test_run_id"] = json!("m0-run-t16-01");
    value["session_fixture_id"] = Value::Null;
    value["session_state"] = json!("unknown");
    value["hook_evidence"][0]["definition_digest"] =
        json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    value["hook_evidence"][0]["disposition"] = json!("skipped");
    value["hook_evidence"][0]["reason"] = json!("reviewed_digest_stale");
    value["bundled_hook_definition_digest"] =
        json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    value["product_hook_review"] = json!("stale");
    value["heartbeat"] = json!({
        "status": "stale",
        "evidence_scope": "historical",
        "session_fixture_id": "m0-session-before-definition-change",
        "hook_source": "codex_user_plugin",
        "hook_definition_digest":
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    });
    value["self_test"] = value["heartbeat"].clone();
    value["effective_protection"] = json!("UNKNOWN");
    value["sentinel_binding_result"] = json!("not_evaluated");
    value["next_checks"] = json!(["review_current_hook_definition"]);
    value
}

fn claude_off_value(
    test_case_id: &str,
    launch_mode: &str,
    explicit_plugin_supplied: Option<bool>,
    disable_all_hooks: bool,
    claim: &str,
    input: &ClientModeEvidenceInput,
) -> Value {
    let source_digest = match claim {
        "claude_disable_all_hooks_true" => {
            "sha256:8d71786a3a7dec5fcb050c095655e59dd5ddbb229d084c354297686fcb575319"
        }
        "claude_disable_all_hooks_false" => {
            "sha256:b02c742904eeed43594bcc3a3346ba6422728e97f633572b94841e9f1ecd9ae6"
        }
        _ => panic!("unsupported test setting claim"),
    };
    let mut value = t15_value();
    value["test_case_id"] = json!(test_case_id);
    value["test_run_id"] = json!(format!("m0-run-{}-01", test_case_id.to_lowercase()));
    value["client"] = json!("claude");
    value["client_version"] = json!("2.1.220");
    value["client_executable"] = json!({
        "invoked_path": "/opt/homebrew/bin/claude",
        "resolved_path": "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js",
        "sha256": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "version_output": "2.1.220 (Claude Code)"
    });
    value["client_runtime_artifact"] = json!({
        "role": "resolved_executable",
        "absolute_path": "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js",
        "sha256": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    });
    value["hooks_enabled"] = json!(false);
    value["client_mode_evidence"] = json!({
        "plugin_state": "installed_enabled",
        "launch_mode": launch_mode,
        "explicit_plugin_supplied": explicit_plugin_supplied,
        "disable_all_hooks": disable_all_hooks,
        "codex_hooks_feature": "not_applicable",
        "setting_evidence": [{
            "source": "claude_user_settings",
            "source_digest": source_digest,
            "claim": claim
        }],
        "evidence_digest": client_mode_evidence_digest(input).expect("digest")
    });
    value["session_fixture_id"] = Value::Null;
    value["session_state"] = json!("unknown");
    value["hook_evidence"] = json!([{
        "source": "claude_user_plugin",
        "definition_digest":
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "disposition": "skipped",
        "reason": "hooks_disabled"
    }]);
    value["reviewed_hook_definition_digest"] = Value::Null;
    value["product_hook_review"] = json!("not_applicable");
    value["heartbeat"] = not_run_check();
    value["self_test"] = not_run_check();
    value["client_trust"] = json!("not_applicable");
    value["effective_protection"] = json!("OFF");
    value["sentinel_binding_result"] = json!("not_evaluated");
    value["next_checks"] = json!(["enable_hooks"]);
    value
}

fn profile_value(
    test_case_id: &str,
    test_profile: &str,
    supplied_digest: Option<&str>,
    rejection_reason: Option<&str>,
    binding_result: &str,
) -> Value {
    let mut value = t15_value();
    value["test_case_id"] = json!(test_case_id);
    value["test_run_id"] = json!(format!("m0-run-{}-01", test_case_id.to_lowercase()));
    value["test_profile"] = json!(test_profile);
    value["test_profile_supplied_digest"] = json!(supplied_digest);
    value["test_profile_rejection_reason"] = json!(rejection_reason);
    value["sentinel_binding_result"] = json!(binding_result);
    value["run_evidence"] = run_evidence_value(test_case_id);
    value
}

fn run_evidence_value(test_case_id: &str) -> Value {
    let (counts, events, observations) = match test_case_id {
        "T19-A-HIGH" => (
            [1, 1, 1, 2],
            vec!["high_detected", "high_blocked"],
            [0, 0, 0],
        ),
        "T19-A-LOW" => ([1, 1, 1, 1], vec!["warned_low"], [1, 1, 1]),
        "T19-A-INFO" => ([1, 1, 1, 1], vec!["allowed_info"], [1, 1, 1]),
        "T19-B-HELPER" | "T19-B-ARGV" => ([1, 0, 0, 0], vec![], [1, 1, 1]),
        "T19-B-MISSING" | "T19-B-DIGEST" | "T19-B-SOURCE" | "T19-C" => {
            ([0, 0, 0, 0], vec![], [0, 0, 0])
        }
        _ => panic!("unsupported T19 case"),
    };
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    json!({
        "object_counts": {
            "hook_envelope": counts[0],
            "m0_action_request": counts[1],
            "m0_action_decision": counts[2],
            "m0_event": counts[3],
            "m0_status_report": 1
        },
        "canonical_digests": {
            "hook_envelope": vec![digest; counts[0]],
            "m0_action_request": vec![digest; counts[1]],
            "m0_action_decision": vec![digest; counts[2]],
            "m0_event": vec![digest; counts[3]]
        },
        "ordered_events": events,
        "observations": {
            "target_process_start_count": observations[0],
            "target_marker_count": observations[1],
            "operator_approval_count": observations[2],
            "secure_onboard_approval_count": 0,
            "uncorrelated_result_count": 0
        }
    })
}

#[test]
fn t13_unreviewed_definition_is_unknown_until_reviewed() {
    let value = t13_value();
    validate_status(
        &serde_json::from_value(value.clone()).unwrap(),
        Some(&mode_input()),
    )
    .expect("valid T13");

    let mut wrong_skip_reason = value;
    wrong_skip_reason["hook_evidence"][0]["reason"] = json!("session_predates_review");
    assert_eq!(
        validate_status(
            &serde_json::from_value(wrong_skip_reason).unwrap(),
            Some(&mode_input())
        ),
        Err(StatusError::SessionEvidence)
    );
}

#[test]
fn t14_existing_session_is_bound_before_a_new_session_can_be_trusted() {
    let value = t14_value();
    validate_status(
        &serde_json::from_value(value.clone()).unwrap(),
        Some(&mode_input()),
    )
    .expect("valid T14");

    let mut missing_session = value;
    missing_session["session_fixture_id"] = Value::Null;
    assert_eq!(
        validate_status(
            &serde_json::from_value(missing_session).unwrap(),
            Some(&mode_input())
        ),
        Err(StatusError::SessionEvidence)
    );
}

#[test]
fn t16_stale_checks_remain_bound_to_the_pre_change_reviewed_digest() {
    let value = t16_value();
    validate_status(
        &serde_json::from_value(value.clone()).unwrap(),
        Some(&mode_input()),
    )
    .expect("valid T16");

    let mut rebound_to_current_definition = value;
    rebound_to_current_definition["heartbeat"]["hook_definition_digest"] =
        rebound_to_current_definition["bundled_hook_definition_digest"].clone();
    assert_eq!(
        validate_status(
            &serde_json::from_value(rebound_to_current_definition).unwrap(),
            Some(&mode_input())
        ),
        Err(StatusError::SessionEvidence)
    );
}

#[test]
fn t16_historical_check_cannot_be_reused_for_the_current_session() {
    let mut value = t16_value();
    value["session_fixture_id"] = value["heartbeat"]["session_fixture_id"].clone();
    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
        Err(StatusError::SessionEvidence)
    );
}

#[test]
fn codex_review_cases_reject_cross_case_session_and_definition_evidence() {
    let mut t13_with_existing_session = t13_value();
    t13_with_existing_session["session_fixture_id"] = json!("existing-session");
    t13_with_existing_session["session_state"] = json!("existing_before_review");

    let mut t14_with_unreviewed_reason = t14_value();
    t14_with_unreviewed_reason["hook_evidence"][0]["reason"] = json!("unreviewed_definition");

    let mut t15_with_unbound_loaded_definition = t15_value();
    let other_digest =
        json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    t15_with_unbound_loaded_definition["hook_evidence"][0]["definition_digest"] =
        other_digest.clone();
    t15_with_unbound_loaded_definition["heartbeat"]["hook_definition_digest"] =
        other_digest.clone();
    t15_with_unbound_loaded_definition["self_test"]["hook_definition_digest"] = other_digest;

    let mut t16_with_unbound_current_definition = t16_value();
    t16_with_unbound_current_definition["hook_evidence"][0]["definition_digest"] =
        json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    for value in [
        t13_with_existing_session,
        t14_with_unreviewed_reason,
        t15_with_unbound_loaded_definition,
        t16_with_unbound_current_definition,
    ] {
        assert_eq!(
            validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
            Err(StatusError::SessionEvidence)
        );
    }
}

#[test]
fn claude_disable_all_hooks_preserves_installed_plugin_status() {
    let input = claude_mode_input(vec!["Y2xhdWRl"], None, "claude_disable_all_hooks_true");
    let value = claude_off_value(
        "T06-C",
        "normal",
        None,
        true,
        "claude_disable_all_hooks_true",
        &input,
    );
    validate_status(
        &serde_json::from_value(value.clone()).unwrap(),
        Some(&input),
    )
    .expect("valid Claude disableAllHooks report");

    let mut contradictory_plugin_status = value;
    contradictory_plugin_status["plugin_installed"] = json!(false);
    assert_eq!(
        validate_status(
            &serde_json::from_value(contradictory_plugin_status).unwrap(),
            Some(&input)
        ),
        Err(StatusError::EffectiveProtection)
    );
}

#[test]
fn claude_disabled_status_rejects_loaded_current_hook_evidence() {
    let input = claude_mode_input(vec!["Y2xhdWRl"], None, "claude_disable_all_hooks_true");
    let mut value = claude_off_value(
        "T06-C",
        "normal",
        None,
        true,
        "claude_disable_all_hooks_true",
        &input,
    );
    value["session_fixture_id"] = json!("disabled-session");
    value["session_state"] = json!("new_after_review");
    value["hook_evidence"][0]["disposition"] = json!("loaded_active");
    value["hook_evidence"][0]["reason"] = json!("selected_enabled_source");
    value["heartbeat"] = json!({
        "status": "passed",
        "evidence_scope": "current",
        "session_fixture_id": "disabled-session",
        "hook_source": "claude_user_plugin",
        "hook_definition_digest":
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    });
    value["self_test"] = value["heartbeat"].clone();

    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&input)),
        Err(StatusError::EffectiveProtection)
    );
}

#[test]
fn claude_disabled_launch_modes_are_off_with_exact_mode_evidence() {
    let disable_all_input =
        claude_mode_input(vec!["Y2xhdWRl"], None, "claude_disable_all_hooks_true");
    let bare_input = claude_mode_input(
        vec!["Y2xhdWRl", "LS1iYXJl"],
        None,
        "claude_disable_all_hooks_false",
    );
    let simple_input = claude_mode_input(
        vec!["Y2xhdWRl"],
        Some("MQ=="),
        "claude_disable_all_hooks_false",
    );
    let cases = [
        (
            claude_off_value(
                "T06-C",
                "normal",
                None,
                true,
                "claude_disable_all_hooks_true",
                &disable_all_input,
            ),
            disable_all_input,
        ),
        (
            claude_off_value(
                "T06-D",
                "claude_bare",
                Some(false),
                false,
                "claude_disable_all_hooks_false",
                &bare_input,
            ),
            bare_input,
        ),
        (
            claude_off_value(
                "T06-E",
                "claude_simple",
                Some(false),
                false,
                "claude_disable_all_hooks_false",
                &simple_input,
            ),
            simple_input,
        ),
    ];

    for (value, input) in cases {
        validate_status(&serde_json::from_value(value).unwrap(), Some(&input))
            .expect("valid Claude disabled report");
    }
}

#[test]
fn claude_launch_mode_cannot_be_relabelled_after_hashing_raw_argv() {
    let bare_input = claude_mode_input(
        vec!["Y2xhdWRl", "LS1iYXJl"],
        None,
        "claude_disable_all_hooks_false",
    );
    let relabelled = claude_off_value(
        "T06-D",
        "claude_simple",
        Some(false),
        false,
        "claude_disable_all_hooks_false",
        &bare_input,
    );

    assert_eq!(
        validate_status(
            &serde_json::from_value(relabelled).unwrap(),
            Some(&bare_input)
        ),
        Err(StatusError::ModeEvidence)
    );
}

#[test]
fn claude_setting_claim_must_be_derived_from_the_raw_setting_bytes() {
    let input: ClientModeEvidenceInput = serde_json::from_value(json!({
        "os_string_encoding": "unix_bytes",
        "launch_argv_base64url": ["Y2xhdWRl", "LS1iYXJl"],
        "relevant_environment": [{
            "name_base64url": "Q0xBVURFX0NPREVfU0lNUExF",
            "value_base64url": null
        }],
        "plugin_list_output_base64url": null,
        "ordered_setting_sources": [{
            "source": "claude_user_settings",
            "source_bytes_base64url": "eyJkaXNhYmxlQWxsSG9va3MiOnRydWV9",
            "claim": "claude_disable_all_hooks_false"
        }]
    }))
    .expect("raw Claude mode input");
    let mut relabelled = claude_off_value(
        "T06-D",
        "claude_bare",
        Some(false),
        false,
        "claude_disable_all_hooks_false",
        &input,
    );
    relabelled["client_mode_evidence"]["setting_evidence"][0]["source_digest"] =
        json!("sha256:8d71786a3a7dec5fcb050c095655e59dd5ddbb229d084c354297686fcb575319");

    assert_eq!(
        validate_status(&serde_json::from_value(relabelled).unwrap(), Some(&input)),
        Err(StatusError::ModeEvidence)
    );
}

#[test]
fn claude_explicit_plugin_claim_must_match_raw_launch_argv() {
    let input = claude_mode_input(
        vec![
            "Y2xhdWRl",
            "LS1iYXJl",
            "LS1wbHVnaW4tZGly",
            "L3RydXN0ZWQvc2VjdXJlLW9uYm9hcmQ=",
        ],
        None,
        "claude_disable_all_hooks_false",
    );
    let relabelled = claude_off_value(
        "T06-D",
        "claude_bare",
        Some(false),
        false,
        "claude_disable_all_hooks_false",
        &input,
    );

    assert_eq!(
        validate_status(&serde_json::from_value(relabelled).unwrap(), Some(&input)),
        Err(StatusError::ModeEvidence)
    );
}

#[test]
fn t19_helper_hash_case_cannot_be_relabelled_as_an_argv_mismatch() {
    let value = profile_value(
        "T19-B-HELPER",
        "loaded",
        Some("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        None,
        "helper_hash_mismatch",
    );
    validate_status(
        &serde_json::from_value(value.clone()).unwrap(),
        Some(&mode_input()),
    )
    .expect("valid T19-B-HELPER");

    let mut wrong_binding = value;
    wrong_binding["sentinel_binding_result"] = json!("argv_mismatch");
    assert_eq!(
        validate_status(
            &serde_json::from_value(wrong_binding).unwrap(),
            Some(&mode_input())
        ),
        Err(StatusError::TestProfile)
    );
}

#[test]
fn t19_test_artifact_profile_oracles_validate() {
    let expected = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let different = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let cases = [
        profile_value("T19-A-HIGH", "loaded", Some(expected), None, "matched"),
        profile_value("T19-A-LOW", "loaded", Some(expected), None, "matched"),
        profile_value("T19-A-INFO", "loaded", Some(expected), None, "matched"),
        profile_value(
            "T19-B-MISSING",
            "rejected",
            None,
            Some("profile_missing"),
            "not_evaluated",
        ),
        profile_value(
            "T19-B-DIGEST",
            "rejected",
            Some(different),
            Some("digest_mismatch"),
            "not_evaluated",
        ),
        profile_value(
            "T19-B-SOURCE",
            "rejected",
            Some(expected),
            Some("profile_source_untrusted"),
            "not_evaluated",
        ),
        profile_value(
            "T19-B-HELPER",
            "loaded",
            Some(expected),
            None,
            "helper_hash_mismatch",
        ),
        profile_value(
            "T19-B-ARGV",
            "loaded",
            Some(expected),
            None,
            "argv_mismatch",
        ),
    ];

    for value in cases {
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input()))
            .expect("valid T19 test profile case");
    }
}

#[test]
fn t19_active_sentinel_case_requires_a_matched_binding() {
    let value = profile_value(
        "T19-A-HIGH",
        "loaded",
        Some("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        None,
        "not_evaluated",
    );
    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
        Err(StatusError::TestProfile)
    );
}

#[test]
fn t19_argv_case_cannot_be_relabelled_as_a_helper_hash_mismatch() {
    let value = profile_value(
        "T19-B-ARGV",
        "loaded",
        Some("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        None,
        "helper_hash_mismatch",
    );
    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
        Err(StatusError::TestProfile)
    );
}

#[test]
fn t19_missing_profile_case_requires_an_absent_supplied_digest() {
    let value = profile_value(
        "T19-B-MISSING",
        "rejected",
        Some("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
        Some("digest_mismatch"),
        "not_evaluated",
    );
    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
        Err(StatusError::TestProfile)
    );
}

#[test]
fn t19_profile_rejection_cases_keep_their_exact_reason_and_digest_relation() {
    let expected = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let different = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let relabelled = [
        profile_value(
            "T19-B-DIGEST",
            "rejected",
            Some(expected),
            Some("profile_source_untrusted"),
            "not_evaluated",
        ),
        profile_value(
            "T19-B-SOURCE",
            "rejected",
            Some(different),
            Some("digest_mismatch"),
            "not_evaluated",
        ),
    ];

    for value in relabelled {
        assert_eq!(
            validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
            Err(StatusError::TestProfile)
        );
    }
}

#[test]
fn t15_requires_current_session_hook_heartbeat_and_exact_mode_digest() {
    let report = t15_report();
    validate_status(&report, Some(&mode_input())).expect("valid T15");

    let mut wrong_digest = t15_value();
    wrong_digest["client_mode_evidence"]["evidence_digest"] =
        json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    assert_eq!(
        validate_status(
            &serde_json::from_value(wrong_digest).unwrap(),
            Some(&mode_input())
        ),
        Err(StatusError::ModeEvidence)
    );

    let mut wrong_session = t15_value();
    wrong_session["heartbeat"]["session_fixture_id"] = json!("other-session");
    assert_eq!(
        validate_status(
            &serde_json::from_value(wrong_session).unwrap(),
            Some(&mode_input())
        ),
        Err(StatusError::SessionEvidence)
    );

    let mut wrong_hook_reason = t15_value();
    wrong_hook_reason["hook_evidence"][0]["reason"] = json!("selected_enabled_source");
    assert_eq!(
        validate_status(
            &serde_json::from_value(wrong_hook_reason).unwrap(),
            Some(&mode_input())
        ),
        Err(StatusError::SessionEvidence)
    );
}

#[test]
fn unknown_protection_needs_a_finite_next_check_and_cross_client_sources_fail() {
    let mut unknown = t15_value();
    unknown["effective_protection"] = json!("UNKNOWN");
    assert_eq!(
        validate_status(
            &serde_json::from_value(unknown).unwrap(),
            Some(&mode_input())
        ),
        Err(StatusError::EffectiveProtection)
    );

    let mut cross_client = t15_value();
    cross_client["hook_evidence"][0]["source"] = json!("claude_user_plugin");
    assert_eq!(
        validate_status(
            &serde_json::from_value(cross_client).unwrap(),
            Some(&mode_input())
        ),
        Err(StatusError::ClientSource)
    );
}

#[test]
fn not_installed_is_off_and_cannot_be_reported_active() {
    let mut value = t15_value();
    value["test_case_id"] = json!("T06-A");
    value["plugin_version"] = Value::Null;
    value["plugin_installed"] = json!(false);
    value["hooks_enabled"] = json!(false);
    value["client_mode_evidence"]["plugin_state"] = json!("not_installed");
    value["hook_evidence"] = json!([]);
    value["session_fixture_id"] = Value::Null;
    value["session_state"] = json!("unknown");
    value["heartbeat"] = json!({
        "status": "not_run",
        "evidence_scope": "none",
        "session_fixture_id": null,
        "hook_source": null,
        "hook_definition_digest": null
    });
    value["self_test"] = value["heartbeat"].clone();
    value["product_hook_review"] = json!("unverified");
    value["effective_protection"] = json!("OFF");
    value["sentinel_binding_result"] = json!("not_evaluated");
    value["next_checks"] = json!(["install_plugin"]);
    let report: M0StatusReport = serde_json::from_value(value.clone()).unwrap();
    validate_status(&report, Some(&mode_input())).expect("valid OFF report");

    value["effective_protection"] = json!("VERIFIED_ACTIVE");
    assert!(validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())).is_err());
}

#[test]
fn verified_active_requires_a_concrete_enabled_plugin_mode() {
    let mut value = t15_value();
    value["client_mode_evidence"]["plugin_state"] = json!("unknown");

    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
        Err(StatusError::EffectiveProtection)
    );
}

#[test]
fn verified_active_requires_the_exact_m0_plugin_version() {
    let mut value = t15_value();
    value["plugin_version"] = json!("0.1.1");

    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
        Err(StatusError::EffectiveProtection)
    );
}

#[test]
fn lower_precedence_enabled_setting_cannot_hide_a_project_disable() {
    let input: ClientModeEvidenceInput = serde_json::from_value(json!({
        "os_string_encoding": "unix_bytes",
        "launch_argv_base64url": ["Y29kZXg="],
        "relevant_environment": [],
        "plugin_list_output_base64url": null,
        "ordered_setting_sources": [
            {
                "source": "codex_user_config",
                "source_bytes_base64url": "W2ZlYXR1cmVzXQpob29rcyA9IHRydWUK",
                "claim": "codex_hooks_feature_enabled"
            },
            {
                "source": "codex_project_config",
                "source_bytes_base64url": "W2ZlYXR1cmVzXQpob29rcyA9IGZhbHNlCg==",
                "claim": "codex_hooks_feature_disabled"
            }
        ]
    }))
    .expect("precedence input");
    let mut value = t15_value();
    value["client_mode_evidence"]["setting_evidence"] = json!([
        {
            "source": "codex_user_config",
            "source_digest":
                "sha256:d37497c3278121598a663564ab38b53f658969717f78decb661ddd11c66551ea",
            "claim": "codex_hooks_feature_enabled"
        },
        {
            "source": "codex_project_config",
            "source_digest":
                "sha256:7d59ec088f039328edd6055a108b838c0da1f31822bdc8b9026d66c85b3bbb72",
            "claim": "codex_hooks_feature_disabled"
        }
    ]);
    value["client_mode_evidence"]["evidence_digest"] =
        json!(client_mode_evidence_digest(&input).unwrap());

    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&input)),
        Err(StatusError::ModeEvidence)
    );
}

#[test]
fn claude_managed_local_project_user_precedence_uses_the_top_claim() {
    let input: ClientModeEvidenceInput = serde_json::from_value(json!({
        "os_string_encoding": "unix_bytes",
        "launch_argv_base64url": ["Y2xhdWRl", "LS1iYXJl"],
        "relevant_environment": [{
            "name_base64url": "Q0xBVURFX0NPREVfU0lNUExF",
            "value_base64url": null
        }],
        "plugin_list_output_base64url": null,
        "ordered_setting_sources": [
            {
                "source": "claude_managed_settings",
                "source_bytes_base64url": "eyJkaXNhYmxlQWxsSG9va3MiOnRydWV9",
                "claim": "claude_disable_all_hooks_true"
            },
            {
                "source": "claude_local_settings",
                "source_bytes_base64url": "eyJkaXNhYmxlQWxsSG9va3MiOmZhbHNlfQ==",
                "claim": "claude_disable_all_hooks_false"
            },
            {
                "source": "claude_project_settings",
                "source_bytes_base64url": "eyJkaXNhYmxlQWxsSG9va3MiOmZhbHNlfQ==",
                "claim": "claude_disable_all_hooks_false"
            },
            {
                "source": "claude_user_settings",
                "source_bytes_base64url": "eyJkaXNhYmxlQWxsSG9va3MiOmZhbHNlfQ==",
                "claim": "claude_disable_all_hooks_false"
            }
        ]
    }))
    .expect("Claude precedence input");
    let mut value = claude_off_value(
        "T06-C",
        "claude_bare",
        Some(false),
        true,
        "claude_disable_all_hooks_true",
        &input,
    );
    value["client_mode_evidence"]["setting_evidence"] = json!([
        {
            "source": "claude_managed_settings",
            "source_digest":
                "sha256:8d71786a3a7dec5fcb050c095655e59dd5ddbb229d084c354297686fcb575319",
            "claim": "claude_disable_all_hooks_true"
        },
        {
            "source": "claude_local_settings",
            "source_digest":
                "sha256:b02c742904eeed43594bcc3a3346ba6422728e97f633572b94841e9f1ecd9ae6",
            "claim": "claude_disable_all_hooks_false"
        },
        {
            "source": "claude_project_settings",
            "source_digest":
                "sha256:b02c742904eeed43594bcc3a3346ba6422728e97f633572b94841e9f1ecd9ae6",
            "claim": "claude_disable_all_hooks_false"
        },
        {
            "source": "claude_user_settings",
            "source_digest":
                "sha256:b02c742904eeed43594bcc3a3346ba6422728e97f633572b94841e9f1ecd9ae6",
            "claim": "claude_disable_all_hooks_false"
        }
    ]);

    validate_status(&serde_json::from_value(value).unwrap(), Some(&input))
        .expect("managed setting wins over local, project, and user settings");
}

#[test]
fn configured_scope_off_wins_even_when_the_hook_is_loaded() {
    let mut value = t15_value();
    value["test_case_id"] = json!("T-SCOPE-OFF");
    value["configured_scope_fixture"] = json!("OFF");
    value["effective_protection"] = json!("OFF");

    validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input()))
        .expect("scope OFF report");
}

#[test]
fn configured_scope_off_still_requires_consistent_native_status_fields() {
    let mut value = t15_value();
    value["test_case_id"] = json!("T-SCOPE-OFF");
    value["configured_scope_fixture"] = json!("OFF");
    value["effective_protection"] = json!("OFF");
    value["hooks_enabled"] = json!(false);

    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
        Err(StatusError::EffectiveProtection)
    );
}

#[test]
fn verified_active_heartbeat_and_self_test_must_bind_the_same_hook() {
    let mut value = t15_value();
    value["hook_evidence"].as_array_mut().unwrap().push(json!({
        "source": "codex_user_config",
        "definition_digest":
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "disposition": "loaded_active",
        "reason": "selected_reviewed_definition"
    }));
    value["self_test"]["hook_source"] = json!("codex_user_config");
    value["self_test"]["hook_definition_digest"] =
        json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
        Err(StatusError::EffectiveProtection)
    );
}

#[test]
fn t15_checks_must_bind_the_reviewed_user_plugin_not_a_loaded_project_hook() {
    let mut value = t15_value();
    value["hook_evidence"].as_array_mut().unwrap().push(json!({
        "source": "codex_project_config",
        "definition_digest":
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "disposition": "loaded_active",
        "reason": "selected_reviewed_definition"
    }));
    value["heartbeat"]["hook_source"] = json!("codex_project_config");
    value["heartbeat"]["hook_definition_digest"] =
        json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    value["self_test"] = value["heartbeat"].clone();

    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
        Err(StatusError::EffectiveProtection)
    );
}

#[test]
fn production_profile_probe_requires_bound_artifact_inspection() {
    let mut value = t15_value();
    value["test_case_id"] = json!("T19-C");
    value["test_run_id"] = json!("m0-run-t19-c-01");
    value["artifact_kind"] = json!("production");
    value["test_profile"] = json!("not_supported");
    value["test_profile_expected_digest"] = Value::Null;
    value["test_profile_rejection_reason"] = json!("production_not_supported");
    value["sentinel_binding_result"] = json!("not_evaluated");
    value["run_evidence"] = run_evidence_value("T19-C");
    value["artifact_inspection"] = json!({
        "method": "bound-build-manifest-plus-black-box-profile-probe/v1",
        "build_manifest_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "bound_artifact_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "forbidden_components": [
            "m0_test_profile_loader",
            "m0_sentinel_rules",
            "m0_status_constructor"
        ],
        "forbidden_component_count": 0,
        "black_box_profile_probe": "not_supported",
        "production_emitted_m0_schema_count": 0
    });
    validate_status(
        &serde_json::from_value(value.clone()).unwrap(),
        Some(&mode_input()),
    )
    .expect("valid production probe");

    let mut wrong_case = value.clone();
    wrong_case["test_case_id"] = json!("T15");
    assert_eq!(
        validate_status(
            &serde_json::from_value(wrong_case).unwrap(),
            Some(&mode_input())
        ),
        Err(StatusError::ArtifactInspection)
    );

    let mut missing_inspection = value.clone();
    missing_inspection["artifact_inspection"] = Value::Null;
    assert_eq!(
        validate_status(
            &serde_json::from_value(missing_inspection).unwrap(),
            Some(&mode_input())
        ),
        Err(StatusError::ArtifactInspection)
    );

    let mut wrong_artifact = value.clone();
    wrong_artifact["artifact_inspection"]["bound_artifact_digest"] =
        json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    assert_eq!(
        validate_status(
            &serde_json::from_value(wrong_artifact).unwrap(),
            Some(&mode_input())
        ),
        Err(StatusError::ArtifactInspection)
    );

    value["artifact_inspection"]["forbidden_component_count"] = json!(1);
    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
        Err(StatusError::ArtifactInspection)
    );
}

#[test]
fn parseable_client_version_output_cannot_be_reported_as_unknown() {
    let mut value = t15_value();
    value["client_version"] = Value::Null;
    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
        Err(StatusError::ClientExecutable)
    );
}

#[test]
fn verified_active_requires_the_exact_supported_client_version() {
    let mut value = t15_value();
    value["client_version"] = Value::Null;
    value["client_executable"]["version_output"] = json!("unparseable-version-output");

    assert_eq!(
        validate_status(&serde_json::from_value(value).unwrap(), Some(&mode_input())),
        Err(StatusError::EffectiveProtection)
    );
}

#[test]
fn strict_status_shape_rejects_unknown_fields_and_missing_nullable_fields() {
    let mut value = t15_value();
    value["unexpected"] = json!(true);
    assert!(from_slice::<M0StatusReport>(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut missing = t15_value();
    missing
        .as_object_mut()
        .unwrap()
        .remove("test_profile_rejection_reason");
    assert!(from_slice::<M0StatusReport>(&serde_json::to_vec(&missing).unwrap()).is_err());
}
