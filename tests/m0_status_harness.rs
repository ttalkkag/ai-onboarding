#![cfg(feature = "m0-test-profile")]

use secure_onboard::contracts::{CwdAssurance, CwdResolutionSource, HookEnvelope};
use secure_onboard::m0::{
    Client, EvaluationMetadata, Invocation, M0ActionRequest, M0EventType, Sentinel, evaluate,
};
use secure_onboard::m0_status::{
    ArtifactInspection, ArtifactKind, ClientModeEvidenceInput, M0StatusReport,
    SentinelBindingResult, StatusError, TestProfileRejectionReason, TestProfileState,
    client_mode_evidence_digest,
};
use secure_onboard::m0_status_harness::{
    M0ProductionEvidence, M0StatusFileBindings, StatusHarnessError, T19RunObjects,
    T19RunObservations, construct_status, construct_t19_status,
};
use secure_onboard::strict_json::{canonical_bytes, canonical_sha256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

struct Fixture {
    _root: TempDir,
    client: PathBuf,
    runtime: PathBuf,
    product: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("secure-onboard-t19-status-")
            .tempdir()
            .expect("tempdir");
        let root_path = root.path().canonicalize().expect("physical tempdir");
        let client = root_path.join("codex");
        let runtime = root_path.join("codex-native");
        let product = root_path.join("secure-onboard-m0-hook");
        fs::write(&client, b"codex launcher fixture").expect("client fixture");
        fs::write(&runtime, b"codex runtime fixture").expect("runtime fixture");
        fs::write(&product, b"test product fixture").expect("product fixture");
        Self {
            _root: root,
            client,
            runtime,
            product,
        }
    }

    fn mode_input(&self) -> ClientModeEvidenceInput {
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

    fn report(&self, test_case_id: &str) -> M0StatusReport {
        let input = self.mode_input();
        serde_json::from_value(json!({
            "schema_version": "m0-status-report/v1",
            "phase": "m0",
            "report_source": "test_harness",
            "test_case_id": test_case_id,
            "test_run_id": format!("m0-run-{}-01", test_case_id.to_lowercase()),
            "client": "codex",
            "client_version": "0.146.0",
            "plugin_version": "0.1.0",
            "os": "macos",
            "architecture": "arm64",
            "client_executable": {
                "invoked_path": self.client,
                "resolved_path": self.client,
                "sha256": sha256_file(&self.client),
                "version_output": "codex-cli 0.146.0"
            },
            "client_runtime_artifact": {
                "role": "native_backend",
                "absolute_path": self.runtime,
                "sha256": sha256_file(&self.runtime)
            },
            "artifact_kind": "test",
            "artifact_digest": sha256_file(&self.product),
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
                    "source_digest":
                        "sha256:d37497c3278121598a663564ab38b53f658969717f78decb661ddd11c66551ea",
                    "claim": "codex_hooks_feature_enabled"
                }],
                "evidence_digest": client_mode_evidence_digest(&input).expect("mode digest")
            },
            "session_fixture_id": "m0-session-01",
            "session_state": "new_after_review",
            "hook_evidence": [{
                "source": "codex_user_plugin",
                "definition_digest":
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "disposition": "loaded_active",
                "reason": "selected_reviewed_definition"
            }],
            "bundled_hook_definition_digest":
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "reviewed_hook_definition_digest":
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "product_hook_review": "verified",
            "heartbeat": {
                "status": "passed",
                "evidence_scope": "current",
                "session_fixture_id": "m0-session-01",
                "hook_source": "codex_user_plugin",
                "hook_definition_digest":
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "self_test": {
                "status": "passed",
                "evidence_scope": "current",
                "session_fixture_id": "m0-session-01",
                "hook_source": "codex_user_plugin",
                "hook_definition_digest":
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            },
            "client_trust": "unknown",
            "effective_protection": "VERIFIED_ACTIVE",
            "test_profile": "loaded",
            "test_profile_expected_digest":
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "test_profile_supplied_digest":
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "test_profile_rejection_reason": null,
            "sentinel_binding_result": "matched",
            "next_checks": [],
            "run_evidence": null,
            "artifact_inspection": null,
            "reasons": [],
            "limitations": ["M0 status is test-harness evidence"]
        }))
        .expect("status report")
    }

    fn bindings(&self) -> M0StatusFileBindings<'_> {
        M0StatusFileBindings {
            client_invoked_path: &self.client,
            client_runtime_artifact_path: &self.runtime,
            product_artifact_path: &self.product,
            production_evidence: None,
        }
    }

    fn claude_bindings(&self) -> M0StatusFileBindings<'_> {
        M0StatusFileBindings {
            client_invoked_path: &self.client,
            client_runtime_artifact_path: &self.client,
            product_artifact_path: &self.product,
            production_evidence: None,
        }
    }
}

#[test]
fn t19_high_constructor_binds_exact_counts_digests_and_event_order() {
    let fixture = Fixture::new();
    let report = fixture.report("T19-A-HIGH");
    let run_id = report.test_run_id.clone();
    let request = request("T19-A-HIGH", &run_id, Sentinel::High);
    let output = evaluate(
        request.clone(),
        EvaluationMetadata {
            decision_id: "m0-decision-01".into(),
            event_ids: ["m0-event-01".into(), "m0-event-02".into()],
            observed_at: "2026-07-29T00:00:00Z".into(),
        },
    )
    .expect("core output");
    let envelope = pre_envelope("m0-envelope-01");

    let validated = construct_t19_status(
        report,
        &fixture.mode_input(),
        fixture.bindings(),
        T19RunObjects {
            hook_envelopes: vec![envelope.clone()],
            action_requests: vec![request.clone()],
            action_decisions: vec![output.decision.clone()],
            events: output.events.clone(),
        },
        T19RunObservations {
            target_process_start_count: 0,
            target_marker_count: 0,
            operator_approval_count: 0,
            secure_onboard_approval_count: 0,
            uncorrelated_result_count: 0,
        },
    )
    .expect("validated T19 HIGH run");

    let evidence = validated
        .report
        .run_evidence
        .as_ref()
        .expect("run evidence");
    assert_eq!(
        evidence.object_counts,
        serde_json::from_value(json!({
            "hook_envelope": 1,
            "m0_action_request": 1,
            "m0_action_decision": 1,
            "m0_event": 2,
            "m0_status_report": 1
        }))
        .unwrap()
    );
    assert_eq!(
        evidence.ordered_events,
        [M0EventType::HighDetected, M0EventType::HighBlocked]
    );
    assert_eq!(
        evidence.canonical_digests.hook_envelope,
        [canonical_sha256(&envelope).unwrap()]
    );
    assert_eq!(
        evidence.canonical_digests.m0_action_request,
        [canonical_sha256(&request).unwrap()]
    );
    assert_eq!(
        validated.status_report_digest,
        canonical_sha256(&validated.report).unwrap()
    );
}

#[test]
fn codex_t19_low_constructor_excludes_the_ambiguous_result_hook() {
    let fixture = Fixture::new();
    let report = fixture.report("T19-A-LOW");
    let run_id = report.test_run_id.clone();
    let request = request("T19-A-LOW", &run_id, Sentinel::Low);
    let output = evaluate(
        request.clone(),
        EvaluationMetadata {
            decision_id: "m0-decision-01".into(),
            event_ids: ["m0-event-01".into(), "unused".into()],
            observed_at: "2026-07-29T00:00:00Z".into(),
        },
    )
    .expect("core output");
    let validated = construct_t19_status(
        report,
        &fixture.mode_input(),
        fixture.bindings(),
        T19RunObjects {
            hook_envelopes: vec![pre_envelope("m0-envelope-01")],
            action_requests: vec![request],
            action_decisions: vec![output.decision],
            events: output.events,
        },
        started_observations(),
    )
    .expect("validated T19 LOW run");

    assert_eq!(
        validated.report.run_evidence.unwrap().ordered_events,
        [M0EventType::WarnedLow]
    );
}

#[test]
fn t19_event_reordering_fails_the_case_oracle() {
    let fixture = Fixture::new();
    let report = fixture.report("T19-A-HIGH");
    let request = request("T19-A-HIGH", &report.test_run_id, Sentinel::High);
    let mut output = evaluate(
        request.clone(),
        EvaluationMetadata {
            decision_id: "m0-decision-01".into(),
            event_ids: ["m0-event-01".into(), "m0-event-02".into()],
            observed_at: "2026-07-29T00:00:00Z".into(),
        },
    )
    .expect("core output");
    output.events.reverse();

    let error = construct_t19_status(
        report,
        &fixture.mode_input(),
        fixture.bindings(),
        T19RunObjects {
            hook_envelopes: vec![pre_envelope("m0-envelope-01")],
            action_requests: vec![request],
            action_decisions: vec![output.decision],
            events: output.events,
        },
        stopped_observations(),
    )
    .expect_err("reordered events must fail");

    assert_eq!(error, StatusHarnessError::Status(StatusError::RunEvidence));
}

#[test]
fn t19_loader_only_and_near_match_cases_have_distinct_exact_counts() {
    let fixture = Fixture::new();
    let mut missing = fixture.report("T19-B-MISSING");
    missing.test_profile = TestProfileState::Rejected;
    missing.test_profile_supplied_digest = None;
    missing.test_profile_rejection_reason = Some(TestProfileRejectionReason::ProfileMissing);
    missing.sentinel_binding_result = SentinelBindingResult::NotEvaluated;
    let missing = construct_t19_status(
        missing,
        &fixture.mode_input(),
        fixture.bindings(),
        empty_objects(),
        stopped_observations(),
    )
    .expect("loader-only missing profile");
    assert_eq!(
        missing
            .report
            .run_evidence
            .unwrap()
            .object_counts
            .hook_envelope,
        0
    );

    let mut helper = fixture.report("T19-B-HELPER");
    helper.sentinel_binding_result = SentinelBindingResult::HelperHashMismatch;
    let helper = construct_t19_status(
        helper,
        &fixture.mode_input(),
        fixture.bindings(),
        T19RunObjects {
            hook_envelopes: vec![pre_envelope("m0-envelope-01")],
            action_requests: vec![],
            action_decisions: vec![],
            events: vec![],
        },
        started_observations(),
    )
    .expect("near-match helper run");
    assert_eq!(
        helper
            .report
            .run_evidence
            .unwrap()
            .object_counts
            .hook_envelope,
        1
    );
}

#[test]
fn remaining_t19_test_artifact_rows_construct_as_independent_runs() {
    let fixture = Fixture::new();

    let info_report = fixture.report("T19-A-INFO");
    let info_request = request("T19-A-INFO", &info_report.test_run_id, Sentinel::Info);
    let info_output = evaluate(
        info_request.clone(),
        EvaluationMetadata {
            decision_id: "m0-decision-01".into(),
            event_ids: ["m0-event-01".into(), "unused".into()],
            observed_at: "2026-07-29T00:00:00Z".into(),
        },
    )
    .expect("INFO core output");
    construct_t19_status(
        info_report,
        &fixture.mode_input(),
        fixture.bindings(),
        T19RunObjects {
            hook_envelopes: vec![pre_envelope("m0-envelope-01")],
            action_requests: vec![info_request],
            action_decisions: vec![info_output.decision],
            events: info_output.events,
        },
        started_observations(),
    )
    .expect("T19-A-INFO");

    let different =
        Some("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned());
    let cases = [
        (
            "T19-B-DIGEST",
            different,
            TestProfileRejectionReason::DigestMismatch,
        ),
        (
            "T19-B-SOURCE",
            Some(
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_owned(),
            ),
            TestProfileRejectionReason::ProfileSourceUntrusted,
        ),
    ];
    for (case_id, supplied, reason) in cases {
        let mut report = fixture.report(case_id);
        report.test_profile = TestProfileState::Rejected;
        report.test_profile_supplied_digest = supplied;
        report.test_profile_rejection_reason = Some(reason);
        report.sentinel_binding_result = SentinelBindingResult::NotEvaluated;
        construct_t19_status(
            report,
            &fixture.mode_input(),
            fixture.bindings(),
            empty_objects(),
            stopped_observations(),
        )
        .unwrap_or_else(|error| panic!("{case_id}: {error}"));
    }

    let mut argv = fixture.report("T19-B-ARGV");
    argv.sentinel_binding_result = SentinelBindingResult::ArgvMismatch;
    construct_t19_status(
        argv,
        &fixture.mode_input(),
        fixture.bindings(),
        T19RunObjects {
            hook_envelopes: vec![pre_envelope("m0-envelope-01")],
            action_requests: vec![],
            action_decisions: vec![],
            events: vec![],
        },
        started_observations(),
    )
    .expect("T19-B-ARGV");
}

#[test]
fn status_constructor_reobserves_bound_artifact_bytes() {
    let fixture = Fixture::new();
    let report = fixture.report("T19-A-HIGH");
    let request = request("T19-A-HIGH", &report.test_run_id, Sentinel::High);
    let output = evaluate(
        request.clone(),
        EvaluationMetadata {
            decision_id: "m0-decision-01".into(),
            event_ids: ["m0-event-01".into(), "m0-event-02".into()],
            observed_at: "2026-07-29T00:00:00Z".into(),
        },
    )
    .expect("core output");
    fs::write(&fixture.product, b"changed after report construction").expect("mutate fixture");

    let error = construct_t19_status(
        report,
        &fixture.mode_input(),
        fixture.bindings(),
        T19RunObjects {
            hook_envelopes: vec![pre_envelope("m0-envelope-01")],
            action_requests: vec![request],
            action_decisions: vec![output.decision],
            events: output.events,
        },
        stopped_observations(),
    )
    .expect_err("stale artifact digest must fail");
    assert_eq!(error, StatusHarnessError::FileBinding);
}

#[test]
fn t19_production_status_binds_the_same_artifact_component_manifest_and_probe() {
    let fixture = Fixture::new();
    let component_probe =
        b"{\"components\":[\"production_profile_rejection\"],\"schema_version\":\"secure-onboard-build-components/v1\"}\n";
    let mut build_manifest = canonical_bytes(&json!({
        "schema_version": "secure-onboard-bound-build-manifest/v1",
        "artifact_sha256": sha256_file(&fixture.product),
        "component_manifest_sha256": sha256_bytes(component_probe),
        "components": ["production_profile_rejection"]
    }))
    .expect("canonical build manifest");
    build_manifest.push(b'\n');

    let mut report = fixture.report("T19-C");
    report.artifact_kind = ArtifactKind::Production;
    report.test_profile = TestProfileState::NotSupported;
    report.test_profile_expected_digest = None;
    report.test_profile_rejection_reason = Some(TestProfileRejectionReason::ProductionNotSupported);
    report.sentinel_binding_result = SentinelBindingResult::NotEvaluated;
    report.artifact_inspection = Some(ArtifactInspection {
        method: "bound-build-manifest-plus-black-box-profile-probe/v1".into(),
        build_manifest_digest: sha256_bytes(&build_manifest),
        bound_artifact_digest: report.artifact_digest.clone(),
        forbidden_components: vec![
            "m0_test_profile_loader".into(),
            "m0_sentinel_rules".into(),
            "m0_status_constructor".into(),
        ],
        forbidden_component_count: 0,
        black_box_profile_probe: "not_supported".into(),
        production_emitted_m0_schema_count: 0,
    });

    let validated = construct_t19_status(
        report,
        &fixture.mode_input(),
        M0StatusFileBindings {
            client_invoked_path: &fixture.client,
            client_runtime_artifact_path: &fixture.runtime,
            product_artifact_path: &fixture.product,
            production_evidence: Some(M0ProductionEvidence {
                bound_build_manifest_bytes: &build_manifest,
                component_probe_stdout: component_probe,
                component_probe_stderr: b"",
                profile_probe_stdout: b"{\"profile\":\"not_supported\"}\n",
                profile_probe_stderr: b"",
            }),
        },
        empty_objects(),
        stopped_observations(),
    )
    .expect("validated production status");

    assert_eq!(
        validated
            .report
            .run_evidence
            .unwrap()
            .object_counts
            .m0_status_report,
        1
    );
}

#[test]
fn status_constructor_covers_t06_and_t12_through_t17_fixture_projections() {
    let fixture = Fixture::new();

    let mut not_installed = report_value(&fixture, "T06-A");
    not_installed["plugin_version"] = Value::Null;
    not_installed["plugin_installed"] = json!(false);
    not_installed["hooks_enabled"] = json!(false);
    not_installed["client_mode_evidence"]["plugin_state"] = json!("not_installed");
    not_installed["hook_evidence"] = json!([]);
    make_unknown_session(&mut not_installed);
    not_installed["product_hook_review"] = json!("unverified");
    not_installed["reviewed_hook_definition_digest"] = Value::Null;
    not_installed["effective_protection"] = json!("OFF");
    not_installed["next_checks"] = json!(["install_plugin"]);
    construct_status(
        parse_report(not_installed),
        &fixture.mode_input(),
        fixture.bindings(),
    )
    .expect("T06-A");

    let codex_disabled_input = codex_mode_input(false);
    let mut codex_disabled = report_value(&fixture, "T06-B");
    codex_disabled["hooks_enabled"] = json!(false);
    codex_disabled["client_mode_evidence"]["codex_hooks_feature"] = json!("disabled");
    codex_disabled["client_mode_evidence"]["setting_evidence"] = json!([{
        "source": "codex_user_config",
        "source_digest":
            "sha256:7d59ec088f039328edd6055a108b838c0da1f31822bdc8b9026d66c85b3bbb72",
        "claim": "codex_hooks_feature_disabled"
    }]);
    make_unknown_session(&mut codex_disabled);
    codex_disabled["hook_evidence"][0]["disposition"] = json!("skipped");
    codex_disabled["hook_evidence"][0]["reason"] = json!("hooks_disabled");
    codex_disabled["effective_protection"] = json!("OFF");
    codex_disabled["next_checks"] = json!(["enable_hooks"]);
    construct_status(
        parse_report(codex_disabled),
        &codex_disabled_input,
        fixture.bindings(),
    )
    .expect("T06-B");

    for (case_id, argv, simple, launch_mode, explicit, disable, claim) in [
        (
            "T06-C",
            vec!["Y2xhdWRl"],
            None,
            "normal",
            None,
            true,
            "claude_disable_all_hooks_true",
        ),
        (
            "T06-D",
            vec!["Y2xhdWRl", "LS1iYXJl"],
            None,
            "claude_bare",
            Some(false),
            false,
            "claude_disable_all_hooks_false",
        ),
        (
            "T06-E",
            vec!["Y2xhdWRl"],
            Some("MQ=="),
            "claude_simple",
            Some(false),
            false,
            "claude_disable_all_hooks_false",
        ),
    ] {
        let input = claude_mode_input(argv, simple, claim);
        let report = claude_off_report(&fixture, case_id, launch_mode, explicit, disable, claim);
        construct_status(report, &input, fixture.claude_bindings())
            .unwrap_or_else(|error| panic!("{case_id}: {error}"));
    }

    for case_id in ["T12", "T13", "T14", "T15", "T16", "T17"] {
        let report = codex_review_report(&fixture, case_id);
        construct_status(report, &fixture.mode_input(), fixture.bindings())
            .unwrap_or_else(|error| panic!("{case_id}: {error}"));
    }
}

fn report_value(fixture: &Fixture, case_id: &str) -> Value {
    serde_json::to_value(fixture.report(case_id)).expect("status value")
}

fn parse_report(value: Value) -> M0StatusReport {
    serde_json::from_value(value).expect("status projection")
}

fn make_unknown_session(value: &mut Value) {
    value["session_fixture_id"] = Value::Null;
    value["session_state"] = json!("unknown");
    value["heartbeat"] = not_run_check();
    value["self_test"] = not_run_check();
    value["sentinel_binding_result"] = json!("not_evaluated");
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

fn codex_mode_input(enabled: bool) -> ClientModeEvidenceInput {
    let (source, claim) = if enabled {
        (
            "W2ZlYXR1cmVzXQpob29rcyA9IHRydWUK",
            "codex_hooks_feature_enabled",
        )
    } else {
        (
            "W2ZlYXR1cmVzXQpob29rcyA9IGZhbHNlCg==",
            "codex_hooks_feature_disabled",
        )
    };
    serde_json::from_value(json!({
        "os_string_encoding": "unix_bytes",
        "launch_argv_base64url": ["Y29kZXg="],
        "relevant_environment": [],
        "plugin_list_output_base64url": null,
        "ordered_setting_sources": [{
            "source": "codex_user_config",
            "source_bytes_base64url": source,
            "claim": claim
        }]
    }))
    .expect("Codex mode input")
}

fn claude_mode_input(
    argv: Vec<&str>,
    simple: Option<&str>,
    claim: &str,
) -> ClientModeEvidenceInput {
    let source = match claim {
        "claude_disable_all_hooks_true" => "eyJkaXNhYmxlQWxsSG9va3MiOnRydWV9",
        "claude_disable_all_hooks_false" => "eyJkaXNhYmxlQWxsSG9va3MiOmZhbHNlfQ==",
        _ => panic!("unsupported Claude claim"),
    };
    serde_json::from_value(json!({
        "os_string_encoding": "unix_bytes",
        "launch_argv_base64url": argv,
        "relevant_environment": [{
            "name_base64url": "Q0xBVURFX0NPREVfU0lNUExF",
            "value_base64url": simple
        }],
        "plugin_list_output_base64url": null,
        "ordered_setting_sources": [{
            "source": "claude_user_settings",
            "source_bytes_base64url": source,
            "claim": claim
        }]
    }))
    .expect("Claude mode input")
}

fn claude_off_report(
    fixture: &Fixture,
    case_id: &str,
    launch_mode: &str,
    explicit_plugin_supplied: Option<bool>,
    disable_all_hooks: bool,
    claim: &str,
) -> M0StatusReport {
    let source_digest = match claim {
        "claude_disable_all_hooks_true" => {
            "sha256:8d71786a3a7dec5fcb050c095655e59dd5ddbb229d084c354297686fcb575319"
        }
        "claude_disable_all_hooks_false" => {
            "sha256:b02c742904eeed43594bcc3a3346ba6422728e97f633572b94841e9f1ecd9ae6"
        }
        _ => panic!("unsupported Claude claim"),
    };
    let mut value = report_value(fixture, case_id);
    value["client"] = json!("claude");
    value["client_version"] = json!("2.1.220");
    value["client_executable"] = json!({
        "invoked_path": fixture.client,
        "resolved_path": fixture.client,
        "sha256": sha256_file(&fixture.client),
        "version_output": "2.1.220 (Claude Code)"
    });
    value["client_runtime_artifact"] = json!({
        "role": "resolved_executable",
        "absolute_path": fixture.client,
        "sha256": sha256_file(&fixture.client)
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
        "evidence_digest": null
    });
    make_unknown_session(&mut value);
    value["hook_evidence"] = json!([{
        "source": "claude_user_plugin",
        "definition_digest":
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "disposition": "skipped",
        "reason": "hooks_disabled"
    }]);
    value["bundled_hook_definition_digest"] = Value::Null;
    value["reviewed_hook_definition_digest"] = Value::Null;
    value["product_hook_review"] = json!("not_applicable");
    value["client_trust"] = json!("not_applicable");
    value["effective_protection"] = json!("OFF");
    value["next_checks"] = json!(["enable_hooks"]);
    parse_report(value)
}

fn codex_review_report(fixture: &Fixture, case_id: &str) -> M0StatusReport {
    let mut value = report_value(fixture, case_id);
    match case_id {
        "T12" | "T13" => {
            make_unknown_session(&mut value);
            value["hook_evidence"][0]["disposition"] = json!("skipped");
            value["hook_evidence"][0]["reason"] = json!("unreviewed_definition");
            value["reviewed_hook_definition_digest"] = Value::Null;
            value["product_hook_review"] = json!("unverified");
            value["effective_protection"] = json!("UNKNOWN");
            value["next_checks"] = json!(["review_current_hook_definition"]);
        }
        "T14" => {
            value["session_fixture_id"] = json!("m0-session-existing-01");
            value["session_state"] = json!("existing_before_review");
            value["hook_evidence"][0]["disposition"] = json!("skipped");
            value["hook_evidence"][0]["reason"] = json!("session_predates_review");
            value["heartbeat"] = not_run_check();
            value["self_test"] = not_run_check();
            value["effective_protection"] = json!("UNKNOWN");
            value["sentinel_binding_result"] = json!("not_evaluated");
            value["next_checks"] = json!(["start_new_client_session"]);
        }
        "T15" => {}
        "T16" => {
            make_unknown_session(&mut value);
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
            value["next_checks"] = json!(["review_current_hook_definition"]);
        }
        "T17" => {
            value["hook_evidence"].as_array_mut().unwrap().push(json!({
                "source": "codex_project_config",
                "definition_digest":
                    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "disposition": "skipped",
                "reason": "untrusted_project_source"
            }));
        }
        _ => panic!("unsupported Codex review case"),
    }
    parse_report(value)
}

fn request(test_case_id: &str, test_run_id: &str, sentinel: Sentinel) -> M0ActionRequest {
    M0ActionRequest {
        schema_version: "m0-action-request/v1".into(),
        phase: "m0".into(),
        test_case_id: test_case_id.into(),
        test_run_id: test_run_id.into(),
        test_profile_digest:
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
        action_id: "m0-action-01".into(),
        envelope_id: "m0-envelope-01".into(),
        client: Client::Codex,
        session_fixture_id: "m0-session-01".into(),
        native_tool_call_id: "m0-tool-01".into(),
        sentinel,
        invocation: Invocation::ShellText {
            shell_executable: "/bin/zsh".into(),
            shell_flags: vec!["-lc".into()],
            dialect: "posix_sh".into(),
            command_text: "/usr/bin/true".into(),
            shell_resolution_source: "m0_runtime_probe".into(),
            shell_resolution_fingerprint:
                "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into(),
        },
        physical_cwd_fixture: "/private/tmp/m0-project".into(),
        cwd_resolution_source: "m0_effective_cwd_binding".into(),
    }
}

fn pre_envelope(envelope_id: &str) -> HookEnvelope {
    HookEnvelope::PreToolUse {
        schema_version: "hook-envelope/v1".into(),
        envelope_id: envelope_id.into(),
        occurred_at: "2026-07-29T00:00:00Z".into(),
        client: Client::Codex,
        session_id: "m0-session-01".into(),
        adapter_turn_id: Some("m0-turn-01".into()),
        native_tool_call_id: "m0-tool-01".into(),
        prompt_context_id: None,
        native_tool_name: "Bash".into(),
        native_tool_input: json!({"command": "/usr/bin/true"}),
        tool_name: "shell_exec".into(),
        tool_input: json!({"command_text": "/usr/bin/true"}),
        native_session_cwd: "/private/tmp/m0-project".into(),
        physical_cwd: Some("/private/tmp/m0-project".into()),
        cwd_assurance: CwdAssurance::Verified,
        cwd_resolution_source: CwdResolutionSource::M0EffectiveCwdBinding,
    }
}

fn empty_objects() -> T19RunObjects {
    T19RunObjects {
        hook_envelopes: vec![],
        action_requests: vec![],
        action_decisions: vec![],
        events: vec![],
    }
}

fn stopped_observations() -> T19RunObservations {
    T19RunObservations {
        target_process_start_count: 0,
        target_marker_count: 0,
        operator_approval_count: 0,
        secure_onboard_approval_count: 0,
        uncorrelated_result_count: 0,
    }
}

fn started_observations() -> T19RunObservations {
    T19RunObservations {
        target_process_start_count: 1,
        target_marker_count: 1,
        operator_approval_count: 1,
        secure_onboard_approval_count: 0,
        uncorrelated_result_count: 0,
    }
}

fn sha256_file(path: &Path) -> String {
    sha256_bytes(&fs::read(path).expect("fixture bytes"))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
