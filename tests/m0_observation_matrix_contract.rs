#![cfg(feature = "m0-test-profile")]

use secure_onboard::m0_observation_matrix::{
    CoverageEffect, HarnessSourceOutputs, MAX_HARNESS_SOURCE_OUTPUT_BYTES, ObservationMatrixError,
    ObservationStatus, validate_harness_source_outputs, validate_observation_matrix,
};
use secure_onboard::strict_json::from_slice;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;
use tempfile::TempDir;

const MATRIX: &str = "tests/fixtures/m0/observations/macos-arm64.json";
const NATIVE_OBSERVATION: &str = "tests/fixtures/m0/observations/native-macos-arm64.json";
const HARNESS_SUMMARY: &str = "tests/fixtures/m0/observations/harness-summary.json";

fn matrix_bytes() -> Vec<u8> {
    fs::read(MATRIX).expect("read checked M0 observation matrix")
}

fn matrix_value() -> Value {
    from_slice(&matrix_bytes()).expect("strict checked matrix")
}

fn validate(value: &Value) -> bool {
    validate_observation_matrix(
        &serde_json::to_vec(value).expect("serialize mutated matrix"),
        Path::new(env!("CARGO_MANIFEST_DIR")),
    )
    .is_ok()
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn repository_temporary_directory() -> TempDir {
    TempDir::new_in(repository_root()).expect("temporary directory inside repository")
}

fn repository_relative(path: &Path) -> String {
    path.strip_prefix(repository_root())
        .expect("path inside repository")
        .to_str()
        .expect("UTF-8 repository-relative path")
        .to_owned()
}

#[test]
fn checked_matrix_is_exactly_two_targets_by_46_cases_with_zero_verified_coverage() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let matrix =
        validate_observation_matrix(&matrix_bytes(), root).expect("valid observation matrix");

    assert_eq!(matrix.cases.len(), 46);
    assert_eq!(matrix.m1_gate.as_str(), "NO_GO");
    let claude = matrix
        .cases
        .iter()
        .map(|case| &case.claude)
        .collect::<Vec<_>>();
    let codex = matrix
        .cases
        .iter()
        .map(|case| &case.codex)
        .collect::<Vec<_>>();
    for (observations, expected) in [(&claude, [0, 24, 0, 11, 11]), (&codex, [0, 12, 16, 14, 4])] {
        let counts = [
            ObservationStatus::Verified,
            ObservationStatus::ContractOnly,
            ObservationStatus::ObservedUnsupported,
            ObservationStatus::Unverified,
            ObservationStatus::NotApplicable,
        ]
        .map(|status| {
            observations
                .iter()
                .filter(|observation| observation.status == status)
                .count()
        });
        assert_eq!(counts, expected);
    }
    assert_eq!(
        matrix
            .cases
            .iter()
            .flat_map(|case| [&case.claude, &case.codex])
            .filter(|observation| observation.coverage_effect == CoverageEffect::Included)
            .count(),
        0
    );
}

#[test]
fn checked_native_result_preserves_unknown_process_approval_and_prompt_boundaries() {
    let observation: Value =
        from_slice(&fs::read(NATIVE_OBSERVATION).expect("native observation bytes"))
            .expect("strict native observation JSON");

    assert_eq!(
        observation.pointer("/host/target_process_started"),
        Some(&Value::Null)
    );
    for client in ["claude", "codex"] {
        for fault in observation[client]["adapter_faults"]
            .as_array()
            .expect("adapter faults")
        {
            assert_eq!(fault["target_process_started"], Value::Null);
            assert_eq!(
                fault["approval_boundary"],
                "unverified_noninteractive_bypass_mode_no_operator_approval"
            );
        }
    }
    assert_eq!(
        observation.pointer("/codex/live/result_outcome"),
        Some(&json!("ambiguous_rejected"))
    );
    assert_eq!(
        observation.pointer("/codex/prompt_continuation/user_prompt_submit_count"),
        Some(&json!(1))
    );
    assert_eq!(
        observation.pointer("/codex/prompt_continuation/stop_count"),
        Some(&json!(2))
    );
    assert_eq!(
        observation.pointer("/codex/prompt_continuation/stop_hook_active"),
        Some(&json!([false, true]))
    );
    assert_eq!(
        observation.pointer("/codex/prompt_continuation/continuation_transport"),
        Some(&json!("api_hook_prompt"))
    );
    assert_eq!(
        observation.pointer("/codex/prompt_continuation/second_user_prompt_submit_observed"),
        Some(&json!(false))
    );
    assert_eq!(
        observation.pointer("/provenance/case_results_sha256"),
        Some(&json!(
            "sha256:6f941fa4d96dd2e9c05c0c46bdbaf5da74f2006f09ebd33323c50200097a21d2"
        ))
    );
}

#[test]
fn checked_harness_summary_binds_sources_without_storing_raw_sensitive_inputs() {
    let summary: Value = from_slice(&fs::read(HARNESS_SUMMARY).expect("harness summary bytes"))
        .expect("strict harness summary JSON");
    let runs = summary["harness_runs"].as_object().expect("harness runs");
    assert_eq!(runs.len(), 5);
    let mut source_digests = std::collections::HashSet::new();
    for run in runs.values() {
        assert!(
            run["source_output_bytes"]
                .as_u64()
                .is_some_and(|size| size > 0)
        );
        assert!(
            source_digests.insert(
                run["source_output_sha256"]
                    .as_str()
                    .expect("source output digest")
            )
        );
    }

    fn assert_redacted(value: &Value) {
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    assert!(
                        !matches!(
                            key.as_str(),
                            "raw"
                                | "raw_command"
                                | "command"
                                | "environment"
                                | "run_root"
                                | "source_output_path"
                                | "temporary_path"
                        ),
                        "forbidden provenance key: {key}"
                    );
                    assert_redacted(child);
                }
            }
            Value::Array(values) => values.iter().for_each(assert_redacted),
            Value::String(text) => {
                assert!(!text.contains("/private/var/"));
                assert!(!text.contains("/private/tmp/"));
                assert!(!text.contains("SECURE_ONBOARD_HUMAN_PROMPT"));
                assert!(!text.contains("M0_CONTINUATION"));
            }
            _ => {}
        }
    }
    assert_redacted(&summary);
}

fn bind_source(summary: &mut Value, run: &str, bytes: &[u8]) {
    summary["harness_runs"][run]["source_output_sha256"] = json!(digest(bytes));
    summary["harness_runs"][run]["source_output_bytes"] = json!(bytes.len());
}

fn synthetic_harness_sources(summary: &Value) -> [Value; 5] {
    let claude_cases = [
        (
            "high",
            "high",
            "default",
            "none",
            false,
            json!(null),
            json!(null),
        ),
        (
            "low",
            "low",
            "default",
            "none",
            true,
            json!(null),
            json!(true),
        ),
        (
            "info",
            "info",
            "default",
            "none",
            true,
            json!(null),
            json!(null),
        ),
        (
            "low-failure-helper",
            "low",
            "failure",
            "none",
            true,
            json!(null),
            json!(true),
        ),
        (
            "info-failure-helper",
            "info",
            "failure",
            "none",
            true,
            json!(null),
            json!(null),
        ),
        (
            "info-core-timeout",
            "info",
            "default",
            "timeout",
            false,
            json!(null),
            json!(null),
        ),
        (
            "info-core-nonzero",
            "info",
            "default",
            "nonzero",
            false,
            json!(null),
            json!(null),
        ),
        (
            "info-core-schema-invalid",
            "info",
            "default",
            "schema-invalid",
            false,
            json!(null),
            json!(null),
        ),
        (
            "high-sibling",
            "high",
            "default",
            "none",
            false,
            json!(true),
            json!(null),
        ),
    ];
    let claude_results = claude_cases
        .into_iter()
        .map(
            |(case, sentinel, helper, core_fault, marker, sibling, warning)| {
                json!({
                    "case": case,
                    "sentinel": sentinel,
                    "helper": helper,
                    "core_fault": core_fault,
                    "marker_exists": marker,
                    "target_process_started": null,
                    "target_process_observation_count": 0,
                    "target_process_observer": "unavailable_operation_not_permitted",
                    "sibling_marker_exists": sibling,
                    "warning_stream_received_before_target": warning,
                    "hook_response_count": 1,
                    "evidence_counts": {}
                })
            },
        )
        .collect::<Vec<_>>();
    let claude_live = json!({
        "schema_version": "m0-claude-native-harness-result/v1",
        "claude_executable": "/pinned/claude",
        "claude_version": "2.1.220 (Claude Code)",
        "environment_binding": {
            "os_build": "25F84",
            "architecture": "arm64",
            "client_sha256": summary["clients"]["claude"]["client_executable_sha256"],
            "client_version_output": "2.1.220 (Claude Code)"
        },
        "product_artifacts": {
            "hook_sha256": summary["clients"]["claude"]["product_hook_sha256"],
            "core_sha256": summary["clients"]["claude"]["product_core_sha256"]
        },
        "run_root": "/ephemeral",
        "kernel_network_confinement": "unavailable_sandbox_exec_operation_not_permitted",
        "proxy_egress_observations": 0,
        "results": claude_results
    });
    let codex_source = |probe: &str, high: Value| {
        json!({
            "schema_version": "m0-codex-native-harness-result/v1",
            "codex_executable": "/pinned/codex",
            "codex_version": "codex-cli 0.146.0",
            "environment_binding": {
                "os_build": "25F84",
                "architecture": "arm64",
                "client_invoked_path": "/opt/homebrew/bin/codex",
                "client_resolved_path": "/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js",
                "client_sha256": summary["clients"]["codex"]["client_executable_sha256"],
                "client_version_output": "codex-cli 0.146.0"
            },
            "product_artifacts": {
                "hook_sha256": summary["clients"]["codex"]["product_hook_sha256"],
                "core_sha256": summary["clients"]["codex"]["product_core_sha256"]
            },
            "run_root": "/ephemeral",
            "kernel_network_confinement": "unavailable_sandbox_exec_operation_not_permitted",
            "proxy_egress_observations": 0,
            "cwd_binding": "unverified",
            "coverage": "excluded",
            "probe_kind": probe,
            "target_marker_exists": true,
            "high_marker_exists": high,
            "system_message_observed": false,
            "result_outcome": "unverified",
            "evidence_counts": {}
        })
    };
    let fault_client = |client: &str, version: &str| {
        let normalized = summary["case_results"][client]["adapter_faults"]
            .as_array()
            .expect("normalized faults");
        let case_order: &[&str] = if client == "claude" {
            &[
                "T05-D", "T05-E", "T05-F", "T05-G", "T05-I", "T05-J", "T05-K",
            ]
        } else {
            &[
                "T05-D",
                "T05-E",
                "T05-F",
                "T05-G",
                "T05-I",
                "T05-J",
                "T05-K",
                "T05-H-Codex",
            ]
        };
        let observations = case_order
            .iter()
            .map(|case_id| {
                let fault = normalized
                    .iter()
                    .find(|fault| fault["case_id"] == **case_id)
                    .expect("normalized fault case");
                json!({
                    "case_id": fault["case_id"],
                    "target_marker_exists": fault["target_marker_exists"],
                    "target_process_started": null,
                    "target_process_observer": "unavailable_not_instrumented",
                    "approval_boundary": "unverified_noninteractive_bypass_mode_no_operator_approval",
                    "protection_claim": false
                })
            })
            .collect::<Vec<_>>();
        json!({
            "executable": format!("/pinned/{client}"),
            "version": version,
            "control": {},
            "observations": observations
        })
    };
    let adapter_faults = json!({
        "schema_version": "m0-adapter-fault-observations/v1",
        "run_root": "/ephemeral",
        "host": {
            "platform": "darwin",
            "architecture": "arm64",
            "node_version": "v26.5.0"
        },
        "network": {},
        "approval_boundary": "unverified_noninteractive_bypass_mode_no_operator_approval",
        "interpretation": "no protection claim",
        "observational_failures": [],
        "unsupported_or_unverified": [],
        "clients": {
            "claude": fault_client("claude", "2.1.220 (Claude Code)"),
            "codex": fault_client("codex", "codex-cli 0.146.0")
        }
    });
    let prompt_continuation = json!({
        "schema_version": "m0-prompt-observations/v1",
        "run_root": "/ephemeral",
        "human_prompt": "SECURE_ONBOARD_HUMAN_PROMPT",
        "codex_stop_block_response": {
            "decision": "block",
            "reason": "M0_CONTINUATION"
        },
        "child_timeout_ms": 30000,
        "kernel_network_confinement": "unavailable_sandbox_exec_operation_not_permitted",
        "claude": {
            "version": "2.1.220 (Claude Code)",
            "prompt_observations": [{
                "payload": {
                    "hook_event_name": "UserPromptSubmit",
                    "prompt": "SECURE_ONBOARD_HUMAN_PROMPT\n"
                },
                "source_assurance": "unverified"
            }]
        },
        "codex": {
            "version": "codex-cli 0.146.0",
            "prompt_observations": [{
                "payload": {"hook_event_name": "UserPromptSubmit"},
                "observed_origin": "initial_human_submission",
                "source_assurance": "unverified"
            }],
            "automatic_continuation": {
                "local_api_input": "<hook_prompt id=\"1\">M0_CONTINUATION</hook_prompt>",
                "user_prompt_submit_observed": false,
                "source_assurance": "unverified"
            },
            "stop_observations": [
                {"payload": {"stop_hook_active": false}},
                {"payload": {"stop_hook_active": true}}
            ],
            "prompt_and_stop_turn_ids_equal": true,
            "stop_turn_ids_equal": true
        }
    });
    [
        claude_live,
        codex_source("high_pre_tool", json!(true)),
        codex_source("result_failure", json!(null)),
        adapter_faults,
        prompt_continuation,
    ]
}

#[test]
fn raw_harness_ingestion_checks_bytes_and_derives_normalized_case_results() {
    let mut summary = from_slice::<Value>(&fs::read(HARNESS_SUMMARY).expect("harness summary"))
        .expect("strict harness summary");
    let sources = synthetic_harness_sources(&summary);
    let bytes = sources
        .iter()
        .map(|source| serde_json::to_vec(source).expect("synthetic source"))
        .collect::<Vec<_>>();
    for (run, source) in [
        ("claude_live", &bytes[0]),
        ("codex_high", &bytes[1]),
        ("codex_result_failure", &bytes[2]),
        ("adapter_faults", &bytes[3]),
        ("prompt_continuation", &bytes[4]),
    ] {
        bind_source(&mut summary, run, source);
    }
    let summary_bytes = serde_json::to_vec(&summary).expect("synthetic harness summary");
    validate_harness_source_outputs(
        &summary_bytes,
        HarnessSourceOutputs {
            claude_live: &bytes[0],
            codex_high: &bytes[1],
            codex_result_failure: &bytes[2],
            adapter_faults: &bytes[3],
            prompt_continuation: &bytes[4],
        },
    )
    .expect("valid raw source bindings");

    let mut tampered = sources[0].clone();
    tampered["results"][1]["marker_exists"] = json!(false);
    let tampered = serde_json::to_vec(&tampered).expect("tampered source");
    bind_source(&mut summary, "claude_live", &tampered);
    assert!(matches!(
        validate_harness_source_outputs(
            &serde_json::to_vec(&summary).expect("tampered harness summary"),
            HarnessSourceOutputs {
                claude_live: &tampered,
                codex_high: &bytes[1],
                codex_result_failure: &bytes[2],
                adapter_faults: &bytes[3],
                prompt_continuation: &bytes[4],
            },
        ),
        Err(ObservationMatrixError::SourceOutput(_))
    ));

    let mut wrong_client = sources[0].clone();
    wrong_client["environment_binding"]["client_sha256"] =
        json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    let wrong_client = serde_json::to_vec(&wrong_client).expect("wrong client source");
    bind_source(&mut summary, "claude_live", &wrong_client);
    assert!(matches!(
        validate_harness_source_outputs(
            &serde_json::to_vec(&summary).expect("wrong client harness summary"),
            HarnessSourceOutputs {
                claude_live: &wrong_client,
                codex_high: &bytes[1],
                codex_result_failure: &bytes[2],
                adapter_faults: &bytes[3],
                prompt_continuation: &bytes[4],
            },
        ),
        Err(ObservationMatrixError::SourceOutput(_))
    ));

    let mut wrong_product = sources[1].clone();
    wrong_product["product_artifacts"]["hook_sha256"] =
        json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    let wrong_product = serde_json::to_vec(&wrong_product).expect("wrong product source");
    bind_source(&mut summary, "codex_high", &wrong_product);
    assert!(matches!(
        validate_harness_source_outputs(
            &serde_json::to_vec(&summary).expect("wrong product harness summary"),
            HarnessSourceOutputs {
                claude_live: &bytes[0],
                codex_high: &wrong_product,
                codex_result_failure: &bytes[2],
                adapter_faults: &bytes[3],
                prompt_continuation: &bytes[4],
            },
        ),
        Err(ObservationMatrixError::SourceOutput(_))
    ));

    let oversized =
        vec![b' '; usize::try_from(MAX_HARNESS_SOURCE_OUTPUT_BYTES + 1).expect("source limit")];
    bind_source(&mut summary, "claude_live", &oversized);
    assert!(matches!(
        validate_harness_source_outputs(
            &serde_json::to_vec(&summary).expect("oversized harness summary"),
            HarnessSourceOutputs {
                claude_live: &oversized,
                codex_high: &bytes[1],
                codex_result_failure: &bytes[2],
                adapter_faults: &bytes[3],
                prompt_continuation: &bytes[4],
            },
        ),
        Err(ObservationMatrixError::SourceOutput(_))
    ));
}

#[test]
#[ignore = "requires five final native harness summary paths"]
fn final_native_harness_outputs_are_ingested_before_their_digests_are_trusted() {
    let read_source = |name: &str| {
        let path = std::env::var_os(name)
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| panic!("missing {name}"));
        let file = fs::File::open(&path)
            .unwrap_or_else(|error| panic!("open {}: {error}", path.display()));
        let mut bytes = Vec::new();
        file.take(MAX_HARNESS_SOURCE_OUTPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert!(
            u64::try_from(bytes.len()).expect("source size") <= MAX_HARNESS_SOURCE_OUTPUT_BYTES,
            "{} exceeds the source output limit",
            path.display()
        );
        bytes
    };
    let claude_live = read_source("M0_CLAUDE_LIVE_SUMMARY");
    let codex_high = read_source("M0_CODEX_HIGH_SUMMARY");
    let codex_result_failure = read_source("M0_CODEX_RESULT_FAILURE_SUMMARY");
    let adapter_faults = read_source("M0_ADAPTER_FAULTS_SUMMARY");
    let prompt_continuation = read_source("M0_PROMPT_CONTINUATION_SUMMARY");

    validate_harness_source_outputs(
        &fs::read(HARNESS_SUMMARY).expect("checked harness summary"),
        HarnessSourceOutputs {
            claude_live: &claude_live,
            codex_high: &codex_high,
            codex_result_failure: &codex_result_failure,
            adapter_faults: &adapter_faults,
            prompt_continuation: &prompt_continuation,
        },
    )
    .expect("raw native summaries bind to the normalized checked result");
    validate_observation_matrix(&matrix_bytes(), repository_root())
        .expect("checked observation matrix also binds final artifacts and manifests");
}

#[test]
fn matrix_and_nested_documents_deny_unknown_missing_duplicate_and_reordered_shape() {
    let value = matrix_value();
    assert!(validate(&value));

    let mut top_unknown = value.clone();
    top_unknown
        .as_object_mut()
        .expect("matrix object")
        .insert("unexpected".into(), Value::Bool(true));
    assert!(!validate(&top_unknown));

    let mut nested_unknown = value.clone();
    nested_unknown["cases"][0]["claude"]
        .as_object_mut()
        .expect("observation")
        .insert("unexpected".into(), Value::Bool(true));
    assert!(!validate(&nested_unknown));

    let mut missing_nullable_selector = value.clone();
    missing_nullable_selector["evidence_catalog"][0]
        .as_object_mut()
        .expect("evidence entry")
        .remove("selector");
    assert!(!validate(&missing_nullable_selector));

    let duplicate_key = br#"{"schema_version":"m0-observation-matrix/v1","schema_version":"m0-observation-matrix/v1"}"#;
    assert!(
        validate_observation_matrix(duplicate_key, Path::new(env!("CARGO_MANIFEST_DIR"))).is_err()
    );

    let mut missing_case = value.clone();
    missing_case["cases"].as_array_mut().expect("cases").pop();
    assert!(!validate(&missing_case));

    let mut reordered = value;
    reordered["cases"].as_array_mut().expect("cases").swap(0, 1);
    assert!(!validate(&reordered));
}

#[test]
fn status_coverage_and_evidence_kind_invariants_reject_false_claims() {
    let value = matrix_value();
    assert!(validate(&value));

    let mut false_inclusion = value.clone();
    false_inclusion["cases"][0]["claude"]["status"] = json!("verified");
    false_inclusion["cases"][0]["claude"]["coverage_effect"] = json!("included");
    assert!(!validate(&false_inclusion));

    let mut mismatched_pair = value.clone();
    mismatched_pair["cases"][0]["claude"]["coverage_effect"] = json!("not_applicable");
    assert!(!validate(&mismatched_pair));

    let mut probe_is_not_result = value.clone();
    probe_is_not_result["cases"][22]["claude"]["status"] = json!("observed_unsupported");
    assert_eq!(probe_is_not_result["cases"][22]["case_id"], "T09");
    assert!(!validate(&probe_is_not_result));

    let mut result_is_not_contract = value.clone();
    assert_eq!(result_is_not_contract["cases"][7]["case_id"], "T05-D");
    result_is_not_contract["cases"][7]["claude"]["status"] = json!("contract_only");
    assert!(!validate(&result_is_not_contract));

    let mut contract_only_cannot_mix_result_evidence = value.clone();
    contract_only_cannot_mix_result_evidence["cases"][0]["claude"]["evidence_ids"] = json!([
        "contract-core-high",
        "contract-native-responses",
        "observation-claude-faults"
    ]);
    assert!(!validate(&contract_only_cannot_mix_result_evidence));

    let mut unverified_needs_a_matching_probe_or_result = value.clone();
    assert_eq!(
        unverified_needs_a_matching_probe_or_result["cases"][7]["case_id"],
        "T05-D"
    );
    unverified_needs_a_matching_probe_or_result["cases"][7]["claude"]["evidence_ids"] =
        json!(["contract-core-high"]);
    assert!(!validate(&unverified_needs_a_matching_probe_or_result));

    let mut wrong_result_client_and_case = value;
    assert_eq!(wrong_result_client_and_case["cases"][1]["case_id"], "T02");
    wrong_result_client_and_case["cases"][1]["codex"]["evidence_ids"] =
        json!(["observation-claude-faults"]);
    assert!(!validate(&wrong_result_client_and_case));
}

#[test]
fn catalog_rejects_bad_digest_selector_duplicate_ids_and_unreferenced_entries() {
    let value = matrix_value();
    assert!(validate(&value));

    let mut bad_digest = value.clone();
    bad_digest["evidence_catalog"][0]["content_sha256"] =
        json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    assert!(!validate(&bad_digest));

    let mut bad_selector = value.clone();
    bad_selector["evidence_catalog"][0]["selector"] = json!("not_a_test");
    assert!(!validate(&bad_selector));

    let mut duplicate_id = value.clone();
    duplicate_id["evidence_catalog"][1]["evidence_id"] =
        duplicate_id["evidence_catalog"][0]["evidence_id"].clone();
    assert!(!validate(&duplicate_id));

    let mut unreferenced = value;
    let mut extra = unreferenced["evidence_catalog"][0].clone();
    extra["evidence_id"] = json!("zz-unreferenced");
    extra["selector"] = json!("low_and_info_continue_without_inventing_a_result_event");
    unreferenced["evidence_catalog"]
        .as_array_mut()
        .expect("catalog")
        .push(extra);
    assert!(!validate(&unreferenced));
}

#[test]
fn observation_result_unknown_fields_fail_even_with_a_matching_digest() {
    let temporary = repository_temporary_directory();
    let bad_observation =
        br#"{"schema_version":"m0-native-observation-result/v1","unexpected":true}"#;
    let bad_path = temporary.path().join("bad.json");
    fs::write(&bad_path, bad_observation).expect("bad observation");

    let mut value = matrix_value();
    assert!(validate(&value));
    value["evidence_catalog"][0]["kind"] = json!("observation_result");
    value["evidence_catalog"][0]["relative_path"] = json!(repository_relative(&bad_path));
    value["evidence_catalog"][0]["content_sha256"] = json!(digest(bad_observation));
    value["evidence_catalog"][0]["selector"] = json!("/claims/x");
    assert!(!validate(&value));
}

#[test]
fn static_manifest_requires_the_full_fixture_manifest_contract() {
    let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/m0");
    let temporary = TempDir::new_in(&fixture_root).expect("temporary fixture directory");
    let schema_version_only = br#"{"architecture":"arm64","client":"claude","client_version":"2.1.220","os":"macos","schema_version":"m0-fixture-manifest/v1"}
"#;
    let fake_manifest = temporary.path().join("fake-manifest.json");
    fs::write(&fake_manifest, schema_version_only).expect("fake manifest");

    let mut value = matrix_value();
    assert!(validate(&value));
    value["evidence_catalog"][0]["kind"] = json!("static_manifest");
    value["evidence_catalog"][0]["relative_path"] = json!(repository_relative(&fake_manifest));
    value["evidence_catalog"][0]["content_sha256"] = json!(digest(schema_version_only));
    value["evidence_catalog"][0]["selector"] = Value::Null;
    assert!(!validate(&value));
}

#[test]
fn evidence_paths_are_repository_relative_regular_and_non_symlinked() {
    let value = matrix_value();
    assert!(validate(&value));

    let mut absolute = value.clone();
    absolute["evidence_catalog"][0]["relative_path"] = json!("/private/tmp/evidence.json");
    assert!(!validate(&absolute));

    let mut traversal = value.clone();
    traversal["evidence_catalog"][0]["relative_path"] = json!("../evidence.json");
    assert!(!validate(&traversal));

    let relative_root = Path::new(".");
    assert!(validate_observation_matrix(&matrix_bytes(), relative_root).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let temporary = repository_temporary_directory();
        let target = temporary.path().join("target.json");
        fs::write(&target, b"{}").expect("target");
        let link = temporary.path().join("link.json");
        symlink(&target, &link).expect("symlink");

        let mut symlinked = value;
        symlinked["evidence_catalog"][0]["kind"] = json!("native_fixture");
        symlinked["evidence_catalog"][0]["relative_path"] = json!(repository_relative(&link));
        symlinked["evidence_catalog"][0]["content_sha256"] = json!(digest(b"{}"));
        symlinked["evidence_catalog"][0]["selector"] = Value::Null;
        assert!(!validate(&symlinked));
    }
}
