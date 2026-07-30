#![cfg(feature = "m0-test-profile")]

use secure_onboard::adapter_runtime::{CoreChild, CoreFault};
use secure_onboard::m0::{Client, DecisionSource, GateDecision, M0EventType, Severity};
use secure_onboard::m0_adapter::{
    AdapterConfig, CorrelationStore, ResultConfig, SentinelBinding, handle_pre_tool_use,
    handle_tool_result, prepare_pre_outcome,
};
use secure_onboard::native::CwdBinding;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::TempDir;

struct Fixture {
    _root: TempDir,
    trusted_root: PathBuf,
    target_root: PathBuf,
    profile_path: PathBuf,
    helper_path: PathBuf,
    marker_root: PathBuf,
    profile_digest: String,
    runtime_version: String,
    shell_fingerprint: String,
    state_root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("temp root");
        let physical = root.path().canonicalize().expect("physical root");
        let trusted_root = physical.join("user-area");
        let target_root = physical.join("target");
        let runtime = trusted_root.join("bin/node");
        let shell = trusted_root.join("bin/zsh");
        let helper_path = trusted_root.join("helpers/m0-target.mjs");
        let failure_helper = trusted_root.join("helpers/m0-target-fail.mjs");
        let marker_root = trusted_root.join("markers");
        let profile_path = trusted_root.join("profiles/claude.json");
        let state_root = trusted_root.join("state");
        for directory in [
            runtime.parent().unwrap(),
            helper_path.parent().unwrap(),
            &marker_root,
            profile_path.parent().unwrap(),
            &state_root,
            &target_root,
        ] {
            fs::create_dir_all(directory).unwrap();
            set_private_directory(directory);
        }
        set_private_directory(&trusted_root);
        fs::write(&runtime, b"runtime").unwrap();
        fs::write(&shell, b"shell").unwrap();
        fs::write(&helper_path, b"helper").unwrap();
        fs::write(&failure_helper, b"failure-helper").unwrap();
        set_file_mode(&runtime, 0o700);
        set_file_mode(&shell, 0o700);
        set_file_mode(&helper_path, 0o600);
        set_file_mode(&failure_helper, 0o600);
        let shell_fingerprint = digest(b"shell-probe");
        let profile = json!({
            "schema_version": "m0-test-profile/v1",
            "build_flavor": "test",
            "client": "claude",
            "client_version": "2.1.220",
            "os": "macos",
            "architecture": "arm64",
            "fixture_runtime": {
                "executable_path": runtime,
                "executable_sha256": digest(b"runtime"),
                "version_output": "vfixture"
            },
            "shell_binding": {
                "executable_path": shell,
                "executable_sha256": digest(b"shell"),
                "flags": ["-lc"],
                "dialect": "posix_sh",
                "resolution_fingerprint": shell_fingerprint
            },
            "helpers": [
                {
                    "role": "default",
                    "relative_path": "helpers/m0-target.mjs",
                    "content_sha256": digest(b"helper"),
                    "command_grammar": "posix_ascii_argv4/v1",
                    "allowed_sentinels": ["high", "low", "info"]
                },
                {
                    "role": "failure",
                    "relative_path": "helpers/m0-target-fail.mjs",
                    "content_sha256": digest(b"failure-helper"),
                    "command_grammar": "posix_ascii_argv4/v1",
                    "allowed_sentinels": ["low", "info"]
                }
            ],
            "marker_root_relative": "markers"
        });
        let mut profile_bytes = serde_json::to_vec_pretty(&profile).unwrap();
        profile_bytes.push(b'\n');
        fs::write(&profile_path, &profile_bytes).unwrap();
        set_file_mode(&profile_path, 0o600);

        Self {
            _root: root,
            trusted_root,
            target_root,
            profile_path,
            helper_path,
            marker_root,
            profile_digest: digest(&profile_bytes),
            runtime_version: "vfixture".into(),
            shell_fingerprint,
            state_root,
        }
    }

    fn command(&self, sentinel: &str, case_id: &str) -> String {
        format!(
            "{} {} {sentinel} {}",
            self.trusted_root.join("bin/node").display(),
            self.helper_path.display(),
            self.marker_root
                .join("run-01")
                .join(format!("{case_id}.marker"))
                .display()
        )
    }

    fn native_pre(&self, command: &str, tool_id: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "session_id": "session-01",
            "transcript_path": "/private/tmp/transcript.jsonl",
            "cwd": self.target_root,
            "prompt_id": "prompt-01",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": tool_id
        }))
        .unwrap()
    }

    fn config(&self, case_id: &str, fault: CoreFault) -> AdapterConfig {
        AdapterConfig {
            client: Client::Claude,
            profile_path: self.profile_path.clone(),
            expected_profile_digest: self.profile_digest.clone(),
            trusted_source_root: self.trusted_root.clone(),
            target_project_root: self.target_root.clone(),
            observed_runtime_version_output: self.runtime_version.clone(),
            observed_shell_resolution_fingerprint: self.shell_fingerprint.clone(),
            cwd_binding: CwdBinding::VerifiedSimpleInvocation,
            test_case_id: case_id.into(),
            test_run_id: "run-01".into(),
            action_id: format!("action-{case_id}"),
            envelope_id: format!("envelope-{case_id}"),
            decision_id: format!("decision-{case_id}"),
            event_ids: [format!("event-{case_id}-1"), format!("event-{case_id}-2")],
            observed_at: "2026-07-22T00:00:00Z".into(),
            core: CoreChild {
                executable: PathBuf::from(env!("CARGO_BIN_EXE_secure-onboard-m0-core")),
                working_directory: self.trusted_root.clone(),
                timeout: Duration::from_secs(1),
                fault,
            },
        }
    }

    fn store(&self) -> CorrelationStore {
        CorrelationStore::new(self.state_root.clone()).expect("state root")
    }
}

fn set_private_directory(path: &std::path::Path) {
    set_file_mode(path, 0o700);
}

fn set_file_mode(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[test]
fn exact_high_command_crosses_native_profile_core_and_deny_boundaries() {
    let fixture = Fixture::new();
    let command = fixture.command("high", "T01");
    let outcome = handle_pre_tool_use(
        &fixture.native_pre(&command, "tool-high"),
        &fixture.config("T01", CoreFault::None),
    )
    .expect("adapter outcome");

    assert_eq!(outcome.binding, SentinelBinding::Matched);
    assert_eq!(
        outcome.request.as_ref().unwrap().invocation.command_text(),
        command
    );
    assert_eq!(outcome.decision.as_ref().unwrap().severity, Severity::High);
    assert_eq!(
        outcome.decision.as_ref().unwrap().gate_decision,
        GateDecision::Deny
    );
    assert_eq!(
        outcome
            .events
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        [M0EventType::HighDetected, M0EventType::HighBlocked]
    );
    assert!(
        std::str::from_utf8(&outcome.native_response)
            .unwrap()
            .contains("\"permissionDecision\":\"deny\"")
    );
    assert!(!fixture.marker_root.join("run-01/T01.marker").exists());
}

#[test]
fn low_warning_then_failure_result_keeps_one_native_tool_correlation() {
    let fixture = Fixture::new();
    let command = fixture.command("low", "T03");
    let store = fixture.store();
    let pre = handle_pre_tool_use(
        &fixture.native_pre(&command, "tool-low"),
        &fixture.config("T03", CoreFault::None),
    )
    .expect("pre outcome");
    assert_eq!(pre.binding, SentinelBinding::Matched);
    assert_eq!(pre.events[0].event_type, M0EventType::WarnedLow);
    assert_eq!(
        pre.decision.as_ref().unwrap().decision_source,
        DecisionSource::Core
    );
    prepare_pre_outcome(&pre, &store)
        .expect("prepare LOW decision")
        .expect("LOW has correlation state")
        .mark_delivered()
        .expect("deliver LOW decision");

    let result_bytes = serde_json::to_vec(&json!({
        "session_id": "session-01",
        "transcript_path": "/private/tmp/transcript.jsonl",
        "cwd": fixture.target_root,
        "prompt_id": "prompt-01",
        "permission_mode": "default",
        "hook_event_name": "PostToolUseFailure",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": "tool-low",
        "error": "fixture exit 23",
        "is_interrupt": false,
        "duration_ms": 1
    }))
    .unwrap();
    let result = handle_tool_result(
        &result_bytes,
        &ResultConfig {
            client: Client::Claude,
            envelope_id: "envelope-result".into(),
            observed_at: "2026-07-22T00:00:01Z".into(),
            event_id: "event-result".into(),
            cwd_binding: CwdBinding::VerifiedSimpleInvocation,
        },
        &store,
    )
    .expect("result outcome");
    assert_eq!(
        result.event.as_ref().unwrap().event_type,
        M0EventType::ToolFailed
    );
    assert_eq!(
        result.event.as_ref().unwrap().native_tool_call_id,
        "tool-low"
    );
    assert_eq!(result.native_response, b"{}\n");
}

#[test]
fn prepared_correlation_is_invisible_to_results_until_delivery() {
    let fixture = Fixture::new();
    let command = fixture.command("low", "T03-PREPARED");
    let store = fixture.store();
    let pre = handle_pre_tool_use(
        &fixture.native_pre(&command, "tool-prepared"),
        &fixture.config("T03-PREPARED", CoreFault::None),
    )
    .expect("pre outcome");
    let preparation = prepare_pre_outcome(&pre, &store)
        .expect("prepare correlation")
        .expect("LOW has correlation state");
    let result_bytes = serde_json::to_vec(&json!({
        "session_id": "session-01",
        "transcript_path": "/private/tmp/transcript.jsonl",
        "cwd": fixture.target_root,
        "prompt_id": "prompt-01",
        "permission_mode": "default",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_response": {"stdout": "", "stderr": ""},
        "tool_use_id": "tool-prepared",
        "duration_ms": 1
    }))
    .unwrap();
    let result_config = ResultConfig {
        client: Client::Claude,
        envelope_id: "envelope-prepared-result".into(),
        observed_at: "2026-07-22T00:00:01Z".into(),
        event_id: "event-prepared-result".into(),
        cwd_binding: CwdBinding::VerifiedSimpleInvocation,
    };

    let before_delivery =
        handle_tool_result(&result_bytes, &result_config, &store).expect("prepared result");
    assert!(before_delivery.event.is_none());

    preparation
        .mark_delivered()
        .expect("mark correlation delivered");
    let after_delivery =
        handle_tool_result(&result_bytes, &result_config, &store).expect("delivered result");
    assert_eq!(
        after_delivery.event.expect("completion event").event_type,
        M0EventType::ToolCompleted
    );
}

#[test]
fn failed_duplicate_cannot_roll_back_another_delivery() {
    let fixture = Fixture::new();
    let command = fixture.command("info", "T04-DUPLICATE");
    let store = fixture.store();
    let pre = handle_pre_tool_use(
        &fixture.native_pre(&command, "tool-duplicate"),
        &fixture.config("T04-DUPLICATE", CoreFault::None),
    )
    .expect("pre outcome");
    let first = prepare_pre_outcome(&pre, &store)
        .expect("first prepare")
        .expect("INFO has correlation state");
    let second = prepare_pre_outcome(&pre, &store)
        .expect("duplicate prepare")
        .expect("duplicate has correlation state");
    second.mark_delivered().expect("duplicate delivery");
    drop(first);

    let result_bytes = serde_json::to_vec(&json!({
        "session_id": "session-01",
        "transcript_path": "/private/tmp/transcript.jsonl",
        "cwd": fixture.target_root,
        "prompt_id": "prompt-01",
        "permission_mode": "default",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_response": {"stdout": "", "stderr": ""},
        "tool_use_id": "tool-duplicate",
        "duration_ms": 1
    }))
    .unwrap();
    let result = handle_tool_result(
        &result_bytes,
        &ResultConfig {
            client: Client::Claude,
            envelope_id: "envelope-duplicate-result".into(),
            observed_at: "2026-07-22T00:00:01Z".into(),
            event_id: "event-duplicate-result".into(),
            cwd_binding: CwdBinding::VerifiedSimpleInvocation,
        },
        &store,
    )
    .expect("delivered duplicate result");

    assert_eq!(
        result.event.expect("completion event").event_type,
        M0EventType::ToolCompleted
    );
}

#[test]
fn parallel_pre_calls_keep_out_of_order_results_on_their_native_tool_ids() {
    let fixture = Fixture::new();
    let store = fixture.store();
    let low_command = fixture.command("low", "T07-LOW");
    let info_command = fixture.command("info", "T07-INFO");
    let low_native = fixture.native_pre(&low_command, "tool-parallel-low");
    let info_native = fixture.native_pre(&info_command, "tool-parallel-info");
    let low_config = fixture.config("T07-LOW", CoreFault::None);
    let info_config = fixture.config("T07-INFO", CoreFault::None);

    let (low, info) = std::thread::scope(|scope| {
        let low = scope.spawn(|| handle_pre_tool_use(&low_native, &low_config));
        let info = scope.spawn(|| handle_pre_tool_use(&info_native, &info_config));
        (
            low.join().expect("low thread").expect("low pre outcome"),
            info.join().expect("info thread").expect("info pre outcome"),
        )
    });
    assert_eq!(low.events[0].event_type, M0EventType::WarnedLow);
    assert_eq!(info.events[0].event_type, M0EventType::AllowedInfo);
    prepare_pre_outcome(&low, &store)
        .expect("prepare LOW decision")
        .expect("LOW has correlation state")
        .mark_delivered()
        .expect("deliver LOW decision");
    prepare_pre_outcome(&info, &store)
        .expect("prepare INFO decision")
        .expect("INFO has correlation state")
        .mark_delivered()
        .expect("deliver INFO decision");

    let info_result = serde_json::to_vec(&json!({
        "session_id": "session-01",
        "transcript_path": "/private/tmp/transcript.jsonl",
        "cwd": fixture.target_root,
        "prompt_id": "prompt-01",
        "permission_mode": "default",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": info_command},
        "tool_response": {"stdout": "", "stderr": ""},
        "tool_use_id": "tool-parallel-info",
        "duration_ms": 1
    }))
    .unwrap();
    let low_result = serde_json::to_vec(&json!({
        "session_id": "session-01",
        "transcript_path": "/private/tmp/transcript.jsonl",
        "cwd": fixture.target_root,
        "prompt_id": "prompt-01",
        "permission_mode": "default",
        "hook_event_name": "PostToolUseFailure",
        "tool_name": "Bash",
        "tool_input": {"command": low_command},
        "tool_use_id": "tool-parallel-low",
        "error": "fixture exit 23",
        "is_interrupt": false,
        "duration_ms": 1
    }))
    .unwrap();

    let info = handle_tool_result(
        &info_result,
        &ResultConfig {
            client: Client::Claude,
            envelope_id: "envelope-info-result".into(),
            observed_at: "2026-07-22T00:00:02Z".into(),
            event_id: "event-info-result".into(),
            cwd_binding: CwdBinding::VerifiedSimpleInvocation,
        },
        &store,
    )
    .expect("info result");
    let low = handle_tool_result(
        &low_result,
        &ResultConfig {
            client: Client::Claude,
            envelope_id: "envelope-low-result".into(),
            observed_at: "2026-07-22T00:00:03Z".into(),
            event_id: "event-low-result".into(),
            cwd_binding: CwdBinding::VerifiedSimpleInvocation,
        },
        &store,
    )
    .expect("low result");

    let info = info.event.expect("info completion event");
    let low = low.event.expect("low failure event");
    assert_eq!(info.event_type, M0EventType::ToolCompleted);
    assert_eq!(info.native_tool_call_id, "tool-parallel-info");
    assert_eq!(low.event_type, M0EventType::ToolFailed);
    assert_eq!(low.native_tool_call_id, "tool-parallel-low");
}

#[test]
fn helper_or_argv_near_match_is_neutral_and_never_reaches_core() {
    let fixture = Fixture::new();
    let command = format!("{} noop", fixture.command("info", "T19-B-ARGV"));
    let outcome = handle_pre_tool_use(
        &fixture.native_pre(&command, "tool-near"),
        &fixture.config("T19-B-ARGV", CoreFault::None),
    )
    .expect("neutral mismatch");
    assert_eq!(outcome.binding, SentinelBinding::ArgvMismatch);
    assert!(outcome.request.is_none());
    assert!(outcome.decision.is_none());
    assert!(outcome.events.is_empty());
    assert_eq!(outcome.native_response, b"{}\n");

    let result_bytes = serde_json::to_vec(&json!({
        "session_id": "session-01",
        "transcript_path": "/private/tmp/transcript.jsonl",
        "cwd": fixture.target_root,
        "prompt_id": "prompt-01",
        "permission_mode": "default",
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_response": {"stdout": "", "stderr": ""},
        "tool_use_id": "tool-near",
        "duration_ms": 1
    }))
    .unwrap();
    let result = handle_tool_result(
        &result_bytes,
        &ResultConfig {
            client: Client::Claude,
            envelope_id: "envelope-near-result".into(),
            observed_at: "2026-07-22T00:00:01Z".into(),
            event_id: "event-near-result".into(),
            cwd_binding: CwdBinding::VerifiedSimpleInvocation,
        },
        &fixture.store(),
    )
    .expect("unmatched result is neutral");
    assert!(result.event.is_none());
    assert_eq!(result.native_response, b"{}\n");
}

#[test]
fn observed_core_failures_become_high_but_core_spawn_failure_does_not() {
    let fixture = Fixture::new();
    for fault in [
        CoreFault::Timeout,
        CoreFault::Nonzero,
        CoreFault::SchemaInvalid,
    ] {
        let outcome = handle_pre_tool_use(
            &fixture.native_pre(&fixture.command("info", "T05"), "tool-fault"),
            &fixture.config("T05", fault),
        )
        .expect("fallback");
        let decision = outcome.decision.unwrap();
        assert_eq!(decision.severity, Severity::High);
        assert_eq!(decision.decision_source, DecisionSource::AdapterFallback);
        assert!(decision.failure_code.is_some());
    }

    let mut config = fixture.config("T05-D", CoreFault::None);
    config.core.executable = PathBuf::from("/private/tmp/missing-secure-onboard-core");
    assert!(
        handle_pre_tool_use(
            &fixture.native_pre(&fixture.command("info", "T05-D"), "tool-spawn"),
            &config,
        )
        .is_err()
    );
}
