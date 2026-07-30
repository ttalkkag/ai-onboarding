#![cfg(feature = "m0-test-profile")]

use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    _root: TempDir,
    trusted_root: PathBuf,
    target_root: PathBuf,
    state_root: PathBuf,
    evidence_root: PathBuf,
    profile_path: PathBuf,
    marker_root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create fixture root");
        let physical_root = root.path().canonicalize().expect("canonical fixture root");
        set_private_directory(&physical_root);

        let trusted_root = physical_root.join("trusted");
        let target_root = physical_root.join("target");
        let state_root = physical_root.join("state");
        let evidence_root = physical_root.join("evidence");
        let profile_path = trusted_root.join("profiles/claude.json");
        let marker_root = trusted_root.join("markers");
        for directory in [
            &trusted_root,
            &target_root,
            &state_root,
            &evidence_root,
            &trusted_root.join("helpers"),
            profile_path.parent().expect("profile parent"),
            &marker_root,
        ] {
            create_private_directory(directory);
        }

        write_private_file(
            &trusted_root.join("helpers/m0-target.mjs"),
            include_bytes!("fixtures/m0/helpers/m0-target.mjs"),
        );
        write_private_file(
            &trusted_root.join("helpers/m0-target-fail.mjs"),
            include_bytes!("fixtures/m0/helpers/m0-target-fail.mjs"),
        );
        write_private_file(
            &profile_path,
            include_bytes!("fixtures/m0/profiles/claude-2.1.220-macos-arm64.json"),
        );

        Self {
            _root: root,
            trusted_root,
            target_root,
            state_root,
            evidence_root,
            profile_path,
            marker_root,
        }
    }

    fn native_pre(
        &self,
        command_text: &str,
        session_id: &str,
        prompt_id: &str,
        tool_use_id: &str,
    ) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "session_id": session_id,
            "transcript_path": self.target_root.join("m0-transcript.jsonl"),
            "cwd": self.target_root,
            "prompt_id": prompt_id,
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command_text},
            "tool_use_id": tool_use_id
        }))
        .expect("native payload")
    }

    fn pre_arguments(
        &self,
        test_case_id: &str,
        test_run_id: &str,
        id_prefix: &str,
        id_binding: Option<&str>,
    ) -> Vec<String> {
        let mut arguments = vec![
            "--client".into(),
            "claude".into(),
            "--profile".into(),
            path_string(&self.profile_path),
            "--trusted-root".into(),
            path_string(&self.trusted_root),
            "--target-root".into(),
            path_string(&self.target_root),
            "--state-root".into(),
            path_string(&self.state_root),
            "--evidence-root".into(),
            path_string(&self.evidence_root),
            "--test-case".into(),
            test_case_id.into(),
            "--test-run".into(),
            test_run_id.into(),
            "--action-id".into(),
            format!("action-{id_prefix}"),
            "--envelope-id".into(),
            format!("envelope-{id_prefix}"),
            "--decision-id".into(),
            format!("decision-{id_prefix}"),
            "--event-id-1".into(),
            format!("event-{id_prefix}-1"),
            "--event-id-2".into(),
            format!("event-{id_prefix}-2"),
            "--observed-at".into(),
            "2026-07-22T00:00:00Z".into(),
            "--core-timeout-ms".into(),
            "1000".into(),
            "--core-fault".into(),
            "none".into(),
            "--cwd-binding".into(),
            "verified-simple".into(),
        ];
        if let Some(id_binding) = id_binding {
            arguments.extend(["--id-binding".into(), id_binding.into()]);
        }
        arguments
    }
}

fn create_private_directory(path: &Path) {
    fs::create_dir_all(path).expect("create private fixture directory");
    set_private_directory(path);
}

fn set_private_directory(path: &Path) {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("set private directory permissions");
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write private fixture file");
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("set private file permissions");
}

fn path_string(path: &Path) -> String {
    path.to_str().expect("fixture path is UTF-8").to_owned()
}

#[cfg(unix)]
fn assert_mode(path: &Path, expected: u32) {
    let actual = fs::symlink_metadata(path)
        .expect("private path metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(actual, expected, "unexpected mode for {}", path.display());
}

fn run_hook(mode: &str, arguments: &[String], input: &[u8]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_secure-onboard-m0-hook"));
    command
        .arg(mode)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn hook");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input)
        .expect("write native payload");
    child.wait_with_output().expect("hook output")
}

fn run_hook_with_closed_stdout(
    mode: &str,
    arguments: &[String],
    input: &[u8],
) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_secure-onboard-m0-hook"));
    command
        .arg(mode)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn hook");
    drop(child.stdout.take().expect("child stdout"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input)
        .expect("write native payload");
    child.wait_with_output().expect("hook output")
}

#[test]
fn pre_tool_internal_failure_still_returns_a_valid_high_deny() {
    let output = run_hook(
        "pre",
        &["--client".to_owned(), "claude".to_owned()],
        b"{}\n",
    );
    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(
        output.stdout,
        b"{\"systemMessage\":\"Secure Onboard M0: adapter failure blocked the action.\",\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"Secure Onboard M0 adapter failure\"}}\n"
    );
    assert_eq!(output.stderr, b"Secure Onboard M0 hook failed closed\n");
}

#[test]
fn hook_cli_emits_only_native_deny_on_stdout_and_writes_separate_evidence() {
    let fixture = Fixture::new();
    let marker = fixture.marker_root.join("run-cli/T01.marker");
    let command_text = format!(
        "/opt/homebrew/Cellar/node/26.5.0/bin/node {} high {}",
        fixture.trusted_root.join("helpers/m0-target.mjs").display(),
        marker.display()
    );
    let native = fixture.native_pre(&command_text, "session-cli", "prompt-cli", "tool-cli");
    let output = run_hook(
        "pre",
        &fixture.pre_arguments("T01", "run-cli", "cli", None),
        &native,
    );
    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(output.stderr, b"");
    let response = std::str::from_utf8(&output.stdout).unwrap();
    assert!(response.contains("\"permissionDecision\":\"deny\""));
    assert!(!marker.exists());
    for kind in [
        "native-input",
        "hook-envelope",
        "m0-action-request",
        "m0-action-decision",
        "m0-event",
        "native-output",
    ] {
        let directory = fixture.evidence_root.join(kind);
        assert!(
            fs::read_dir(&directory)
                .expect("evidence directory")
                .next()
                .is_some(),
            "missing {kind}"
        );
        #[cfg(unix)]
        assert_mode(&directory, 0o700);
        #[cfg(unix)]
        for entry in fs::read_dir(&directory).expect("evidence entries") {
            assert_mode(&entry.expect("evidence entry").path(), 0o600);
        }
    }

    for (sentinel, tool_id) in [("low", "tool-parallel-low"), ("info", "tool-parallel-info")] {
        let parallel_marker = fixture.marker_root.join("run-parallel/T07.marker");
        let command_text = format!(
            "/opt/homebrew/Cellar/node/26.5.0/bin/node {} {sentinel} {}",
            fixture.trusted_root.join("helpers/m0-target.mjs").display(),
            parallel_marker.display()
        );
        create_private_directory(&fixture.marker_root.join("run-parallel"));
        let native = fixture.native_pre(
            &command_text,
            "session-parallel",
            "prompt-parallel",
            tool_id,
        );
        let output = run_hook(
            "pre",
            &fixture.pre_arguments("T07", "run-parallel", "parallel", Some("native-sha256")),
            &native,
        );
        assert!(output.status.success(), "{:?}", output.stderr);
    }
    let action_ids = fs::read_dir(fixture.evidence_root.join("m0-action-request"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| fs::read(entry.path()).unwrap())
        .map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).unwrap())
        .filter(|request| request["test_run_id"] == "run-parallel")
        .map(|request| request["action_id"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(action_ids.len(), 2, "parallel calls reused an action ID");

    #[cfg(unix)]
    for directory in [
        &fixture.trusted_root,
        &fixture.target_root,
        &fixture.state_root,
        &fixture.evidence_root,
    ] {
        assert_mode(directory, 0o700);
    }
    #[cfg(unix)]
    for entry in fs::read_dir(&fixture.state_root).expect("state entries") {
        assert_mode(&entry.expect("state entry").path(), 0o600);
    }
    let state_names = fs::read_dir(&fixture.state_root)
        .expect("state entries")
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        state_names
            .iter()
            .filter(|name| name.ends_with(".json"))
            .count(),
        2
    );
    assert_eq!(
        state_names
            .iter()
            .filter(|name| name.ends_with(".delivered"))
            .count(),
        2
    );
}

#[test]
fn evidence_preflight_failure_does_not_commit_a_low_decision_before_high_fallback() {
    let fixture = Fixture::new();
    create_private_directory(&fixture.marker_root.join("run-evidence"));
    write_private_file(&fixture.evidence_root.join("hook-envelope"), b"collision");
    let marker = fixture.marker_root.join("run-evidence/T03.marker");
    let command_text = format!(
        "/opt/homebrew/Cellar/node/26.5.0/bin/node {} low {}",
        fixture.trusted_root.join("helpers/m0-target.mjs").display(),
        marker.display()
    );
    let native = fixture.native_pre(
        &command_text,
        "session-evidence",
        "prompt-evidence",
        "tool-evidence",
    );

    let output = run_hook(
        "pre",
        &fixture.pre_arguments("T03", "run-evidence", "evidence", None),
        &native,
    );

    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(
        output.stdout,
        b"{\"systemMessage\":\"Secure Onboard M0: adapter failure blocked the action.\",\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"Secure Onboard M0 adapter failure\"}}\n"
    );
    assert_eq!(output.stderr, b"Secure Onboard M0 hook failed closed\n");
    assert_eq!(
        fs::read_dir(&fixture.state_root).unwrap().count(),
        0,
        "LOW correlation was committed before the native warning was deliverable"
    );
    assert!(!fixture.evidence_root.join("m0-action-decision").exists());
    assert!(!fixture.evidence_root.join("m0-event").exists());
    assert!(!marker.exists());
}

#[test]
fn native_output_evidence_failure_happens_before_any_low_response_is_written() {
    let fixture = Fixture::new();
    create_private_directory(&fixture.marker_root.join("run-native-output"));
    write_private_file(&fixture.evidence_root.join("native-output"), b"collision");
    let marker = fixture.marker_root.join("run-native-output/T03.marker");
    let command_text = format!(
        "/opt/homebrew/Cellar/node/26.5.0/bin/node {} low {}",
        fixture.trusted_root.join("helpers/m0-target.mjs").display(),
        marker.display()
    );
    let native = fixture.native_pre(
        &command_text,
        "session-native-output",
        "prompt-native-output",
        "tool-native-output",
    );

    let output = run_hook(
        "pre",
        &fixture.pre_arguments("T03", "run-native-output", "native-output", None),
        &native,
    );

    assert!(output.status.success(), "{:?}", output.stderr);
    assert_eq!(
        output.stdout,
        b"{\"systemMessage\":\"Secure Onboard M0: adapter failure blocked the action.\",\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"Secure Onboard M0 adapter failure\"}}\n"
    );
    assert_eq!(output.stderr, b"Secure Onboard M0 hook failed closed\n");
    assert_eq!(fs::read_dir(&fixture.state_root).unwrap().count(), 0);
    assert!(!marker.exists());
}

#[test]
fn failed_low_stdout_write_blocks_and_leaves_only_prepared_correlation() {
    let fixture = Fixture::new();
    create_private_directory(&fixture.marker_root.join("run-closed-stdout"));
    let marker = fixture.marker_root.join("run-closed-stdout/T03.marker");
    let command_text = format!(
        "/opt/homebrew/Cellar/node/26.5.0/bin/node {} low {}",
        fixture.trusted_root.join("helpers/m0-target.mjs").display(),
        marker.display()
    );
    let native = fixture.native_pre(
        &command_text,
        "session-closed-stdout",
        "prompt-closed-stdout",
        "tool-closed-stdout",
    );

    let output = run_hook_with_closed_stdout(
        "pre",
        &fixture.pre_arguments("T03", "run-closed-stdout", "closed-stdout", None),
        &native,
    );

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stderr, b"Secure Onboard M0 hook failed\n");
    let state_files = fs::read_dir(&fixture.state_root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(state_files.len(), 1);
    assert!(state_files[0].ends_with(".json"));
    for kind in ["m0-action-decision", "m0-event", "native-output"] {
        assert_eq!(
            fs::read_dir(fixture.evidence_root.join(kind))
                .expect("preflight evidence directory")
                .count(),
            0,
            "failed stdout write left durable {kind} evidence"
        );
    }
    assert!(!marker.exists());
}

#[test]
fn evidence_failure_after_low_stdout_blocks_and_never_delivers_correlation() {
    let fixture = Fixture::new();
    create_private_directory(&fixture.marker_root.join("run-post-response-fault"));
    let marker = fixture
        .marker_root
        .join("run-post-response-fault/T03.marker");
    let command_text = format!(
        "/opt/homebrew/Cellar/node/26.5.0/bin/node {} low {}",
        fixture.trusted_root.join("helpers/m0-target.mjs").display(),
        marker.display()
    );
    let native = fixture.native_pre(
        &command_text,
        "session-post-response-fault",
        "prompt-post-response-fault",
        "tool-post-response-fault",
    );
    let mut arguments = fixture.pre_arguments(
        "T03",
        "run-post-response-fault",
        "post-response-fault",
        None,
    );
    arguments.extend(["--post-response-fault".into(), "evidence-write".into()]);

    let output = run_hook("pre", &arguments, &native);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        output.stdout,
        b"{\"systemMessage\":\"Secure Onboard M0: LOW warning.\"}\n"
    );
    assert_eq!(output.stderr, b"Secure Onboard M0 hook failed\n");
    let state_names = fs::read_dir(&fixture.state_root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(state_names.len(), 1);
    assert!(state_names[0].ends_with(".json"));
    assert!(!marker.exists());
}

#[test]
fn conflicting_correlation_returns_high_without_recording_the_candidate_decision() {
    let fixture = Fixture::new();
    for run_id in ["run-state-first", "run-state-conflict"] {
        create_private_directory(&fixture.marker_root.join(run_id));
    }
    let session_id = "session-state-collision";
    let tool_id = "tool-state-collision";
    let first_command = format!(
        "/opt/homebrew/Cellar/node/26.5.0/bin/node {} low {}",
        fixture.trusted_root.join("helpers/m0-target.mjs").display(),
        fixture
            .marker_root
            .join("run-state-first/T03.marker")
            .display()
    );
    let first_native =
        fixture.native_pre(&first_command, session_id, "prompt-state-first", tool_id);
    let first = run_hook(
        "pre",
        &fixture.pre_arguments("T03", "run-state-first", "state-first", None),
        &first_native,
    );
    assert!(first.status.success(), "{:?}", first.stderr);

    let evidence_count = |kind: &str| {
        fs::read_dir(fixture.evidence_root.join(kind))
            .expect("evidence directory")
            .count()
    };
    let before = [
        evidence_count("m0-action-decision"),
        evidence_count("m0-event"),
        evidence_count("native-output"),
    ];

    let conflicting_command = format!(
        "/opt/homebrew/Cellar/node/26.5.0/bin/node {} info {}",
        fixture.trusted_root.join("helpers/m0-target.mjs").display(),
        fixture
            .marker_root
            .join("run-state-conflict/T04.marker")
            .display()
    );
    let conflicting_native = fixture.native_pre(
        &conflicting_command,
        session_id,
        "prompt-state-conflict",
        tool_id,
    );
    let conflicting = run_hook(
        "pre",
        &fixture.pre_arguments("T04", "run-state-conflict", "state-conflict", None),
        &conflicting_native,
    );

    assert!(conflicting.status.success(), "{:?}", conflicting.stderr);
    assert_eq!(
        conflicting.stdout,
        b"{\"systemMessage\":\"Secure Onboard M0: adapter failure blocked the action.\",\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"Secure Onboard M0 adapter failure\"}}\n"
    );
    assert_eq!(
        conflicting.stderr,
        b"Secure Onboard M0 hook failed closed\n"
    );
    assert_eq!(
        [
            evidence_count("m0-action-decision"),
            evidence_count("m0-event"),
            evidence_count("native-output"),
        ],
        before
    );
    assert_eq!(fs::read_dir(&fixture.state_root).unwrap().count(), 2);
}
