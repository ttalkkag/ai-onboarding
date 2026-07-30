#![cfg(feature = "m0-test-profile")]

use secure_onboard::adapter_runtime::{CoreChild, CoreChildError, CoreFault, run_core_child};
use secure_onboard::m0::{
    Client, EvaluationMetadata, Invocation, M0ActionRequest, M0EventType, Sentinel,
};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn request() -> M0ActionRequest {
    M0ActionRequest {
        schema_version: "m0-action-request/v1".into(),
        phase: "m0".into(),
        test_case_id: "T02".into(),
        test_run_id: "m0-run-t02-01".into(),
        test_profile_digest: "sha256:profile".into(),
        action_id: "m0-action-01".into(),
        envelope_id: "envelope-01".into(),
        client: Client::Claude,
        session_fixture_id: "m0-session-01".into(),
        native_tool_call_id: "tool-call-01".into(),
        sentinel: Sentinel::High,
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

fn child(fault: CoreFault) -> CoreChild {
    CoreChild {
        executable: PathBuf::from(env!("CARGO_BIN_EXE_secure-onboard-m0-core")),
        working_directory: PathBuf::from("/private/tmp"),
        timeout: Duration::from_secs(1),
        fault,
    }
}

#[test]
fn live_core_child_round_trip_returns_a_strict_correlated_decision() {
    let output =
        run_core_child(&child(CoreFault::None), &request(), &metadata()).expect("core result");
    assert_eq!(
        output
            .events
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>(),
        [M0EventType::HighDetected, M0EventType::HighBlocked]
    );
}

#[test]
fn only_timeout_nonzero_and_schema_invalid_have_m0_fallback_codes() {
    for (fault, expected) in [
        (CoreFault::Timeout, "core_timeout"),
        (CoreFault::Nonzero, "core_nonzero"),
        (CoreFault::SchemaInvalid, "core_schema_invalid"),
        (CoreFault::OversizedStdout, "core_schema_invalid"),
    ] {
        let error = run_core_child(&child(fault), &request(), &metadata())
            .expect_err("fault must not return a core decision");
        assert_eq!(
            error.fallback_failure().map(|failure| failure.as_str()),
            Some(expected)
        );
    }
}

#[test]
fn timeout_kills_the_child_well_before_the_native_hook_timeout() {
    let started = Instant::now();
    let error =
        run_core_child(&child(CoreFault::Timeout), &request(), &metadata()).expect_err("timeout");
    assert!(matches!(error, CoreChildError::Timeout));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn timeout_also_bounds_a_large_stdin_when_the_child_never_reads_it() {
    let mut large = request();
    let Invocation::ShellText { command_text, .. } = &mut large.invocation;
    *command_text = "x".repeat(900_000);
    let mut core = child(CoreFault::Timeout);
    core.timeout = Duration::from_millis(100);

    let started = Instant::now();
    let error = run_core_child(&core, &large, &metadata()).expect_err("timeout");

    assert!(matches!(error, CoreChildError::Timeout));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[cfg(unix)]
#[test]
fn timeout_terminates_descendants_that_keep_core_pipes_open() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("temporary helper root");
    let ready = root.path().join("descendant-ready");
    let marker = root.path().join("descendant-survived");
    let helper = root.path().join("forking-core");
    fs::write(
        &helper,
        format!(
            concat!(
                "#!/usr/bin/python3\n",
                "import os\n",
                "import signal\n",
                "import time\n",
                "\n",
                "if os.fork() == 0:\n",
                "    signal.signal(signal.SIGHUP, signal.SIG_IGN)\n",
                "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n",
                "    with open({ready:?}, \"wb\") as ready_file:\n",
                "        ready_file.write(b\"ready\")\n",
                "    time.sleep(3)\n",
                "    with open({marker:?}, \"wb\") as marker_file:\n",
                "        marker_file.write(b\"survived\")\n",
                "    os._exit(0)\n",
                "time.sleep(30)\n",
            ),
            ready = ready,
            marker = marker
        ),
    )
    .expect("write forking core");
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))
        .expect("make forking core executable");
    let core = CoreChild {
        executable: helper,
        working_directory: root.path().to_owned(),
        timeout: Duration::from_millis(1_500),
        fault: CoreFault::None,
    };

    let runtime = std::thread::spawn(move || {
        let started = Instant::now();
        let result = run_core_child(&core, &request(), &metadata());
        (result, started.elapsed())
    });
    let ready_deadline = Instant::now() + Duration::from_secs(1);
    while !ready.exists() && Instant::now() < ready_deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    if !ready.exists() {
        let diagnostic = runtime.join().expect("join failed helper runtime");
        panic!("descendant helper did not start: {diagnostic:?}");
    }
    let (result, elapsed) = runtime.join().expect("join core runtime");
    let error = result.expect_err("timeout");

    assert!(matches!(error, CoreChildError::Timeout));
    assert!(
        elapsed < Duration::from_millis(2_250),
        "descendant-held pipes escaped the core deadline"
    );
    std::thread::sleep(Duration::from_millis(1_700));
    assert!(!marker.exists(), "timed-out descendant kept running");
}

#[test]
fn core_executable_spawn_failure_is_not_reported_as_a_valid_fallback_decision() {
    let missing = CoreChild {
        executable: PathBuf::from("/private/tmp/secure-onboard-missing-core"),
        working_directory: PathBuf::from("/private/tmp"),
        timeout: Duration::from_millis(100),
        fault: CoreFault::None,
    };
    let error = run_core_child(&missing, &request(), &metadata()).expect_err("spawn failure");
    assert!(matches!(error, CoreChildError::Spawn));
    assert_eq!(error.fallback_failure(), None);
}
