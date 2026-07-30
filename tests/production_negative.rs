use serde_json::Value;
use std::process::Command;

#[test]
fn production_artifact_rejects_the_exact_test_profile_without_m0_output() {
    let binary = env!("CARGO_BIN_EXE_secure-onboard");
    let output = Command::new(binary)
        .args([
            "probe-profile",
            "tests/fixtures/m0/profiles/claude-2.1.220-macos-arm64.json",
        ])
        .output()
        .expect("run production probe");
    assert!(output.status.success());
    assert_eq!(output.stderr, b"");
    assert_eq!(output.stdout, b"{\"profile\":\"not_supported\"}\n");
    let text = std::str::from_utf8(&output.stdout).unwrap();
    for schema in [
        "m0-action-request/v1",
        "m0-action-decision/v1",
        "m0-event/v1",
        "m0-status-report/v1",
    ] {
        assert!(!text.contains(schema));
    }
}

#[test]
fn production_component_manifest_has_no_test_loader_rule_or_status_constructor() {
    let output = Command::new(env!("CARGO_BIN_EXE_secure-onboard"))
        .arg("components")
        .output()
        .expect("run component probe");
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("component JSON");
    assert_eq!(
        value,
        serde_json::json!({
            "schema_version": "secure-onboard-build-components/v1",
            "components": ["production_profile_rejection"]
        })
    );
    let text = std::str::from_utf8(&output.stdout).unwrap();
    for forbidden in [
        "m0_test_profile_loader",
        "m0_sentinel_rules",
        "m0_status_constructor",
    ] {
        assert!(!text.contains(forbidden));
    }
}
