#![cfg(feature = "m0-test-profile")]

use secure_onboard::m0::{M0ActionDecision, M0ActionRequest, M0Event};
use secure_onboard::strict_json::from_slice;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const ACTIVE_MARKDOWN: &[&str] = &[
    "README.md",
    "CONTEXT.md",
    "docs/system-prompt.md",
    "docs/user-prompt.md",
    "docs/plan/decisions.md",
    "docs/plan/proposal.md",
    "docs/plan/workflow.md",
    "docs/plan/report-template.md",
    "docs/plan/use-cases.md",
    "docs/review/README.md",
    "docs/review/hook-contract-and-decisions.md",
];

const LINKED_REVIEW_MARKDOWN: &[&str] = &[
    "docs/review/plan-research-review.md",
    "docs/review/core-reverse-engineering-review.md",
    "docs/review/security-modules-review.md",
    "docs/review/runtime-modules-review.md",
];

fn run_validator(root: &Path) -> Output {
    Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/validate-docs"))
        .arg("--root")
        .arg(root)
        .output()
        .expect("run docs validator")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "validator failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &Output, expected: &str) {
    assert!(
        !output.status.success(),
        "validator unexpectedly succeeded\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let diagnostics = String::from_utf8_lossy(&output.stderr);
    assert!(
        diagnostics.contains(expected),
        "missing diagnostic {expected:?}\nstderr:\n{diagnostics}"
    );
}

fn contract_fixture() -> TempDir {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = tempfile::tempdir().expect("create docs fixture");
    for relative in ACTIVE_MARKDOWN.iter().chain(LINKED_REVIEW_MARKDOWN) {
        let source = source_root.join(relative);
        let destination = fixture.path().join(relative);
        fs::create_dir_all(destination.parent().expect("fixture parent"))
            .expect("create fixture parent");
        fs::copy(source, destination).expect("copy active Markdown");
    }
    fixture
}

fn append(relative: impl Into<PathBuf>, content: &str) {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(relative.into())
        .expect("open fixture Markdown");
    file.write_all(content.as_bytes())
        .expect("append fixture Markdown");
}

fn replace_once(path: impl Into<PathBuf>, from: &str, to: &str) {
    let path = path.into();
    let text = fs::read_to_string(&path).expect("read fixture Markdown");
    assert!(text.contains(from), "fixture text to replace is missing");
    fs::write(path, text.replacen(from, to, 1)).expect("replace fixture Markdown");
}

fn schema_example(schema: &str) -> String {
    let report = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/plan/report-template.md"),
    )
    .expect("read report template");
    let needle = format!("\"schema_version\": \"{schema}\"");
    let matches = report
        .split("```json\n")
        .skip(1)
        .filter_map(|tail| tail.split_once("\n```").map(|(json, _)| json))
        .filter(|json| json.contains(&needle))
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "expected one {schema} example");
    matches[0].to_owned()
}

#[test]
fn repository_docs_satisfy_the_local_contract() {
    assert_success(&run_validator(Path::new(env!("CARGO_MANIFEST_DIR"))));
}

#[test]
fn fenced_json_rejects_duplicate_object_keys() {
    let fixture = contract_fixture();
    append(
        fixture.path().join("docs/plan/proposal.md"),
        "\n```json\n{\"severity\":\"HIGH\",\"severity\":\"LOW\"}\n```\n",
    );

    assert_failure(
        &run_validator(fixture.path()),
        "duplicate object key: severity",
    );
}

#[test]
fn fenced_json_rejects_trailing_non_whitespace() {
    let fixture = contract_fixture();
    append(
        fixture.path().join("docs/plan/proposal.md"),
        "\n```json\n{\"severity\":\"HIGH\"} trailing\n```\n",
    );

    assert_failure(&run_validator(fixture.path()), "invalid fenced JSON");
}

#[test]
fn local_markdown_links_require_an_existing_file() {
    let fixture = contract_fixture();
    append(
        fixture.path().join("docs/plan/proposal.md"),
        "\n[missing contract](missing-contract.md)\n",
    );

    assert_failure(&run_validator(fixture.path()), "link target does not exist");
}

#[test]
fn local_markdown_links_require_an_existing_anchor() {
    let fixture = contract_fixture();
    append(
        fixture.path().join("docs/plan/decisions.md"),
        "\n[missing anchor](proposal.md#not-a-real-heading)\n",
    );

    assert_failure(&run_validator(fixture.path()), "link anchor does not exist");
}

#[test]
fn local_reference_links_require_an_existing_file() {
    let fixture = contract_fixture();
    append(
        fixture.path().join("docs/plan/proposal.md"),
        "\n[missing reference][contract]\n\n[contract]: missing-reference.md\n",
    );

    assert_failure(&run_validator(fixture.path()), "link target does not exist");
}

#[test]
fn local_file_links_require_exact_path_casing() {
    let fixture = contract_fixture();
    append(
        fixture.path().join("README.md"),
        "\n[wrong case](context.md)\n",
    );

    assert_failure(
        &run_validator(fixture.path()),
        "link path casing does not match",
    );
}

#[test]
fn user_prompt_is_limited_to_1500_unicode_characters() {
    let fixture = contract_fixture();
    fs::write(
        fixture.path().join("docs/user-prompt.md"),
        "가".repeat(1501),
    )
    .expect("replace user prompt");

    assert_failure(&run_validator(fixture.path()), "exceeds 1500 characters");
}

#[test]
fn active_readiness_documents_keep_m0_exclusions_coverage_zero_and_m1_no_go() {
    let fixture = contract_fixture();
    replace_once(fixture.path().join("README.md"), "M1 NO-GO", "M1 GO");

    assert_failure(
        &run_validator(fixture.path()),
        "readiness marker is missing: M1 NO-GO",
    );
}

#[test]
fn schema_examples_only_allow_high_low_and_info_severity() {
    let fixture = contract_fixture();
    append(
        fixture.path().join("docs/plan/proposal.md"),
        "\n```json\n{\"severity\":\"MEDIUM\"}\n```\n",
    );

    assert_failure(
        &run_validator(fixture.path()),
        "invalid severity enum: MEDIUM",
    );
}

#[test]
fn active_prose_rejects_legacy_severity_as_a_current_contract() {
    let fixture = contract_fixture();
    append(
        fixture.path().join("docs/plan/proposal.md"),
        "\n현재 제품 등급은 `MED`도 지원한다.\n",
    );

    assert_failure(
        &run_validator(fixture.path()),
        "legacy severity is asserted outside an allowed historical context: MED",
    );
}

#[test]
fn active_contract_rejects_retired_secret_redaction_candidates() {
    let fixture = contract_fixture();
    append(
        fixture.path().join("README.md"),
        "\n비밀값은 `SECURE_ONBOARD_REDACTED_SECRET`로 치환한다.\n",
    );

    assert_failure(
        &run_validator(fixture.path()),
        "retired secret redaction candidate is asserted: SECURE_ONBOARD_REDACTED_SECRET",
    );
}

#[test]
fn active_contract_rejects_a_secret_rendering_policy_branch() {
    let fixture = contract_fixture();
    append(
        fixture.path().join("README.md"),
        "\nGatePolicy는 `secret_rendering=redact_known_secrets`를 선택할 수 있다.\n",
    );

    assert_failure(
        &run_validator(fixture.path()),
        "secret_rendering branch is not fixed to literal_all",
    );
}

#[test]
fn active_contract_rejects_project_local_product_installation() {
    let fixture = contract_fixture();
    append(
        fixture.path().join("docs/plan/proposal.md"),
        "\nSecure Onboard는 프로젝트별 제품 설치를 제공한다.\n",
    );

    assert_failure(
        &run_validator(fixture.path()),
        "project-local product installation is asserted",
    );
}

#[test]
fn restored_control_byte_policy_rejects_the_known_contradiction() {
    let fixture = contract_fixture();
    append(
        fixture.path().join("docs/plan/proposal.md"),
        "\nsecret 출처에 따른 치환이나 terminal control escape는 하지 않는다.\n",
    );

    assert_failure(
        &run_validator(fixture.path()),
        "known control-byte contradiction is present",
    );
}

#[test]
fn restored_control_byte_policy_requires_the_safe_rendering_vocabulary() {
    let fixture = contract_fixture();
    let path = fixture.path().join("docs/plan/report-template.md");
    let text = fs::read_to_string(&path).expect("read report template fixture");
    assert!(text.contains("control_escape"));
    fs::write(path, text.replace("control_escape", "control_passthrough"))
        .expect("replace control rendering term");

    assert_failure(
        &run_validator(fixture.path()),
        "restored control-byte wording is missing",
    );
}

#[test]
fn m0_schema_examples_require_the_exact_documented_shape() {
    let fixture = contract_fixture();
    replace_once(
        fixture.path().join("docs/plan/report-template.md"),
        "\"schema_version\": \"m0-action-decision/v1\",\n  \"phase\": \"m0\",",
        "\"schema_version\": \"m0-action-decision/v1\",\n  \"unexpected\": true,\n  \"phase\": \"m0\",",
    );

    assert_failure(
        &run_validator(fixture.path()),
        "m0-action-decision/v1 example has unexpected keys: unexpected",
    );
}

#[test]
fn m0_runtime_types_accept_the_documented_request_decision_and_event_examples() {
    let request = schema_example("m0-action-request/v1");
    let request: M0ActionRequest = from_slice(request.as_bytes()).expect("request example");
    assert_eq!(request.schema_version, "m0-action-request/v1");

    let decision = schema_example("m0-action-decision/v1");
    let decision: M0ActionDecision = from_slice(decision.as_bytes()).expect("decision example");
    assert_eq!(decision.schema_version, "m0-action-decision/v1");

    let event = schema_example("m0-event/v1");
    let event: M0Event = from_slice(event.as_bytes()).expect("event example");
    assert_eq!(event.schema_version, "m0-event/v1");
}

#[cfg(feature = "m0-test-profile")]
#[test]
fn m0_status_runtime_type_accepts_the_documented_example() {
    use secure_onboard::m0_status::M0StatusReport;

    let status = schema_example("m0-status-report/v1");
    let status: M0StatusReport = from_slice(status.as_bytes()).expect("status example");
    assert_eq!(status.schema_version, "m0-status-report/v1");
}
