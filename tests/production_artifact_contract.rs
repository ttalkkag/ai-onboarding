#[cfg(feature = "m0-test-profile")]
use secure_onboard::m0_status::ArtifactInspection;
#[cfg(feature = "m0-test-profile")]
use secure_onboard::m0_status_harness::{
    M0ProductionEvidence, validate_production_artifact_evidence,
};
#[cfg(feature = "m0-test-profile")]
use secure_onboard::strict_json::canonical_bytes;
use serde_json::Value;
#[cfg(feature = "m0-test-profile")]
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

const PROFILE_FIXTURES: [&str; 2] = [
    "tests/fixtures/m0/profiles/claude-2.1.220-macos-arm64.json",
    "tests/fixtures/m0/profiles/codex-0.146.0-macos-arm64.json",
];

const HELPER_FIXTURES: [&str; 3] = [
    "tests/fixtures/m0/helpers/m0-target.mjs",
    "tests/fixtures/m0/helpers/m0-target-fail.mjs",
    "tests/fixtures/m0/helpers/m0-target-near-match.mjs",
];

#[test]
fn clean_no_feature_release_artifact_rejects_m0_profiles_and_contains_no_m0_payload() {
    let artifact = ProductionArtifact::build();
    let artifact_before_probe = fs::read(&artifact.binary).expect("read production artifact");
    let library = fs::read(&artifact.library).expect("read production library");

    for relative_profile in PROFILE_FIXTURES {
        let profile = artifact.manifest_dir.join(relative_profile);
        let output = Command::new(&artifact.binary)
            .arg("probe-profile")
            .arg(&profile)
            .output()
            .expect("run production profile probe");
        assert_success(&output, "production profile probe");
        assert_eq!(output.stderr, b"");
        assert_eq!(output.stdout, b"{\"profile\":\"not_supported\"}\n");
    }

    let components = Command::new(&artifact.binary)
        .arg("components")
        .output()
        .expect("read production component manifest");
    assert_success(&components, "production component manifest");
    assert_eq!(components.stderr, b"");
    let component_manifest: Value =
        serde_json::from_slice(&components.stdout).expect("parse production component manifest");
    assert_eq!(
        component_manifest,
        serde_json::json!({
            "schema_version": "secure-onboard-build-components/v1",
            "components": ["production_profile_rejection"]
        })
    );

    let artifact_after_probe = fs::read(&artifact.binary).expect("re-read production artifact");
    assert_eq!(
        artifact_before_probe, artifact_after_probe,
        "all checks must use the unchanged artifact from one clean release build"
    );

    #[cfg(feature = "m0-test-profile")]
    {
        let artifact_digest = sha256_label(&artifact_after_probe);
        let mut bound_manifest = canonical_bytes(&serde_json::json!({
            "schema_version": "secure-onboard-bound-build-manifest/v1",
            "artifact_sha256": artifact_digest,
            "component_manifest_sha256": sha256_label(&components.stdout),
            "components": ["production_profile_rejection"]
        }))
        .expect("canonical bound build manifest");
        bound_manifest.push(b'\n');
        let profile = artifact.manifest_dir.join(PROFILE_FIXTURES[0]);
        let profile_probe = Command::new(&artifact.binary)
            .arg("probe-profile")
            .arg(profile)
            .output()
            .expect("run bound production profile probe");
        let inspection = ArtifactInspection {
            method: "bound-build-manifest-plus-black-box-profile-probe/v1".into(),
            build_manifest_digest: sha256_label(&bound_manifest),
            bound_artifact_digest: artifact_digest,
            forbidden_components: vec![
                "m0_test_profile_loader".into(),
                "m0_sentinel_rules".into(),
                "m0_status_constructor".into(),
            ],
            forbidden_component_count: 0,
            black_box_profile_probe: "not_supported".into(),
            production_emitted_m0_schema_count: 0,
        };
        let production_binary = artifact
            .binary
            .canonicalize()
            .expect("physical production binary");
        validate_production_artifact_evidence(
            &production_binary,
            &inspection,
            M0ProductionEvidence {
                bound_build_manifest_bytes: &bound_manifest,
                component_probe_stdout: &components.stdout,
                component_probe_stderr: &components.stderr,
                profile_probe_stdout: &profile_probe.stdout,
                profile_probe_stderr: &profile_probe.stderr,
            },
        )
        .expect("same-build production evidence");
    }

    for (label, forbidden) in forbidden_m0_strings() {
        assert_omits(&artifact_after_probe, forbidden, label);
        assert_omits(&library, forbidden, label);
    }
    for relative_profile in PROFILE_FIXTURES {
        let bytes = fs::read(artifact.manifest_dir.join(relative_profile))
            .expect("read embedded-profile fixture");
        assert_omits(&artifact_after_probe, &bytes, relative_profile);
    }
    for relative_helper in HELPER_FIXTURES {
        let bytes =
            fs::read(artifact.manifest_dir.join(relative_helper)).expect("read helper fixture");
        assert_omits(&artifact_after_probe, &bytes, relative_helper);
    }

    for m0_binary in ["secure-onboard-m0-core", "secure-onboard-m0-hook"] {
        let path = artifact
            .release_dir
            .join(format!("{m0_binary}{}", std::env::consts::EXE_SUFFIX));
        assert!(
            !path.exists(),
            "no-feature production build unexpectedly emitted {}",
            path.display()
        );
    }
}

struct ProductionArtifact {
    _target_dir: TempDir,
    manifest_dir: PathBuf,
    release_dir: PathBuf,
    binary: PathBuf,
    library: PathBuf,
}

impl ProductionArtifact {
    fn build() -> Self {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let target_dir = tempfile::Builder::new()
            .prefix("secure-onboard-production-artifact-")
            .tempdir()
            .expect("create clean Cargo target directory");
        let output = Command::new(cargo_executable())
            .current_dir(&manifest_dir)
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_INCREMENTAL", "0")
            .env_remove("CARGO_FEATURE_M0_TEST_PROFILE")
            .arg("build")
            .arg("--locked")
            .arg("--offline")
            .arg("--release")
            .arg("--no-default-features")
            .arg("--lib")
            .arg("--bin")
            .arg("secure-onboard")
            .arg("--target-dir")
            .arg(target_dir.path())
            .output()
            .expect("build clean no-feature production artifact");
        assert_success(&output, "clean no-feature release build");

        let release_dir = target_dir.path().join("release");
        let binary = release_dir.join(format!("secure-onboard{}", std::env::consts::EXE_SUFFIX));
        let library = release_dir.join("libsecure_onboard.rlib");
        assert!(
            binary.is_file(),
            "production artifact was not created at {}",
            binary.display()
        );
        assert!(
            library.is_file(),
            "production library was not created at {}",
            library.display()
        );

        Self {
            _target_dir: target_dir,
            manifest_dir,
            release_dir,
            binary,
            library,
        }
    }
}

fn cargo_executable() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_omits(artifact: &[u8], forbidden: &[u8], label: &str) {
    assert!(
        !contains_bytes(artifact, forbidden),
        "production artifact contains forbidden M0 payload: {label}"
    );
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[cfg(feature = "m0-test-profile")]
fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn forbidden_m0_strings() -> [(&'static str, &'static [u8]); 20] {
    [
        ("test profile loader component", b"m0_test_profile_loader"),
        ("sentinel rules component", b"m0_sentinel_rules"),
        ("status constructor component", b"m0_status_constructor"),
        ("test profile schema", b"m0-test-profile/v1"),
        ("action request schema", b"m0-action-request/v1"),
        ("action decision schema", b"m0-action-decision/v1"),
        ("event schema", b"m0-event/v1"),
        ("status report schema", b"m0-status-report/v1"),
        ("HIGH sentinel rule", b"m0.sentinel.high"),
        ("LOW sentinel rule", b"m0.sentinel.low"),
        ("INFO sentinel rule", b"m0.sentinel.info"),
        ("default helper name", b"m0-target.mjs"),
        ("failure helper name", b"m0-target-fail.mjs"),
        ("near-match helper name", b"m0-target-near-match.mjs"),
        ("M0 fixture root", b"/private/tmp/secure-onboard-m0-v1"),
        ("M0 argv grammar", b"posix_ascii_argv4/v1"),
        ("M0 loader error", b"M0 test profile input is missing"),
        (
            "M0 artifact inspection constructor",
            b"bound-build-manifest-plus-black-box-profile-probe/v1",
        ),
        ("M0 core executable", b"secure-onboard-m0-core"),
        ("M0 hook executable", b"secure-onboard-m0-hook"),
    ]
}
