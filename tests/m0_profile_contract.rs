#![cfg(feature = "m0-test-profile")]

use secure_onboard::m0_profile::{
    BindingResult, LoadProfileRequest, LoadedM0TestProfile, M0ProfileClient, M0Sentinel,
    ProfileError, embedded_profile_bytes, embedded_profile_digest, load_profile,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

struct Fixture {
    _root: TempDir,
    trusted_root: PathBuf,
    target_root: PathBuf,
    profile_path: PathBuf,
    default_helper: PathBuf,
    marker_root: PathBuf,
    profile_bytes: Vec<u8>,
    digest: String,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create fixture root");
        let physical_root = root.path().canonicalize().expect("resolve fixture root");
        let trusted_root = physical_root.join("user-area");
        let target_root = physical_root.join("target-project");
        let runtime = trusted_root.join("bin/node");
        let shell = trusted_root.join("bin/zsh");
        let default_helper = trusted_root.join("fixtures/m0-target.mjs");
        let failure_helper = trusted_root.join("fixtures/m0-target-fail.mjs");
        let marker_root = trusted_root.join("markers");
        let profile_path = trusted_root.join("profiles/codex.json");

        for directory in [
            runtime.parent().expect("runtime parent"),
            default_helper.parent().expect("helper parent"),
            &marker_root,
            profile_path.parent().expect("profile parent"),
            &target_root,
        ] {
            fs::create_dir_all(directory).expect("create fixture directory");
            set_mode(directory, 0o700);
        }
        set_mode(&trusted_root, 0o700);

        fs::write(&runtime, b"fixture-runtime").expect("write runtime");
        fs::write(&shell, b"fixture-shell").expect("write shell");
        fs::write(&default_helper, b"default-helper").expect("write default helper");
        fs::write(&failure_helper, b"failure-helper").expect("write failure helper");
        set_mode(&runtime, 0o700);
        set_mode(&shell, 0o700);
        set_mode(&default_helper, 0o600);
        set_mode(&failure_helper, 0o600);

        let runtime_digest = digest(b"fixture-runtime");
        let default_digest = digest(b"default-helper");
        let failure_digest = digest(b"failure-helper");
        let document = json!({
            "schema_version": "m0-test-profile/v1",
            "build_flavor": "test",
            "client": "codex",
            "client_version": "0.146.0",
            "os": "macos",
            "architecture": "arm64",
            "fixture_runtime": {
                "executable_path": runtime,
                "executable_sha256": runtime_digest,
                "version_output": "v26.5.0"
            },
            "shell_binding": {
                "executable_path": shell,
                "executable_sha256": digest(b"fixture-shell"),
                "flags": ["-lc"],
                "dialect": "posix_sh",
                "resolution_fingerprint": digest(b"shell-binding")
            },
            "helpers": [
                {
                    "role": "default",
                    "relative_path": "fixtures/m0-target.mjs",
                    "content_sha256": default_digest,
                    "command_grammar": "posix_ascii_argv4/v1",
                    "allowed_sentinels": ["high", "low", "info"]
                },
                {
                    "role": "failure",
                    "relative_path": "fixtures/m0-target-fail.mjs",
                    "content_sha256": failure_digest,
                    "command_grammar": "posix_ascii_argv4/v1",
                    "allowed_sentinels": ["low", "info"]
                }
            ],
            "marker_root_relative": "markers"
        });
        let mut profile_bytes = serde_json::to_vec_pretty(&document).expect("serialize profile");
        profile_bytes.push(b'\n');
        fs::write(&profile_path, &profile_bytes).expect("write profile");
        set_mode(&profile_path, 0o600);
        let digest = digest(&profile_bytes);

        Self {
            _root: root,
            trusted_root,
            target_root,
            profile_path,
            default_helper,
            marker_root,
            profile_bytes,
            digest,
        }
    }

    fn load(&self) -> Result<LoadedM0TestProfile, ProfileError> {
        self.load_at(Some(&self.profile_path), &self.digest)
    }

    fn load_at(
        &self,
        profile_path: Option<&std::path::Path>,
        expected_digest: &str,
    ) -> Result<LoadedM0TestProfile, ProfileError> {
        load_profile(LoadProfileRequest {
            profile_path,
            compile_time_expected_digest: expected_digest,
            trusted_source_root: &self.trusted_root,
            target_project_root: &self.target_root,
            expected_client: M0ProfileClient::Codex,
            expected_client_version: "0.146.0",
            expected_os: "macos",
            expected_architecture: "arm64",
            observed_runtime_version_output: "v26.5.0",
            observed_shell_resolution_fingerprint: &digest(b"shell-binding"),
        })
    }

    fn exact_default_command(&self, sentinel: &str) -> String {
        let runtime = self.trusted_root.join("bin/node");
        let marker = self.marker_root.join("run-01/T19-A.marker");
        format!(
            "{} {} {sentinel} {}",
            runtime.display(),
            self.default_helper.display(),
            marker.display()
        )
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn set_mode(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).expect("fixture metadata").permissions();
        permissions.set_mode(mode);
        fs::set_permissions(path, permissions).expect("set fixture permissions");
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

fn replace_once(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = std::str::from_utf8(bytes).expect("fixture is UTF-8");
    text.replacen(from, to, 1).into_bytes()
}

#[test]
fn exact_trusted_profile_and_argv_activate_the_declared_sentinel() {
    let fixture = Fixture::new();
    let profile = fixture.load().expect("valid profile loads");

    assert_eq!(profile.client(), M0ProfileClient::Codex);
    assert_eq!(profile.supplied_digest(), fixture.digest);
    assert_eq!(
        profile.match_command(&fixture.exact_default_command("high"), "run-01", "T19-A"),
        BindingResult::Matched {
            sentinel: M0Sentinel::High
        }
    );
}

#[test]
fn missing_profile_is_rejected_before_any_sentinel_can_load() {
    let fixture = Fixture::new();

    assert!(matches!(
        fixture.load_at(None, &fixture.digest),
        Err(ProfileError::ProfileMissing)
    ));
}

#[test]
fn one_changed_profile_byte_is_rejected_by_the_compile_time_digest() {
    let fixture = Fixture::new();
    let changed = replace_once(
        &fixture.profile_bytes,
        "\"client_version\": \"0.146.0\"",
        "\"client_version\": \"0.145.1\"",
    );
    fs::write(&fixture.profile_path, &changed).expect("replace profile bytes");

    assert_eq!(
        fixture.load().expect_err("changed bytes must be rejected"),
        ProfileError::DigestMismatch {
            expected_digest: fixture.digest,
            supplied_digest: digest(&changed),
        }
    );
}

#[test]
fn profile_larger_than_the_m0_contract_is_rejected_even_with_a_matching_digest() {
    let fixture = Fixture::new();
    let mut oversized = b"{\n".to_vec();
    oversized.extend(std::iter::repeat_n(b' ', 64 * 1024));
    oversized.extend_from_slice(&fixture.profile_bytes[2..]);
    fs::write(&fixture.profile_path, &oversized).expect("write oversized profile");

    assert!(
        fixture
            .load_at(Some(&fixture.profile_path), &digest(&oversized))
            .is_err(),
        "a profile over the M0 byte limit must not load"
    );
}

#[test]
fn digest_matched_profile_inside_the_target_project_is_still_untrusted() {
    let fixture = Fixture::new();
    let target_profile = fixture.target_root.join("profile.json");
    fs::write(&target_profile, &fixture.profile_bytes).expect("write target-owned profile");

    assert!(matches!(
        fixture.load_at(Some(&target_profile), &fixture.digest),
        Err(ProfileError::ProfileSourceUntrusted)
    ));
}

#[cfg(unix)]
#[test]
fn symlinked_profile_path_is_rejected_even_when_its_target_and_digest_are_valid() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    let linked_profile = fixture.trusted_root.join("profiles/linked.json");
    symlink(&fixture.profile_path, &linked_profile).expect("create profile symlink");

    assert!(matches!(
        fixture.load_at(Some(&linked_profile), &fixture.digest),
        Err(ProfileError::ProfileSourceUntrusted)
    ));
}

#[cfg(unix)]
#[test]
fn writable_trusted_root_is_rejected_before_the_profile_can_load() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let mut permissions = fs::metadata(&fixture.trusted_root)
        .expect("trusted root metadata")
        .permissions();
    permissions.set_mode(0o777);
    fs::set_permissions(&fixture.trusted_root, permissions).expect("make trusted root writable");

    assert!(matches!(
        fixture.load(),
        Err(ProfileError::ProfileSourceUntrusted)
    ));
}

#[cfg(unix)]
#[test]
fn non_private_profile_file_is_rejected_before_its_bytes_are_used() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let mut permissions = fs::metadata(&fixture.profile_path)
        .expect("profile metadata")
        .permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(&fixture.profile_path, permissions).expect("make profile non-private");

    assert!(matches!(
        fixture.load(),
        Err(ProfileError::ProfileSourceUntrusted)
    ));
}

#[cfg(unix)]
#[test]
fn non_private_helper_file_is_rejected_before_the_profile_can_load() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = Fixture::new();
    let mut permissions = fs::metadata(&fixture.default_helper)
        .expect("helper metadata")
        .permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(&fixture.default_helper, permissions).expect("make helper non-private");

    assert!(matches!(
        fixture.load(),
        Err(ProfileError::ProfileSourceUntrusted)
    ));
}

#[cfg(unix)]
#[test]
fn every_trusted_asset_directory_must_remain_private() {
    use std::os::unix::fs::PermissionsExt;

    for relative in ["profiles", "fixtures", "markers"] {
        let fixture = Fixture::new();
        let directory = fixture.trusted_root.join(relative);
        let mut permissions = fs::metadata(&directory)
            .expect("trusted directory metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&directory, permissions).expect("make directory non-private");

        assert!(
            matches!(fixture.load(), Err(ProfileError::ProfileSourceUntrusted)),
            "non-private trusted directory loaded: {relative}"
        );
    }
}

#[test]
fn helper_bytes_changed_after_profile_load_disable_the_sentinel() {
    let fixture = Fixture::new();
    let profile = fixture.load().expect("valid profile loads");
    fs::write(&fixture.default_helper, b"near-match-helper").expect("replace helper bytes");

    assert_eq!(
        profile.match_command(&fixture.exact_default_command("high"), "run-01", "T19-A"),
        BindingResult::HelperHashMismatch
    );
}

#[test]
fn helper_larger_than_the_m0_contract_is_rejected_with_matching_digests() {
    let fixture = Fixture::new();
    let oversized = vec![b'x'; 1024 * 1024 + 1];
    fs::write(&fixture.default_helper, &oversized).expect("write oversized helper");
    let mut profile: serde_json::Value =
        serde_json::from_slice(&fixture.profile_bytes).expect("parse profile");
    profile["helpers"][0]["content_sha256"] = serde_json::json!(digest(&oversized));
    let mut profile_bytes = serde_json::to_vec_pretty(&profile).expect("serialize profile");
    profile_bytes.push(b'\n');
    fs::write(&fixture.profile_path, &profile_bytes).expect("write rebound profile");

    assert!(
        fixture
            .load_at(Some(&fixture.profile_path), &digest(&profile_bytes))
            .is_err(),
        "a helper over the M0 byte limit must not load"
    );
}

#[test]
fn any_non_exact_posix_ascii_argv4_input_disables_the_sentinel() {
    let fixture = Fixture::new();
    let profile = fixture.load().expect("valid profile loads");
    let exact = fixture.exact_default_command("high");
    let wrong_marker = fixture.marker_root.join("run-01/other.marker");
    let runtime = fixture.trusted_root.join("bin/node");
    let wrong_runtime = fixture.trusted_root.join("bin/not-node");
    let helper = &fixture.default_helper;
    let marker = fixture.marker_root.join("run-01/T19-A.marker");
    let cases = [
        format!(" {exact}"),
        format!("{exact} "),
        exact.replacen(' ', "  ", 1),
        format!("{exact} noop"),
        format!(
            "\"{}\" {} high {}",
            runtime.display(),
            helper.display(),
            marker.display()
        ),
        format!(
            "{} {} high {}",
            runtime.display(),
            helper.display(),
            wrong_marker.display()
        ),
        format!(
            "{} {} HIGH {}",
            runtime.display(),
            helper.display(),
            marker.display()
        ),
        format!(
            "{} {} high {}",
            wrong_runtime.display(),
            helper.display(),
            marker.display()
        ),
        format!(
            "{} {} high {};noop",
            runtime.display(),
            helper.display(),
            marker.display()
        ),
        format!(
            "{} {} hi\u{0000}gh {}",
            runtime.display(),
            helper.display(),
            marker.display()
        ),
        format!(
            "{} {} hígh {}",
            runtime.display(),
            helper.display(),
            marker.display()
        ),
    ];

    for command in cases {
        assert_eq!(
            profile.match_command(&command, "run-01", "T19-A"),
            BindingResult::ArgvMismatch,
            "unexpected match for {command:?}"
        );
    }
    assert_eq!(
        profile.match_command(&exact, "run/child", "T19-A"),
        BindingResult::ArgvMismatch
    );
    assert_eq!(
        profile.match_command(&exact, "run-01", "T19/A"),
        BindingResult::ArgvMismatch
    );
}

#[test]
fn profile_bytes_and_schema_are_strict_not_best_effort() {
    let fixture = Fixture::new();
    let mut invalid_utf8 = fixture.profile_bytes.clone();
    invalid_utf8.insert(invalid_utf8.len() - 2, 0xff);
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend_from_slice(&fixture.profile_bytes);
    let duplicate_key = replace_once(
        &fixture.profile_bytes,
        "{\n",
        "{\n  \"schema_version\": \"m0-test-profile/v1\",\n",
    );
    let additional_key = replace_once(
        &fixture.profile_bytes,
        "}\n",
        ",\n  \"unexpected\": true\n}\n",
    );
    let wrong_helper_layout = replace_once(
        &fixture.profile_bytes,
        "\"role\": \"default\"",
        "\"role\": \"failure\"",
    );
    let wrong_digest_shape = replace_once(
        &fixture.profile_bytes,
        &digest(b"default-helper"),
        "sha256:not-a-digest",
    );
    let cases = [
        invalid_utf8,
        bom,
        duplicate_key,
        additional_key,
        wrong_helper_layout,
        wrong_digest_shape,
        {
            let mut bytes = fixture.profile_bytes.clone();
            bytes.push(b'\n');
            bytes
        },
        {
            let mut bytes = fixture.profile_bytes.clone();
            bytes.splice(bytes.len() - 1.., *b"\r\n");
            bytes
        },
    ];

    for bytes in cases {
        fs::write(&fixture.profile_path, &bytes).expect("write malformed profile");
        let expected = digest(&bytes);
        assert!(
            matches!(
                fixture.load_at(Some(&fixture.profile_path), &expected),
                Err(ProfileError::SchemaInvalid)
            ),
            "malformed profile unexpectedly loaded"
        );
    }
}

#[test]
fn malformed_compile_time_digest_is_rejected() {
    let fixture = Fixture::new();

    assert!(matches!(
        fixture.load_at(Some(&fixture.profile_path), "sha256:not-a-digest"),
        Err(ProfileError::ExpectedDigestInvalid)
    ));
}

#[test]
fn checked_in_profiles_are_compile_time_bound_to_exact_bytes() {
    assert_eq!(
        embedded_profile_digest(M0ProfileClient::Claude),
        "sha256:970e4f76faad81b11157f4c352c4427c7857b7fede4b0828a1aec0d89be19be4"
    );
    assert_eq!(
        embedded_profile_digest(M0ProfileClient::Codex),
        "sha256:db3ecd25dcbdfaccc46a75700c60339b1115a7eab5cb47d38996244ab0e2e749"
    );
    assert!(embedded_profile_bytes(M0ProfileClient::Claude).ends_with(b"}\n"));
    assert!(embedded_profile_bytes(M0ProfileClient::Codex).ends_with(b"}\n"));
}

#[test]
fn runtime_hash_version_and_shell_probe_are_required_before_loading() {
    let fixture = Fixture::new();
    fs::write(fixture.trusted_root.join("bin/node"), b"changed-runtime").expect("replace runtime");
    assert!(matches!(fixture.load(), Err(ProfileError::SchemaInvalid)));

    let fixture = Fixture::new();
    assert!(matches!(
        load_profile(LoadProfileRequest {
            profile_path: Some(&fixture.profile_path),
            compile_time_expected_digest: &fixture.digest,
            trusted_source_root: &fixture.trusted_root,
            target_project_root: &fixture.target_root,
            expected_client: M0ProfileClient::Codex,
            expected_client_version: "0.146.0",
            expected_os: "macos",
            expected_architecture: "arm64",
            observed_runtime_version_output: "v0.0.0",
            observed_shell_resolution_fingerprint: &digest(b"shell-binding"),
        }),
        Err(ProfileError::SchemaInvalid)
    ));
    assert!(matches!(
        load_profile(LoadProfileRequest {
            profile_path: Some(&fixture.profile_path),
            compile_time_expected_digest: &fixture.digest,
            trusted_source_root: &fixture.trusted_root,
            target_project_root: &fixture.target_root,
            expected_client: M0ProfileClient::Codex,
            expected_client_version: "0.146.0",
            expected_os: "macos",
            expected_architecture: "arm64",
            observed_runtime_version_output: "v26.5.0",
            observed_shell_resolution_fingerprint: &digest(b"different-shell"),
        }),
        Err(ProfileError::SchemaInvalid)
    ));

    let fixture = Fixture::new();
    fs::write(
        fixture.trusted_root.join("bin/zsh"),
        b"changed-fixture-shell",
    )
    .expect("replace shell");
    assert!(matches!(fixture.load(), Err(ProfileError::SchemaInvalid)));
}

#[test]
fn profile_identity_must_match_the_invoking_client_version_and_host() {
    for (from, to) in [
        ("\"client\": \"codex\"", "\"client\": \"claude\""),
        (
            "\"client_version\": \"0.146.0\"",
            "\"client_version\": \"9.9.9\"",
        ),
        (
            "\"architecture\": \"arm64\"",
            "\"architecture\": \"x86_64\"",
        ),
    ] {
        let fixture = Fixture::new();
        let changed = replace_once(&fixture.profile_bytes, from, to);
        fs::write(&fixture.profile_path, &changed).expect("write rebound profile");
        assert!(
            matches!(
                fixture.load_at(Some(&fixture.profile_path), &digest(&changed)),
                Err(ProfileError::SchemaInvalid)
            ),
            "profile identity mutation {from} -> {to} was accepted"
        );
    }
}
