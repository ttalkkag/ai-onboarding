#![cfg(feature = "m0-test-profile")]

use secure_onboard::m0_fixture_manifest::{
    Architecture, BindingKind, ManifestError, OperatingSystem, validate_fixture_manifest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

struct Fixture {
    _root: TempDir,
    fixture_root: PathBuf,
    client_resolved: PathBuf,
    client_runtime: PathBuf,
    product_artifact: PathBuf,
    core_artifact: PathBuf,
    plugin_manifest: PathBuf,
    shipped_hooks_definition: PathBuf,
    manifest: Value,
}

impl Fixture {
    fn new(client: &str) -> Self {
        let root = tempfile::tempdir().expect("fixture tempdir");
        let physical_root = root.path().canonicalize().expect("physical tempdir");
        let fixture_root = physical_root.join("fixtures");
        let client_resolved = physical_root.join("bin/client-real");
        let client_runtime = physical_root.join("bin/client-runtime");
        let client_invoked = physical_root.join("bin/client");
        let product_artifact = physical_root.join("bin/secure-onboard-m0-hook");
        let core_artifact = physical_root.join("bin/secure-onboard-m0-core");
        let plugin_root = physical_root.join(format!("plugins/{client}-m0"));
        let plugin_manifest = plugin_root.join(if client == "claude" {
            ".claude-plugin/plugin.json"
        } else {
            ".codex-plugin/plugin.json"
        });
        let shipped_hooks_definition = plugin_root.join("hooks/hooks.json");
        let runtime = physical_root.join("bin/node");
        let shell = physical_root.join("bin/zsh");
        fs::create_dir_all(client_resolved.parent().unwrap()).expect("bin directory");
        fs::create_dir_all(plugin_manifest.parent().unwrap()).expect("plugin manifest directory");
        fs::create_dir_all(shipped_hooks_definition.parent().unwrap())
            .expect("plugin hooks directory");
        for relative in ["profiles", "helpers", "native"] {
            fs::create_dir_all(fixture_root.join(relative)).expect("fixture directory");
        }

        fs::write(&client_resolved, b"client-executable").expect("client executable");
        fs::write(&client_runtime, b"client-runtime").expect("client runtime");
        fs::write(&product_artifact, b"m0-product-artifact").expect("product artifact");
        fs::write(&core_artifact, b"m0-core-artifact").expect("core artifact");
        fs::write(&plugin_manifest, b"{\"name\":\"m0-plugin\"}\n").expect("plugin manifest");
        fs::write(&shipped_hooks_definition, b"{\"hooks\":{},\"timeout\":5}\n")
            .expect("shipped hooks definition");
        fs::write(&runtime, b"fixture-runtime").expect("fixture runtime");
        fs::write(&shell, b"fixture-shell").expect("fixture shell");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&client_resolved, &client_invoked)
            .expect("client invoked symlink");
        #[cfg(not(unix))]
        fs::copy(&client_resolved, &client_invoked).expect("client invoked copy");

        let helper_specs = [
            (
                "default",
                "helpers/default.mjs",
                b"default-helper".as_slice(),
            ),
            (
                "failure",
                "helpers/failure.mjs",
                b"failure-helper".as_slice(),
            ),
            (
                "near_match",
                "helpers/near-match.mjs",
                b"near-match-helper".as_slice(),
            ),
        ];
        for (_, relative_path, bytes) in helper_specs {
            fs::write(fixture_root.join(relative_path), bytes).expect("helper");
        }

        let version = if client == "claude" {
            "2.1.220"
        } else {
            "0.146.0"
        };
        let profile = json!({
            "schema_version": "m0-test-profile/v1",
            "build_flavor": "test",
            "client": client,
            "client_version": version,
            "os": "macos",
            "architecture": "arm64",
            "fixture_runtime": {
                "executable_path": runtime,
                "executable_sha256": digest(b"fixture-runtime"),
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
                    "relative_path": "helpers/default.mjs",
                    "content_sha256": digest(b"default-helper"),
                    "command_grammar": "posix_ascii_argv4/v1",
                    "allowed_sentinels": ["high", "low", "info"]
                },
                {
                    "role": "failure",
                    "relative_path": "helpers/failure.mjs",
                    "content_sha256": digest(b"failure-helper"),
                    "command_grammar": "posix_ascii_argv4/v1",
                    "allowed_sentinels": ["low", "info"]
                }
            ],
            "marker_root_relative": "markers"
        });
        let mut profile_bytes = serde_json::to_vec_pretty(&profile).expect("profile JSON");
        profile_bytes.push(b'\n');
        let profile_relative = "profiles/profile.json";
        fs::write(fixture_root.join(profile_relative), &profile_bytes).expect("profile");
        let profile_digest = digest(&profile_bytes);

        let native_specs = [
            ("prompt", "native/prompt.json", "UserPromptSubmit"),
            ("pre_tool_use", "native/pre.json", "PreToolUse"),
            (
                "result_success",
                "native/result-success.json",
                "PostToolUse",
            ),
            (
                "result_failure",
                "native/result-failure.json",
                "PostToolUseFailure",
            ),
            ("stop", "native/stop.json", "Stop"),
        ];
        let mut native_fixtures = Vec::new();
        for (role, relative_path, hook_event_name) in native_specs {
            let value = json!({
                "hook_event_name": hook_event_name,
                "session_id": "m0-session-01"
            });
            let mut bytes = serde_json::to_vec_pretty(&value).expect("native JSON");
            bytes.push(b'\n');
            fs::write(fixture_root.join(relative_path), &bytes).expect("native fixture");
            native_fixtures.push(json!({
                "role": role,
                "relative_path": relative_path,
                "content_sha256": digest(&bytes),
                "canonical_json_sha256": canonical_digest(&value)
            }));
        }

        let version_output = if client == "claude" {
            format!("{version} (Claude Code)")
        } else {
            format!("codex-cli {version}")
        };
        let manifest = json!({
            "schema_version": "m0-fixture-manifest/v1",
            "client": client,
            "client_version": version,
            "os": "macos",
            "architecture": "arm64",
            "client_executable": {
                "invoked_path": client_invoked,
                "resolved_path": client_resolved,
                "sha256": digest(b"client-executable"),
                "version_output": version_output
            },
            "client_runtime_artifact": {
                "role": if client == "claude" {
                    "resolved_executable"
                } else {
                    "native_backend"
                },
                "absolute_path": if client == "claude" {
                    client_resolved.clone()
                } else {
                    client_runtime.clone()
                },
                "sha256": if client == "claude" {
                    digest(b"client-executable")
                } else {
                    digest(b"client-runtime")
                }
            },
            "plugin_manifest": {
                "absolute_path": plugin_manifest,
                "sha256": digest(b"{\"name\":\"m0-plugin\"}\n")
            },
            "shipped_hooks_definition": {
                "absolute_path": shipped_hooks_definition,
                "sha256": digest(b"{\"hooks\":{},\"timeout\":5}\n")
            },
            "product_artifact": {
                "absolute_path": product_artifact,
                "sha256": digest(b"m0-product-artifact"),
                "compiled_test_profile_sha256": profile_digest
            },
            "core_artifact": {
                "absolute_path": core_artifact,
                "sha256": digest(b"m0-core-artifact")
            },
            "test_profile": {
                "relative_path": profile_relative,
                "content_sha256": profile_digest
            },
            "helper_fixtures": helper_specs.map(|(role, relative_path, bytes)| json!({
                "role": role,
                "relative_path": relative_path,
                "content_sha256": digest(bytes)
            })),
            "native_fixtures": native_fixtures
        });

        Self {
            _root: root,
            fixture_root,
            client_resolved,
            client_runtime,
            product_artifact,
            core_artifact,
            plugin_manifest,
            shipped_hooks_definition,
            manifest,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&self.manifest).expect("canonical manifest");
        bytes.push(b'\n');
        bytes
    }

    fn rewrite_profile(&mut self, mutate: impl FnOnce(&mut Value)) {
        let relative_path = self.manifest["test_profile"]["relative_path"]
            .as_str()
            .expect("profile relative path");
        let path = self.fixture_root.join(relative_path);
        let bytes = fs::read(&path).expect("read profile");
        let mut profile: Value = serde_json::from_slice(&bytes).expect("parse profile fixture");
        mutate(&mut profile);
        let mut changed = serde_json::to_vec_pretty(&profile).expect("serialize profile");
        changed.push(b'\n');
        fs::write(path, &changed).expect("write changed profile");
        let changed_digest = digest(&changed);
        self.manifest["test_profile"]["content_sha256"] = json!(changed_digest);
        self.manifest["product_artifact"]["compiled_test_profile_sha256"] =
            self.manifest["test_profile"]["content_sha256"].clone();
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn canonical_digest(value: &Value) -> String {
    let bytes = secure_onboard::strict_json::canonical_bytes(value).expect("canonical JSON");
    digest(&bytes)
}

#[test]
fn canonical_manifest_binds_a_claude_target_and_every_m0_fixture() {
    let fixture = Fixture::new("claude");

    let manifest =
        validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root).expect("valid manifest");

    assert_eq!(manifest.client(), secure_onboard::m0::Client::Claude);
    assert_eq!(manifest.client_version(), "2.1.220");
    assert_eq!(manifest.os(), OperatingSystem::Macos);
    assert_eq!(manifest.architecture(), Architecture::Arm64);
    assert_eq!(manifest.client_resolved_path(), fixture.client_resolved);
    assert_eq!(manifest.product_artifact_path(), fixture.product_artifact);
    assert_eq!(manifest.canonical_bytes(), fixture.bytes());
}

#[test]
fn strict_shape_rejects_duplicate_unknown_and_missing_fields() {
    let fixture = Fixture::new("claude");
    let canonical = fixture.bytes();
    let text = std::str::from_utf8(&canonical).expect("UTF-8 manifest");
    let duplicate = text.replacen(
        "\"schema_version\":\"m0-fixture-manifest/v1\",",
        "\"schema_version\":\"m0-fixture-manifest/v1\",\"schema_version\":\"m0-fixture-manifest/v1\",",
        1,
    );
    assert_eq!(
        validate_fixture_manifest(duplicate.as_bytes(), &fixture.fixture_root),
        Err(ManifestError::SchemaInvalid)
    );

    let mut unknown = fixture.manifest.clone();
    unknown["unexpected"] = json!(true);
    assert_eq!(
        validate_fixture_manifest(&canonical_document_bytes(&unknown), &fixture.fixture_root),
        Err(ManifestError::SchemaInvalid)
    );

    let mut missing = fixture.manifest.clone();
    missing.as_object_mut().unwrap().remove("architecture");
    assert_eq!(
        validate_fixture_manifest(&canonical_document_bytes(&missing), &fixture.fixture_root),
        Err(ManifestError::SchemaInvalid)
    );
}

#[test]
fn every_digest_field_requires_a_lowercase_sha256_label() {
    let fixture = Fixture::new("codex");
    let mutations: &[(&[&str], BindingKind)] = &[
        (
            &["client_executable", "sha256"],
            BindingKind::ClientExecutable,
        ),
        (
            &["product_artifact", "sha256"],
            BindingKind::ProductArtifact,
        ),
        (
            &["product_artifact", "compiled_test_profile_sha256"],
            BindingKind::ProductArtifact,
        ),
        (&["plugin_manifest", "sha256"], BindingKind::PluginManifest),
        (
            &["shipped_hooks_definition", "sha256"],
            BindingKind::ShippedHooksDefinition,
        ),
        (&["core_artifact", "sha256"], BindingKind::CoreArtifact),
        (
            &["test_profile", "content_sha256"],
            BindingKind::TestProfile,
        ),
        (
            &["helper_fixtures", "0", "content_sha256"],
            BindingKind::HelperFixture,
        ),
        (
            &["native_fixtures", "0", "content_sha256"],
            BindingKind::NativeFixture,
        ),
        (
            &["native_fixtures", "0", "canonical_json_sha256"],
            BindingKind::NativeFixture,
        ),
    ];

    for (path, kind) in mutations {
        let mut changed = fixture.manifest.clone();
        replace_path(&mut changed, path, json!("SHA256:not-canonical"));
        assert_eq!(
            validate_fixture_manifest(&canonical_document_bytes(&changed), &fixture.fixture_root),
            Err(ManifestError::InvalidDigest(*kind)),
            "digest path {path:?}"
        );
    }
}

#[test]
fn core_artifact_bytes_are_bound_separately_from_the_hook() {
    let fixture = Fixture::new("claude");
    fs::write(&fixture.core_artifact, b"changed-core").expect("change core artifact");

    assert_eq!(
        validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root),
        Err(ManifestError::DigestMismatch(BindingKind::CoreArtifact))
    );
}

#[test]
fn shipped_plugin_manifest_and_hooks_definition_paths_and_bytes_are_bound() {
    let fixture = Fixture::new("claude");
    fs::write(&fixture.plugin_manifest, b"{\"name\":\"changed\"}\n")
        .expect("change plugin manifest");
    assert_eq!(
        validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root),
        Err(ManifestError::DigestMismatch(BindingKind::PluginManifest))
    );

    fs::write(&fixture.plugin_manifest, b"{\"name\":\"m0-plugin\"}\n")
        .expect("restore plugin manifest");
    fs::write(
        &fixture.shipped_hooks_definition,
        b"{\"hooks\":{},\"timeout\":9}\n",
    )
    .expect("change shipped hooks definition");
    assert_eq!(
        validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root),
        Err(ManifestError::DigestMismatch(
            BindingKind::ShippedHooksDefinition
        ))
    );

    fs::write(
        &fixture.shipped_hooks_definition,
        b"{\"hooks\":{},\"timeout\":5}\n",
    )
    .expect("restore shipped hooks definition");
    let mut wrong_client_path = fixture.manifest.clone();
    wrong_client_path["plugin_manifest"]["absolute_path"] =
        json!(fixture.plugin_manifest.parent().unwrap().join("other.json"));
    fs::write(
        wrong_client_path["plugin_manifest"]["absolute_path"]
            .as_str()
            .unwrap(),
        b"{\"name\":\"m0-plugin\"}\n",
    )
    .expect("write misplaced plugin manifest");
    assert_eq!(
        validate_fixture_manifest(
            &canonical_document_bytes(&wrong_client_path),
            &fixture.fixture_root
        ),
        Err(ManifestError::BindingMismatch(BindingKind::PluginManifest))
    );

    let other_hooks = fixture
        .fixture_root
        .join("plugins/claude-m0/hooks/hooks.json");
    fs::create_dir_all(other_hooks.parent().unwrap()).expect("other hooks directory");
    fs::write(&other_hooks, b"{\"hooks\":{},\"timeout\":5}\n").expect("other hooks");
    let mut split_bundle = fixture.manifest.clone();
    split_bundle["shipped_hooks_definition"]["absolute_path"] = json!(other_hooks);
    assert_eq!(
        validate_fixture_manifest(
            &canonical_document_bytes(&split_bundle),
            &fixture.fixture_root
        ),
        Err(ManifestError::BindingMismatch(BindingKind::PluginManifest))
    );
}

#[test]
fn core_artifact_must_be_the_named_sibling_of_the_hook() {
    let mut fixture = Fixture::new("claude");
    let other = fixture.fixture_root.join("secure-onboard-m0-core");
    fs::write(&other, b"m0-core-artifact").expect("write displaced core");
    fixture.manifest["core_artifact"]["absolute_path"] = json!(other);

    assert_eq!(
        validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root),
        Err(ManifestError::BindingMismatch(BindingKind::CoreArtifact))
    );
}

#[test]
fn manifest_bytes_must_be_canonical_json_with_exactly_one_final_lf() {
    let fixture = Fixture::new("claude");
    let pretty = format!(
        "{}\n",
        serde_json::to_string_pretty(&fixture.manifest).unwrap()
    );
    assert_eq!(
        validate_fixture_manifest(pretty.as_bytes(), &fixture.fixture_root),
        Err(ManifestError::NonCanonicalBytes)
    );

    let mut two_lf = fixture.bytes();
    two_lf.push(b'\n');
    assert_eq!(
        validate_fixture_manifest(&two_lf, &fixture.fixture_root),
        Err(ManifestError::NonCanonicalBytes)
    );

    let without_lf = serde_json::to_vec(&fixture.manifest).unwrap();
    assert_eq!(
        validate_fixture_manifest(&without_lf, &fixture.fixture_root),
        Err(ManifestError::NonCanonicalBytes)
    );
}

#[test]
fn codex_and_x86_64_are_bound_to_the_same_profile_target() {
    let mut fixture = Fixture::new("codex");
    fixture.manifest["architecture"] = json!("x86_64");
    fixture.rewrite_profile(|profile| profile["architecture"] = json!("x86_64"));

    let manifest =
        validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root).expect("valid Codex");

    assert_eq!(manifest.client(), secure_onboard::m0::Client::Codex);
    assert_eq!(manifest.client_version(), "0.146.0");
    assert_eq!(manifest.architecture(), Architecture::X86_64);
}

#[test]
fn client_executable_resolved_path_version_and_bytes_are_all_bound() {
    let fixture = Fixture::new("codex");

    let mut wrong_hash = fixture.manifest.clone();
    wrong_hash["client_executable"]["sha256"] =
        json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(
        validate_fixture_manifest(
            &canonical_document_bytes(&wrong_hash),
            &fixture.fixture_root
        ),
        Err(ManifestError::DigestMismatch(BindingKind::ClientExecutable))
    );

    let mut wrong_version = fixture.manifest.clone();
    wrong_version["client_executable"]["version_output"] = json!("codex-cli 0.144.0");
    assert_eq!(
        validate_fixture_manifest(
            &canonical_document_bytes(&wrong_version),
            &fixture.fixture_root
        ),
        Err(ManifestError::BindingMismatch(
            BindingKind::ClientExecutable
        ))
    );

    let mut wrong_resolved = fixture.manifest.clone();
    wrong_resolved["client_executable"]["resolved_path"] = json!(fixture.product_artifact);
    assert_eq!(
        validate_fixture_manifest(
            &canonical_document_bytes(&wrong_resolved),
            &fixture.fixture_root
        ),
        Err(ManifestError::BindingMismatch(
            BindingKind::ClientExecutable
        ))
    );
}

#[test]
fn product_artifact_and_compiled_profile_digest_are_bound() {
    let fixture = Fixture::new("claude");
    fs::write(&fixture.product_artifact, b"changed-product").expect("change product");
    assert_eq!(
        validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root),
        Err(ManifestError::DigestMismatch(BindingKind::ProductArtifact))
    );

    fs::write(&fixture.product_artifact, b"m0-product-artifact").expect("restore product");
    let mut wrong_profile_binding = fixture.manifest.clone();
    wrong_profile_binding["product_artifact"]["compiled_test_profile_sha256"] =
        json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(
        validate_fixture_manifest(
            &canonical_document_bytes(&wrong_profile_binding),
            &fixture.fixture_root
        ),
        Err(ManifestError::BindingMismatch(BindingKind::ProductArtifact))
    );
}

#[test]
fn helper_bytes_and_profile_helper_digests_are_bound_together() {
    let mut fixture = Fixture::new("claude");
    fs::write(
        fixture.fixture_root.join("helpers/default.mjs"),
        b"changed-helper",
    )
    .expect("change helper");
    assert_eq!(
        validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root),
        Err(ManifestError::DigestMismatch(BindingKind::HelperFixture))
    );

    fs::write(
        fixture.fixture_root.join("helpers/default.mjs"),
        b"default-helper",
    )
    .expect("restore helper");
    fixture.rewrite_profile(|profile| {
        profile["helpers"][0]["content_sha256"] =
            json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    });
    assert_eq!(
        validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root),
        Err(ManifestError::BindingMismatch(BindingKind::ProfileMetadata))
    );
}

#[test]
fn native_fixture_binds_both_raw_and_canonical_json_digests() {
    let fixture = Fixture::new("codex");
    fs::write(
        fixture.fixture_root.join("native/prompt.json"),
        b"{\"hook_event_name\":\"UserPromptSubmit\",\"session_id\":\"changed\"}\n",
    )
    .expect("change native fixture");
    assert_eq!(
        validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root),
        Err(ManifestError::DigestMismatch(BindingKind::NativeFixture))
    );

    let value = json!({
        "hook_event_name": "UserPromptSubmit",
        "session_id": "m0-session-01"
    });
    let mut original = serde_json::to_vec_pretty(&value).unwrap();
    original.push(b'\n');
    fs::write(fixture.fixture_root.join("native/prompt.json"), original)
        .expect("restore native fixture");
    let mut wrong_canonical = fixture.manifest.clone();
    wrong_canonical["native_fixtures"][0]["canonical_json_sha256"] =
        json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(
        validate_fixture_manifest(
            &canonical_document_bytes(&wrong_canonical),
            &fixture.fixture_root
        ),
        Err(ManifestError::DigestMismatch(BindingKind::NativeFixture))
    );
}

#[test]
fn native_fixture_larger_than_the_m0_contract_is_rejected_with_matching_digests() {
    let mut fixture = Fixture::new("codex");
    let value = json!({
        "hook_event_name": "UserPromptSubmit",
        "padding": "x".repeat(1024 * 1024),
        "session_id": "m0-session-01"
    });
    let mut bytes = serde_json::to_vec_pretty(&value).expect("oversized native JSON");
    bytes.push(b'\n');
    fs::write(fixture.fixture_root.join("native/prompt.json"), &bytes)
        .expect("write oversized native fixture");
    fixture.manifest["native_fixtures"][0]["content_sha256"] = json!(digest(&bytes));
    fixture.manifest["native_fixtures"][0]["canonical_json_sha256"] =
        json!(canonical_digest(&value));

    assert!(
        validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root).is_err(),
        "a native fixture over the M0 byte limit must not validate"
    );
}

#[test]
fn client_runtime_artifact_bytes_are_bound_separately_from_the_launcher() {
    let mut fixture = Fixture::new("codex");
    fixture.manifest["client_runtime_artifact"] = json!({
        "role": "native_backend",
        "absolute_path": fixture.client_runtime,
        "sha256": digest(b"client-runtime")
    });

    validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root)
        .expect("runtime artifact binding");

    fs::write(&fixture.client_runtime, b"changed-runtime").expect("change runtime");
    assert_eq!(
        validate_fixture_manifest(&fixture.bytes(), &fixture.fixture_root).unwrap_err(),
        ManifestError::DigestMismatch(BindingKind::ClientRuntimeArtifact)
    );
}

fn canonical_document_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("canonical manifest");
    bytes.push(b'\n');
    bytes
}

fn replace_path(value: &mut Value, path: &[&str], replacement: Value) {
    let (last, parents) = path.split_last().expect("non-empty path");
    let mut current = value;
    for segment in parents {
        current = if let Ok(index) = segment.parse::<usize>() {
            &mut current[index]
        } else {
            &mut current[*segment]
        };
    }
    current[*last] = replacement;
}
