#![cfg(feature = "m0-test-profile")]
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use secure_onboard::m0_fixture_manifest::validate_fixture_manifest;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const CLIENTS: [(&str, &str, &str); 2] = [
    (
        "claude",
        "2.1.220 (Claude Code)",
        "claude-2.1.220-macos-arm64",
    ),
    ("codex", "codex-cli 0.146.0", "codex-0.146.0-macos-arm64"),
];

const NATIVE_SUFFIXES: [&str; 5] = ["prompt", "pre", "post-success", "post-failure", "stop"];

struct GeneratorFixture {
    _root: TempDir,
    fixture_root: PathBuf,
    artifact: PathBuf,
    core_artifact: PathBuf,
    claude_invoked: PathBuf,
    codex_invoked: PathBuf,
    codex_runtime: PathBuf,
}

impl GeneratorFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create generator fixture");
        let physical_root = root.path().canonicalize().expect("physical fixture root");
        let fixture_root = physical_root.join("fixtures");
        let artifact = physical_root.join("secure-onboard-m0-hook");
        let core_artifact = physical_root.join("secure-onboard-m0-core");
        let bin_root = physical_root.join("bin");
        fs::create_dir_all(fixture_root.join("profiles")).expect("profile directory");
        fs::create_dir_all(fixture_root.join("helpers")).expect("helper directory");
        fs::create_dir_all(fixture_root.join("native")).expect("native directory");
        fs::create_dir_all(&bin_root).expect("client bin directory");

        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/m0");
        for relative in [
            "profiles/claude-2.1.220-macos-arm64.json",
            "profiles/codex-0.146.0-macos-arm64.json",
            "helpers/m0-target.mjs",
            "helpers/m0-target-fail.mjs",
            "helpers/m0-target-near-match.mjs",
        ] {
            fs::copy(source_root.join(relative), fixture_root.join(relative))
                .expect("copy generator input");
        }
        for (_, _, prefix) in CLIENTS {
            for suffix in NATIVE_SUFFIXES {
                let bytes = serde_json::to_vec_pretty(&json!({
                    "client_fixture": prefix,
                    "native_role_fixture": suffix,
                }))
                .expect("serialize native fixture");
                let mut bytes = bytes;
                bytes.push(b'\n');
                fs::write(
                    fixture_root.join(format!("native/{prefix}-{suffix}.json")),
                    bytes,
                )
                .expect("write native fixture");
            }
        }

        let mut artifact_bytes = b"synthetic-m0-artifact-prefix\n".to_vec();
        for (_, _, prefix) in CLIENTS {
            artifact_bytes.extend(
                fs::read(fixture_root.join(format!("profiles/{prefix}.json")))
                    .expect("read profile for artifact"),
            );
            artifact_bytes.extend_from_slice(b"synthetic-m0-artifact-separator\n");
        }
        fs::write(&artifact, artifact_bytes).expect("write synthetic artifact");
        set_executable(&artifact);
        fs::write(&core_artifact, b"synthetic-m0-core").expect("write synthetic core");
        set_executable(&core_artifact);

        let mut invoked_paths = Vec::new();
        for (client, version_output, _) in CLIENTS {
            let resolved = bin_root.join(format!("{client}-real"));
            let invoked = bin_root.join(client);
            fs::write(
                &resolved,
                format!("#!/bin/sh\nprintf '%s\\n' '{version_output}'\n"),
            )
            .expect("write synthetic client");
            set_executable(&resolved);
            symlink(&resolved, &invoked).expect("link synthetic client");
            invoked_paths.push(invoked);
        }
        let codex_runtime = bin_root.join("codex-runtime");
        fs::write(
            &codex_runtime,
            "#!/bin/sh\nprintf '%s\\n' 'codex-cli 0.146.0'\n",
        )
        .expect("write synthetic Codex runtime");
        set_executable(&codex_runtime);

        Self {
            _root: root,
            fixture_root,
            artifact,
            core_artifact,
            claude_invoked: invoked_paths.remove(0),
            codex_invoked: invoked_paths.remove(0),
            codex_runtime,
        }
    }

    fn run(&self) -> Output {
        Command::new("python3")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/generate-m0-fixture-manifests"),
            )
            .arg("--fixture-root")
            .arg(&self.fixture_root)
            .arg("--artifact")
            .arg(&self.artifact)
            .arg("--core-artifact")
            .arg(&self.core_artifact)
            .arg("--claude-invoked")
            .arg(&self.claude_invoked)
            .arg("--codex-invoked")
            .arg(&self.codex_invoked)
            .arg("--codex-runtime")
            .arg(&self.codex_runtime)
            .output()
            .expect("run fixture manifest generator")
    }

    fn manifest_path(&self, prefix: &str) -> PathBuf {
        self.fixture_root.join(format!("manifests/{prefix}.json"))
    }
}

fn set_executable(path: &Path) {
    let mut permissions = fs::metadata(path).expect("artifact metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("set executable");
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "generator failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn generator_emits_deterministic_canonical_manifests_accepted_by_the_rust_contract() {
    let fixture = GeneratorFixture::new();

    let first = fixture.run();
    assert_success(&first);
    let first_bytes = CLIENTS.map(|(_, _, prefix)| {
        fs::read(fixture.manifest_path(prefix)).expect("read generated manifest")
    });

    let second = fixture.run();
    assert_success(&second);

    for (index, (client, _, prefix)) in CLIENTS.into_iter().enumerate() {
        let path = fixture.manifest_path(prefix);
        let bytes = fs::read(&path).expect("re-read generated manifest");
        assert_eq!(bytes, first_bytes[index], "{client} output changed");
        assert!(bytes.ends_with(b"}\n"));
        assert!(!bytes.ends_with(b"}\n\n"));

        let value: Value = serde_json::from_slice(&bytes).expect("strict JSON value");
        assert_eq!(
            value["core_artifact"]["sha256"],
            digest(&fs::read(&fixture.core_artifact).expect("read core artifact"))
        );
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let plugin_root = repository_root.join(format!("plugins/{client}-m0"));
        let plugin_manifest = plugin_root.join(if client == "claude" {
            ".claude-plugin/plugin.json"
        } else {
            ".codex-plugin/plugin.json"
        });
        let shipped_hooks_definition = plugin_root.join("hooks/hooks.json");
        assert_eq!(
            value["plugin_manifest"],
            json!({
                "absolute_path": plugin_manifest,
                "sha256": digest(&fs::read(&plugin_manifest).expect("read plugin manifest"))
            })
        );
        assert_eq!(
            value["shipped_hooks_definition"],
            json!({
                "absolute_path": shipped_hooks_definition,
                "sha256": digest(
                    &fs::read(&shipped_hooks_definition).expect("read shipped hooks definition")
                )
            })
        );
        let mut expected = serde_json::to_vec(&value).expect("canonical JSON");
        expected.push(b'\n');
        assert_eq!(bytes, expected, "{client} manifest is not canonical");

        let validated = validate_fixture_manifest(&bytes, &fixture.fixture_root)
            .expect("generated manifest satisfies Rust contract");
        assert_eq!(
            validated.client_version(),
            if client == "claude" {
                "2.1.220"
            } else {
                "0.146.0"
            }
        );
    }
}

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[test]
fn missing_native_dependency_fails_before_any_manifest_is_written() {
    let fixture = GeneratorFixture::new();
    let missing = fixture
        .fixture_root
        .join("native/codex-0.146.0-macos-arm64-prompt.json");
    fs::remove_file(&missing).expect("remove required native fixture");

    let output = fixture.run();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("required native fixture is missing or invalid"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!fixture.fixture_root.join("manifests").exists());
}

#[test]
fn artifact_without_exact_embedded_profile_fails_before_writing_outputs() {
    let fixture = GeneratorFixture::new();
    fs::write(&fixture.artifact, b"stale release artifact").expect("stale artifact");
    set_executable(&fixture.artifact);

    let output = fixture.run();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("release artifact does not contain the exact profile bytes once"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!fixture.fixture_root.join("manifests").exists());
}

#[test]
fn profile_unknown_fields_are_rejected_before_writing_outputs() {
    let fixture = GeneratorFixture::new();
    let profile_path = fixture
        .fixture_root
        .join("profiles/claude-2.1.220-macos-arm64.json");
    let mut profile: Value =
        serde_json::from_slice(&fs::read(&profile_path).expect("read profile")).unwrap();
    profile["unexpected"] = serde_json::json!(true);
    let mut changed = serde_json::to_vec_pretty(&profile).unwrap();
    changed.push(b'\n');
    fs::write(&profile_path, changed).expect("write changed profile");

    let mut artifact_bytes = b"synthetic-m0-artifact-prefix\n".to_vec();
    for (_, _, prefix) in CLIENTS {
        artifact_bytes.extend(
            fs::read(fixture.fixture_root.join(format!("profiles/{prefix}.json")))
                .expect("read current profile"),
        );
        artifact_bytes.extend_from_slice(b"synthetic-m0-artifact-separator\n");
    }
    fs::write(&fixture.artifact, artifact_bytes).expect("rebuild synthetic artifact");
    set_executable(&fixture.artifact);

    let output = fixture.run();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("fields must be exactly"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!fixture.fixture_root.join("manifests").exists());
}

#[test]
fn profile_shell_digest_must_match_the_physical_shell_before_writing_outputs() {
    let fixture = GeneratorFixture::new();
    let profile_path = fixture
        .fixture_root
        .join("profiles/claude-2.1.220-macos-arm64.json");
    let mut profile: Value =
        serde_json::from_slice(&fs::read(&profile_path).expect("read profile")).unwrap();
    profile["shell_binding"]["executable_sha256"] =
        json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let mut changed = serde_json::to_vec_pretty(&profile).unwrap();
    changed.push(b'\n');
    fs::write(&profile_path, changed).expect("write changed profile");

    let mut artifact_bytes = b"synthetic-m0-artifact-prefix\n".to_vec();
    for (_, _, prefix) in CLIENTS {
        artifact_bytes.extend(
            fs::read(fixture.fixture_root.join(format!("profiles/{prefix}.json")))
                .expect("read current profile"),
        );
        artifact_bytes.extend_from_slice(b"synthetic-m0-artifact-separator\n");
    }
    fs::write(&fixture.artifact, artifact_bytes).expect("rebuild synthetic artifact");
    set_executable(&fixture.artifact);

    let output = fixture.run();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("shell executable SHA-256 does not match physical bytes"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!fixture.fixture_root.join("manifests").exists());
}

#[test]
fn non_utf8_runtime_version_is_a_controlled_generation_error() {
    let fixture = GeneratorFixture::new();
    fs::write(
        &fixture.codex_runtime,
        "#!/usr/bin/env python3\nimport sys\nsys.stdout.buffer.write(b'\\xff\\n')\n",
    )
    .expect("write non-UTF-8 runtime");
    set_executable(&fixture.codex_runtime);

    let output = fixture.run();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("codex native runtime --version output is not UTF-8"),
        "unexpected diagnostic: {stderr}"
    );
    assert!(
        !stderr.contains("Traceback"),
        "unexpected traceback: {stderr}"
    );
    assert!(!fixture.fixture_root.join("manifests").exists());
}

#[test]
fn invoked_symlink_retargeted_during_version_observation_is_rejected() {
    let fixture = GeneratorFixture::new();
    let resolved = fs::canonicalize(&fixture.claude_invoked).expect("resolved Claude fixture");
    let alternate = resolved.with_file_name("claude-alternate");
    fs::write(
        &alternate,
        "#!/bin/sh\nprintf '%s\\n' '2.1.220 (Claude Code)'\n",
    )
    .expect("write alternate Claude fixture");
    set_executable(&alternate);
    fs::write(
        &resolved,
        format!(
            "#!/bin/sh\nrm -f '{}'\nln -s '{}' '{}'\nprintf '%s\\n' '2.1.220 (Claude Code)'\n",
            fixture.claude_invoked.display(),
            alternate.display(),
            fixture.claude_invoked.display(),
        ),
    )
    .expect("write retargeting Claude fixture");
    set_executable(&resolved);

    let output = fixture.run();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("invoked executable changed during version observation"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!fixture.fixture_root.join("manifests").exists());
}

#[test]
fn executable_metadata_changed_during_version_observation_is_rejected() {
    let fixture = GeneratorFixture::new();
    let resolved = fs::canonicalize(&fixture.claude_invoked).expect("resolved Claude fixture");
    fs::write(
        &resolved,
        format!(
            "#!/bin/sh\ntouch '{}'\nprintf '%s\\n' '2.1.220 (Claude Code)'\n",
            resolved.display(),
        ),
    )
    .expect("write mutating Claude fixture");
    set_executable(&resolved);

    let output = fixture.run();

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("executable changed during version observation"),
        "unexpected diagnostic: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!fixture.fixture_root.join("manifests").exists());
}
