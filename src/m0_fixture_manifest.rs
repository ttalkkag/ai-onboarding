#![cfg(feature = "m0-test-profile")]

use crate::m0::Client;
use crate::m0_physical_file::{PhysicalFileError, read_bounded, validate_digest_bounded};
use crate::strict_json::{canonical_bytes, from_slice};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

const SCHEMA_VERSION: &str = "m0-fixture-manifest/v1";
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PRODUCT_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DEFINITION_BYTES: u64 = 1024 * 1024;
const MAX_PROFILE_BYTES: u64 = 64 * 1024;
const MAX_FIXTURE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatingSystem {
    Macos,
    Windows,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Architecture {
    #[serde(rename = "arm64")]
    Arm64,
    #[serde(rename = "x86_64")]
    X86_64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingKind {
    ClientExecutable,
    ClientRuntimeArtifact,
    PluginManifest,
    ShippedHooksDefinition,
    ProductArtifact,
    CoreArtifact,
    TestProfile,
    HelperFixture,
    NativeFixture,
    ProfileMetadata,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ManifestError {
    #[error("fixture manifest is not strict m0-fixture-manifest/v1 JSON")]
    SchemaInvalid,
    #[error("fixture manifest bytes are not canonical JSON followed by one LF")]
    NonCanonicalBytes,
    #[error("fixture manifest has an invalid digest")]
    InvalidDigest(BindingKind),
    #[error("fixture manifest path is invalid or unavailable")]
    PathInvalid(BindingKind),
    #[error("fixture file exceeds its M0 byte limit")]
    SizeLimitExceeded(BindingKind),
    #[error("fixture bytes do not match their manifest digest")]
    DigestMismatch(BindingKind),
    #[error("fixture manifest bindings are inconsistent")]
    BindingMismatch(BindingKind),
}

#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedM0FixtureManifest {
    document: M0FixtureManifestDocument,
    canonical_bytes: Vec<u8>,
}

impl ValidatedM0FixtureManifest {
    pub fn client(&self) -> Client {
        self.document.client
    }

    pub fn client_version(&self) -> &str {
        &self.document.client_version
    }

    pub fn os(&self) -> OperatingSystem {
        self.document.os
    }

    pub fn architecture(&self) -> Architecture {
        self.document.architecture
    }

    pub fn client_resolved_path(&self) -> &Path {
        &self.document.client_executable.resolved_path
    }

    pub fn product_artifact_path(&self) -> &Path {
        &self.document.product_artifact.absolute_path
    }

    pub fn core_artifact_path(&self) -> &Path {
        &self.document.core_artifact.absolute_path
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

pub fn validate_fixture_manifest(
    bytes: &[u8],
    fixture_root: &Path,
) -> Result<ValidatedM0FixtureManifest, ManifestError> {
    let json_bytes = bytes
        .strip_suffix(b"\n")
        .ok_or(ManifestError::NonCanonicalBytes)?;
    let value: serde_json::Value =
        from_slice(json_bytes).map_err(|_| ManifestError::SchemaInvalid)?;
    let mut expected = canonical_bytes(&value).map_err(|_| ManifestError::SchemaInvalid)?;
    expected.push(b'\n');
    if bytes != expected {
        return Err(ManifestError::NonCanonicalBytes);
    }
    let document: M0FixtureManifestDocument =
        from_slice(json_bytes).map_err(|_| ManifestError::SchemaInvalid)?;

    validate_document(&document)?;
    validate_files(&document, fixture_root)?;

    Ok(ValidatedM0FixtureManifest {
        document,
        canonical_bytes: expected,
    })
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct M0FixtureManifestDocument {
    schema_version: String,
    client: Client,
    client_version: String,
    os: OperatingSystem,
    architecture: Architecture,
    client_executable: ClientExecutableBinding,
    client_runtime_artifact: ClientRuntimeArtifactBinding,
    plugin_manifest: AbsoluteFileBinding,
    shipped_hooks_definition: AbsoluteFileBinding,
    product_artifact: ProductArtifactBinding,
    core_artifact: AbsoluteFileBinding,
    test_profile: RelativeFileBinding,
    helper_fixtures: Vec<HelperFixtureBinding>,
    native_fixtures: Vec<NativeFixtureBinding>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ClientExecutableBinding {
    invoked_path: PathBuf,
    resolved_path: PathBuf,
    sha256: String,
    version_output: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ClientRuntimeArtifactRole {
    ResolvedExecutable,
    NativeBackend,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ClientRuntimeArtifactBinding {
    role: ClientRuntimeArtifactRole,
    absolute_path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProductArtifactBinding {
    absolute_path: PathBuf,
    sha256: String,
    compiled_test_profile_sha256: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct AbsoluteFileBinding {
    absolute_path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RelativeFileBinding {
    relative_path: PathBuf,
    content_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum HelperRole {
    Default,
    Failure,
    NearMatch,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HelperFixtureBinding {
    role: HelperRole,
    relative_path: PathBuf,
    content_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum NativeFixtureRole {
    Prompt,
    PreToolUse,
    ResultSuccess,
    ResultFailure,
    Stop,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeFixtureBinding {
    role: NativeFixtureRole,
    relative_path: PathBuf,
    content_sha256: String,
    canonical_json_sha256: String,
}

fn validate_document(document: &M0FixtureManifestDocument) -> Result<(), ManifestError> {
    if document.schema_version != SCHEMA_VERSION
        || document.client_version.is_empty()
        || document.client_version.chars().any(char::is_control)
    {
        return Err(ManifestError::SchemaInvalid);
    }

    let expected_version_output = match document.client {
        Client::Claude => format!("{} (Claude Code)", document.client_version),
        Client::Codex => format!("codex-cli {}", document.client_version),
    };
    if document.client_executable.version_output != expected_version_output {
        return Err(ManifestError::BindingMismatch(
            BindingKind::ClientExecutable,
        ));
    }
    let expected_runtime_role = match document.client {
        Client::Claude => ClientRuntimeArtifactRole::ResolvedExecutable,
        Client::Codex => ClientRuntimeArtifactRole::NativeBackend,
    };
    if document.client_runtime_artifact.role != expected_runtime_role {
        return Err(ManifestError::BindingMismatch(
            BindingKind::ClientRuntimeArtifact,
        ));
    }

    for (digest, kind) in [
        (
            document.client_executable.sha256.as_str(),
            BindingKind::ClientExecutable,
        ),
        (
            document.client_runtime_artifact.sha256.as_str(),
            BindingKind::ClientRuntimeArtifact,
        ),
        (
            document.plugin_manifest.sha256.as_str(),
            BindingKind::PluginManifest,
        ),
        (
            document.shipped_hooks_definition.sha256.as_str(),
            BindingKind::ShippedHooksDefinition,
        ),
        (
            document.product_artifact.sha256.as_str(),
            BindingKind::ProductArtifact,
        ),
        (
            document
                .product_artifact
                .compiled_test_profile_sha256
                .as_str(),
            BindingKind::ProductArtifact,
        ),
        (
            document.core_artifact.sha256.as_str(),
            BindingKind::CoreArtifact,
        ),
        (
            document.test_profile.content_sha256.as_str(),
            BindingKind::TestProfile,
        ),
    ] {
        if !is_sha256_label(digest) {
            return Err(ManifestError::InvalidDigest(kind));
        }
    }

    let expected_helpers = [
        HelperRole::Default,
        HelperRole::Failure,
        HelperRole::NearMatch,
    ];
    if document.helper_fixtures.len() != expected_helpers.len()
        || document
            .helper_fixtures
            .iter()
            .map(|fixture| fixture.role)
            .ne(expected_helpers)
    {
        return Err(ManifestError::BindingMismatch(BindingKind::HelperFixture));
    }
    if document
        .helper_fixtures
        .iter()
        .any(|fixture| !is_sha256_label(&fixture.content_sha256))
    {
        return Err(ManifestError::InvalidDigest(BindingKind::HelperFixture));
    }

    let expected_native = [
        NativeFixtureRole::Prompt,
        NativeFixtureRole::PreToolUse,
        NativeFixtureRole::ResultSuccess,
        NativeFixtureRole::ResultFailure,
        NativeFixtureRole::Stop,
    ];
    if document.native_fixtures.len() != expected_native.len()
        || document
            .native_fixtures
            .iter()
            .map(|fixture| fixture.role)
            .ne(expected_native)
    {
        return Err(ManifestError::BindingMismatch(BindingKind::NativeFixture));
    }
    if document.native_fixtures.iter().any(|fixture| {
        !is_sha256_label(&fixture.content_sha256)
            || !is_sha256_label(&fixture.canonical_json_sha256)
    }) {
        return Err(ManifestError::InvalidDigest(BindingKind::NativeFixture));
    }

    Ok(())
}

fn validate_files(
    document: &M0FixtureManifestDocument,
    fixture_root: &Path,
) -> Result<(), ManifestError> {
    let fixture_root = physical_directory(fixture_root, BindingKind::TestProfile)?;
    validate_client_executable(&document.client_executable)?;
    if document.client == Client::Claude {
        if document.client_runtime_artifact.absolute_path
            != document.client_executable.resolved_path
            || document.client_runtime_artifact.sha256 != document.client_executable.sha256
        {
            return Err(ManifestError::BindingMismatch(
                BindingKind::ClientRuntimeArtifact,
            ));
        }
    } else {
        validate_absolute_file(
            &document.client_runtime_artifact.absolute_path,
            &document.client_runtime_artifact.sha256,
            BindingKind::ClientRuntimeArtifact,
        )?;
    }
    validate_plugin_definition(document)?;
    validate_absolute_file(
        &document.product_artifact.absolute_path,
        &document.product_artifact.sha256,
        BindingKind::ProductArtifact,
    )?;
    validate_absolute_file(
        &document.core_artifact.absolute_path,
        &document.core_artifact.sha256,
        BindingKind::CoreArtifact,
    )?;
    let expected_hook_name = format!("secure-onboard-m0-hook{}", std::env::consts::EXE_SUFFIX);
    let expected_core_name = format!("secure-onboard-m0-core{}", std::env::consts::EXE_SUFFIX);
    if document.product_artifact.absolute_path.file_name() != Some(expected_hook_name.as_ref())
        || document.core_artifact.absolute_path.file_name() != Some(expected_core_name.as_ref())
        || document.core_artifact.absolute_path.parent()
            != document.product_artifact.absolute_path.parent()
    {
        return Err(ManifestError::BindingMismatch(BindingKind::CoreArtifact));
    }

    let profile_bytes = read_relative_file(
        &fixture_root,
        &document.test_profile.relative_path,
        &document.test_profile.content_sha256,
        BindingKind::TestProfile,
        MAX_PROFILE_BYTES,
    )?;
    if document.product_artifact.compiled_test_profile_sha256
        != document.test_profile.content_sha256
    {
        return Err(ManifestError::BindingMismatch(BindingKind::ProductArtifact));
    }
    validate_profile_binding(document, &profile_bytes)?;

    for helper in &document.helper_fixtures {
        read_relative_file(
            &fixture_root,
            &helper.relative_path,
            &helper.content_sha256,
            BindingKind::HelperFixture,
            MAX_FIXTURE_BYTES,
        )?;
    }
    for native in &document.native_fixtures {
        let bytes = read_relative_file(
            &fixture_root,
            &native.relative_path,
            &native.content_sha256,
            BindingKind::NativeFixture,
            MAX_FIXTURE_BYTES,
        )?;
        let value: serde_json::Value =
            from_slice(&bytes).map_err(|_| ManifestError::SchemaInvalid)?;
        let canonical = canonical_bytes(&value).map_err(|_| ManifestError::SchemaInvalid)?;
        if sha256_label(&canonical) != native.canonical_json_sha256 {
            return Err(ManifestError::DigestMismatch(BindingKind::NativeFixture));
        }
    }
    Ok(())
}

fn validate_plugin_definition(document: &M0FixtureManifestDocument) -> Result<(), ManifestError> {
    validate_absolute_file(
        &document.plugin_manifest.absolute_path,
        &document.plugin_manifest.sha256,
        BindingKind::PluginManifest,
    )?;
    validate_absolute_file(
        &document.shipped_hooks_definition.absolute_path,
        &document.shipped_hooks_definition.sha256,
        BindingKind::ShippedHooksDefinition,
    )?;
    let plugin_suffix = match document.client {
        Client::Claude => Path::new("plugins/claude-m0/.claude-plugin/plugin.json"),
        Client::Codex => Path::new("plugins/codex-m0/.codex-plugin/plugin.json"),
    };
    let hooks_suffix = match document.client {
        Client::Claude => Path::new("plugins/claude-m0/hooks/hooks.json"),
        Client::Codex => Path::new("plugins/codex-m0/hooks/hooks.json"),
    };
    let manifest_root = document
        .plugin_manifest
        .absolute_path
        .parent()
        .and_then(Path::parent);
    let hooks_root = document
        .shipped_hooks_definition
        .absolute_path
        .parent()
        .and_then(Path::parent);
    if !document
        .plugin_manifest
        .absolute_path
        .ends_with(plugin_suffix)
        || !document
            .shipped_hooks_definition
            .absolute_path
            .ends_with(hooks_suffix)
        || manifest_root != hooks_root
    {
        return Err(ManifestError::BindingMismatch(BindingKind::PluginManifest));
    }
    Ok(())
}

fn validate_client_executable(binding: &ClientExecutableBinding) -> Result<(), ManifestError> {
    if !binding.invoked_path.is_absolute() || !binding.resolved_path.is_absolute() {
        return Err(ManifestError::PathInvalid(BindingKind::ClientExecutable));
    }
    let invoked = fs::canonicalize(&binding.invoked_path)
        .map_err(|_| ManifestError::PathInvalid(BindingKind::ClientExecutable))?;
    let resolved = physical_file(&binding.resolved_path, BindingKind::ClientExecutable)?;
    if invoked != resolved {
        return Err(ManifestError::BindingMismatch(
            BindingKind::ClientExecutable,
        ));
    }
    validate_file_digest(
        &resolved,
        &binding.sha256,
        BindingKind::ClientExecutable,
        MAX_EXECUTABLE_BYTES,
    )
}

fn validate_absolute_file(
    path: &Path,
    expected_digest: &str,
    kind: BindingKind,
) -> Result<(), ManifestError> {
    let physical = physical_file(path, kind)?;
    validate_file_digest(
        &physical,
        expected_digest,
        kind,
        max_bytes_for_binding(kind),
    )
}

fn read_relative_file(
    root: &Path,
    relative_path: &Path,
    expected_digest: &str,
    kind: BindingKind,
    max_bytes: u64,
) -> Result<Vec<u8>, ManifestError> {
    if relative_path.as_os_str().is_empty()
        || relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ManifestError::PathInvalid(kind));
    }
    let joined = root.join(relative_path);
    if !joined.starts_with(root) {
        return Err(ManifestError::PathInvalid(kind));
    }
    let file = read_bounded(&joined, max_bytes).map_err(|error| map_file_error(error, kind))?;
    if file.sha256 != expected_digest {
        return Err(ManifestError::DigestMismatch(kind));
    }
    Ok(file.bytes)
}

fn validate_profile_binding(
    document: &M0FixtureManifestDocument,
    profile_bytes: &[u8],
) -> Result<(), ManifestError> {
    let json_bytes = profile_bytes
        .strip_suffix(b"\n")
        .ok_or(ManifestError::BindingMismatch(BindingKind::TestProfile))?;
    let profile: serde_json::Value =
        from_slice(json_bytes).map_err(|_| ManifestError::SchemaInvalid)?;
    let matches_target = profile
        .get("schema_version")
        .and_then(|value| value.as_str())
        == Some("m0-test-profile/v1")
        && profile.get("build_flavor").and_then(|value| value.as_str()) == Some("test")
        && profile.get("client").and_then(|value| value.as_str())
            == Some(match document.client {
                Client::Claude => "claude",
                Client::Codex => "codex",
            })
        && profile
            .get("client_version")
            .and_then(|value| value.as_str())
            == Some(&document.client_version)
        && profile.get("os").and_then(|value| value.as_str())
            == Some(match document.os {
                OperatingSystem::Macos => "macos",
                OperatingSystem::Windows => "windows",
            })
        && profile.get("architecture").and_then(|value| value.as_str())
            == Some(match document.architecture {
                Architecture::Arm64 => "arm64",
                Architecture::X86_64 => "x86_64",
            });
    if !matches_target {
        return Err(ManifestError::BindingMismatch(BindingKind::ProfileMetadata));
    }

    let Some(profile_helpers) = profile.get("helpers").and_then(|value| value.as_array()) else {
        return Err(ManifestError::BindingMismatch(BindingKind::ProfileMetadata));
    };
    if profile_helpers.len() != 2 {
        return Err(ManifestError::BindingMismatch(BindingKind::ProfileMetadata));
    }
    for (index, role) in [(0, HelperRole::Default), (1, HelperRole::Failure)] {
        let expected = &document.helper_fixtures[index];
        let actual = profile_helpers.get(index);
        let role_name = match role {
            HelperRole::Default => "default",
            HelperRole::Failure => "failure",
            HelperRole::NearMatch => unreachable!(),
        };
        if expected.role != role
            || actual.and_then(|value| value.get("role"))
                != Some(&serde_json::Value::String(role_name.to_owned()))
            || actual
                .and_then(|value| value.get("content_sha256"))
                .and_then(|value| value.as_str())
                != Some(&expected.content_sha256)
            || actual
                .and_then(|value| value.get("relative_path"))
                .and_then(|value| value.as_str())
                != expected.relative_path.to_str()
        {
            return Err(ManifestError::BindingMismatch(BindingKind::ProfileMetadata));
        }
    }
    Ok(())
}

fn physical_directory(path: &Path, kind: BindingKind) -> Result<PathBuf, ManifestError> {
    if !path.is_absolute() {
        return Err(ManifestError::PathInvalid(kind));
    }
    let canonical = fs::canonicalize(path).map_err(|_| ManifestError::PathInvalid(kind))?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ManifestError::PathInvalid(kind))?;
    if !metadata.file_type().is_dir() || canonical != path {
        return Err(ManifestError::PathInvalid(kind));
    }
    Ok(canonical)
}

fn physical_file(path: &Path, kind: BindingKind) -> Result<PathBuf, ManifestError> {
    if !path.is_absolute() {
        return Err(ManifestError::PathInvalid(kind));
    }
    let canonical = fs::canonicalize(path).map_err(|_| ManifestError::PathInvalid(kind))?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ManifestError::PathInvalid(kind))?;
    if !metadata.file_type().is_file() || canonical != path {
        return Err(ManifestError::PathInvalid(kind));
    }
    Ok(canonical)
}

fn validate_file_digest(
    path: &Path,
    expected_digest: &str,
    kind: BindingKind,
    max_bytes: u64,
) -> Result<(), ManifestError> {
    validate_digest_bounded(path, expected_digest, max_bytes)
        .map_err(|error| map_file_error(error, kind))
}

fn map_file_error(error: PhysicalFileError, kind: BindingKind) -> ManifestError {
    match error {
        PhysicalFileError::PathInvalid => ManifestError::PathInvalid(kind),
        PhysicalFileError::SizeLimitExceeded => ManifestError::SizeLimitExceeded(kind),
        PhysicalFileError::DigestMismatch => ManifestError::DigestMismatch(kind),
    }
}

fn max_bytes_for_binding(kind: BindingKind) -> u64 {
    match kind {
        BindingKind::ClientExecutable | BindingKind::ClientRuntimeArtifact => MAX_EXECUTABLE_BYTES,
        BindingKind::ProductArtifact | BindingKind::CoreArtifact => MAX_PRODUCT_ARTIFACT_BYTES,
        BindingKind::PluginManifest | BindingKind::ShippedHooksDefinition => MAX_DEFINITION_BYTES,
        BindingKind::TestProfile => MAX_PROFILE_BYTES,
        BindingKind::HelperFixture | BindingKind::NativeFixture => MAX_FIXTURE_BYTES,
        BindingKind::ProfileMetadata => MAX_PROFILE_BYTES,
    }
}

fn is_sha256_label(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
