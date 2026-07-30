#![cfg(feature = "m0-test-profile")]

use crate::m0_physical_file::{PhysicalFileError, read_bounded, validate_digest_bounded};
use crate::m0_secure_fs::{require_private_directory, require_private_file};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

const PROFILE_SCHEMA: &str = "m0-test-profile/v1";
const TEST_BUILD_FLAVOR: &str = "test";
const POSIX_ARGV4_GRAMMAR: &str = "posix_ascii_argv4/v1";
const MAX_PROFILE_BYTES: u64 = 64 * 1024;
const MAX_HELPER_BYTES: u64 = 1024 * 1024;
const MAX_RUNTIME_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum M0ProfileClient {
    Claude,
    Codex,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum M0Sentinel {
    High,
    Low,
    Info,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingResult {
    Matched { sentinel: M0Sentinel },
    HelperHashMismatch,
    ArgvMismatch,
}

#[derive(Clone, Copy, Debug)]
pub struct LoadProfileRequest<'a> {
    pub profile_path: Option<&'a Path>,
    pub compile_time_expected_digest: &'a str,
    pub trusted_source_root: &'a Path,
    pub target_project_root: &'a Path,
    pub expected_client: M0ProfileClient,
    pub expected_client_version: &'a str,
    pub expected_os: &'a str,
    pub expected_architecture: &'a str,
    pub observed_runtime_version_output: &'a str,
    pub observed_shell_resolution_fingerprint: &'a str,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProfileError {
    #[error("M0 test profile input is missing")]
    ProfileMissing,
    #[error("M0 test profile cannot be read")]
    ProfileUnreadable,
    #[error("M0 test profile digest is invalid")]
    ExpectedDigestInvalid,
    #[error("M0 test profile digest does not match the test artifact")]
    DigestMismatch {
        expected_digest: String,
        supplied_digest: String,
    },
    #[error("M0 test profile source is not trusted")]
    ProfileSourceUntrusted,
    #[error("M0 test profile is not strict UTF-8 JSON matching m0-test-profile/v1")]
    SchemaInvalid,
}

#[derive(Debug)]
pub struct LoadedM0TestProfile {
    profile: M0TestProfile,
    supplied_digest: String,
    trusted_source_root: PathBuf,
}

impl LoadedM0TestProfile {
    pub fn client(&self) -> M0ProfileClient {
        self.profile.client
    }

    pub fn supplied_digest(&self) -> &str {
        &self.supplied_digest
    }

    pub fn client_version(&self) -> &str {
        &self.profile.client_version
    }

    pub fn fixture_runtime_path(&self) -> &Path {
        &self.profile.fixture_runtime.executable_path
    }

    pub fn shell_executable_path(&self) -> &Path {
        &self.profile.shell_binding.executable_path
    }

    pub fn shell_flags(&self) -> &[String] {
        &self.profile.shell_binding.flags
    }

    pub fn shell_dialect(&self) -> &str {
        &self.profile.shell_binding.dialect
    }

    pub fn shell_resolution_fingerprint(&self) -> &str {
        &self.profile.shell_binding.resolution_fingerprint
    }

    pub fn match_command(
        &self,
        command_text: &str,
        test_run_id: &str,
        test_case_id: &str,
    ) -> BindingResult {
        let Some(tokens) = exact_posix_tokens(command_text) else {
            return BindingResult::ArgvMismatch;
        };
        if !is_safe_path_component(test_run_id) || !is_safe_path_component(test_case_id) {
            return BindingResult::ArgvMismatch;
        }
        if tokens[0]
            != self
                .profile
                .fixture_runtime
                .executable_path
                .to_string_lossy()
        {
            return BindingResult::ArgvMismatch;
        }

        let Some(helper) = self.profile.helpers.iter().find(|helper| {
            tokens[1]
                == self
                    .trusted_source_root
                    .join(&helper.relative_path)
                    .to_string_lossy()
        }) else {
            return BindingResult::ArgvMismatch;
        };
        let Some(sentinel) = parse_sentinel(tokens[2]) else {
            return BindingResult::ArgvMismatch;
        };
        if !helper.allowed_sentinels.contains(&sentinel) {
            return BindingResult::ArgvMismatch;
        }

        let expected_marker = self
            .trusted_source_root
            .join(&self.profile.marker_root_relative)
            .join(test_run_id)
            .join(format!("{test_case_id}.marker"));
        if tokens[3] != expected_marker.to_string_lossy()
            || ensure_physical_existing_prefix(&expected_marker).is_err()
        {
            return BindingResult::ArgvMismatch;
        }

        let helper_path = self.trusted_source_root.join(&helper.relative_path);
        if require_private_file(&helper_path).is_err()
            || validate_digest_bounded(&helper_path, &helper.content_sha256, MAX_HELPER_BYTES)
                .is_err()
        {
            return BindingResult::HelperHashMismatch;
        }

        BindingResult::Matched { sentinel }
    }
}

pub fn load_profile(request: LoadProfileRequest<'_>) -> Result<LoadedM0TestProfile, ProfileError> {
    if !is_sha256_label(request.compile_time_expected_digest) {
        return Err(ProfileError::ExpectedDigestInvalid);
    }
    require_private_directory(request.trusted_source_root)
        .map_err(|_| ProfileError::ProfileSourceUntrusted)?;
    let profile_path = request.profile_path.ok_or(ProfileError::ProfileMissing)?;
    require_private_parent_directories(profile_path, request.trusted_source_root)?;
    require_private_file(profile_path).map_err(|_| ProfileError::ProfileSourceUntrusted)?;
    let profile_file =
        read_bounded(profile_path, MAX_PROFILE_BYTES).map_err(|error| match error {
            PhysicalFileError::PathInvalid => ProfileError::ProfileSourceUntrusted,
            PhysicalFileError::SizeLimitExceeded | PhysicalFileError::DigestMismatch => {
                ProfileError::ProfileUnreadable
            }
        })?;
    let bytes = profile_file.bytes;
    let supplied_digest = profile_file.sha256;
    if supplied_digest != request.compile_time_expected_digest {
        return Err(ProfileError::DigestMismatch {
            expected_digest: request.compile_time_expected_digest.to_owned(),
            supplied_digest,
        });
    }

    ensure_trusted_profile_source(
        profile_path,
        request.trusted_source_root,
        request.target_project_root,
    )?;
    validate_document_bytes(&bytes)?;
    let profile: M0TestProfile = serde_json::from_slice(&bytes[..bytes.len() - 1])
        .map_err(|_| ProfileError::SchemaInvalid)?;
    validate_profile(&profile, &request)?;

    Ok(LoadedM0TestProfile {
        profile,
        supplied_digest,
        trusted_source_root: request.trusted_source_root.to_owned(),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct M0TestProfile {
    schema_version: String,
    build_flavor: String,
    client: M0ProfileClient,
    client_version: String,
    os: OperatingSystem,
    architecture: Architecture,
    fixture_runtime: FixtureRuntime,
    shell_binding: ShellBinding,
    helpers: Vec<Helper>,
    marker_root_relative: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum OperatingSystem {
    Macos,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum Architecture {
    #[serde(rename = "arm64")]
    Arm64,
    #[serde(rename = "x86_64")]
    X86_64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRuntime {
    executable_path: PathBuf,
    executable_sha256: String,
    version_output: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShellBinding {
    executable_path: PathBuf,
    executable_sha256: String,
    flags: Vec<String>,
    dialect: String,
    resolution_fingerprint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Helper {
    role: HelperRole,
    relative_path: PathBuf,
    content_sha256: String,
    command_grammar: String,
    allowed_sentinels: Vec<M0Sentinel>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum HelperRole {
    Default,
    Failure,
}

fn validate_document_bytes(bytes: &[u8]) -> Result<(), ProfileError> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf])
        || bytes.len() < 3
        || !bytes.ends_with(b"}\n")
        || std::str::from_utf8(bytes).is_err()
    {
        return Err(ProfileError::SchemaInvalid);
    }
    Ok(())
}

fn validate_profile(
    profile: &M0TestProfile,
    request: &LoadProfileRequest<'_>,
) -> Result<(), ProfileError> {
    if profile.schema_version != PROFILE_SCHEMA
        || profile.build_flavor != TEST_BUILD_FLAVOR
        || profile.client != request.expected_client
        || profile.client_version != request.expected_client_version
        || operating_system_name(profile.os) != request.expected_os
        || architecture_name(profile.architecture) != request.expected_architecture
        || profile.client_version.is_empty()
        || profile.client_version.chars().any(char::is_control)
        || profile.fixture_runtime.version_output.is_empty()
        || profile
            .fixture_runtime
            .version_output
            .chars()
            .any(char::is_control)
        || !is_sha256_label(&profile.fixture_runtime.executable_sha256)
        || !is_sha256_label(&profile.shell_binding.executable_sha256)
        || !is_sha256_label(&profile.shell_binding.resolution_fingerprint)
        || profile.shell_binding.dialect != "posix_sh"
        || profile.shell_binding.flags.is_empty()
        || profile
            .shell_binding
            .flags
            .iter()
            .any(|flag| flag.is_empty() || flag.chars().any(char::is_control))
        || profile.fixture_runtime.version_output != request.observed_runtime_version_output
        || profile.shell_binding.resolution_fingerprint
            != request.observed_shell_resolution_fingerprint
        || profile.helpers.len() != 2
        || profile.helpers[0].role != HelperRole::Default
        || profile.helpers[1].role != HelperRole::Failure
        || profile.helpers[0].allowed_sentinels
            != [M0Sentinel::High, M0Sentinel::Low, M0Sentinel::Info]
        || profile.helpers[1].allowed_sentinels != [M0Sentinel::Low, M0Sentinel::Info]
    {
        return Err(ProfileError::SchemaInvalid);
    }

    for path in [
        &profile.fixture_runtime.executable_path,
        &profile.shell_binding.executable_path,
    ] {
        ensure_physical_file(path).map_err(|_| ProfileError::SchemaInvalid)?;
        if !is_safe_path_token(path) {
            return Err(ProfileError::SchemaInvalid);
        }
    }
    validate_digest_bounded(
        &profile.fixture_runtime.executable_path,
        &profile.fixture_runtime.executable_sha256,
        MAX_RUNTIME_BYTES,
    )
    .map_err(|_| ProfileError::SchemaInvalid)?;
    validate_digest_bounded(
        &profile.shell_binding.executable_path,
        &profile.shell_binding.executable_sha256,
        MAX_RUNTIME_BYTES,
    )
    .map_err(|_| ProfileError::SchemaInvalid)?;

    for helper in &profile.helpers {
        if helper.command_grammar != POSIX_ARGV4_GRAMMAR
            || !is_sha256_label(&helper.content_sha256)
            || !is_safe_relative_path(&helper.relative_path)
        {
            return Err(ProfileError::SchemaInvalid);
        }
        let helper_path = request.trusted_source_root.join(&helper.relative_path);
        require_private_parent_directories(&helper_path, request.trusted_source_root)?;
        require_private_file(&helper_path).map_err(|_| ProfileError::ProfileSourceUntrusted)?;
        ensure_physical_file(&helper_path).map_err(|_| ProfileError::SchemaInvalid)?;
        ensure_trusted_asset(
            &helper_path,
            request.trusted_source_root,
            request.target_project_root,
        )?;
        validate_digest_bounded(&helper_path, &helper.content_sha256, MAX_HELPER_BYTES)
            .map_err(|_| ProfileError::SchemaInvalid)?;
    }

    if !is_safe_relative_path(&profile.marker_root_relative) {
        return Err(ProfileError::SchemaInvalid);
    }
    let marker_root = request
        .trusted_source_root
        .join(&profile.marker_root_relative);
    require_private_directory_chain(&marker_root, request.trusted_source_root)?;
    ensure_physical_directory(&marker_root).map_err(|_| ProfileError::SchemaInvalid)?;
    ensure_trusted_asset(
        &marker_root,
        request.trusted_source_root,
        request.target_project_root,
    )?;

    Ok(())
}

fn operating_system_name(value: OperatingSystem) -> &'static str {
    match value {
        OperatingSystem::Macos => "macos",
    }
}

fn architecture_name(value: Architecture) -> &'static str {
    match value {
        Architecture::Arm64 => "arm64",
        Architecture::X86_64 => "x86_64",
    }
}

fn ensure_trusted_profile_source(
    profile_path: &Path,
    trusted_source_root: &Path,
    target_project_root: &Path,
) -> Result<(), ProfileError> {
    ensure_trusted_asset(profile_path, trusted_source_root, target_project_root)
}

fn require_private_parent_directories(
    path: &Path,
    trusted_source_root: &Path,
) -> Result<(), ProfileError> {
    let parent = path.parent().ok_or(ProfileError::ProfileSourceUntrusted)?;
    require_private_directory_chain(parent, trusted_source_root)
}

fn require_private_directory_chain(
    directory: &Path,
    trusted_source_root: &Path,
) -> Result<(), ProfileError> {
    let relative = directory
        .strip_prefix(trusted_source_root)
        .map_err(|_| ProfileError::ProfileSourceUntrusted)?;
    let mut current = trusted_source_root.to_owned();
    require_private_directory(&current).map_err(|_| ProfileError::ProfileSourceUntrusted)?;
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(ProfileError::ProfileSourceUntrusted);
        };
        current.push(component);
        require_private_directory(&current).map_err(|_| ProfileError::ProfileSourceUntrusted)?;
    }
    Ok(())
}

fn ensure_trusted_asset(
    path: &Path,
    trusted_source_root: &Path,
    target_project_root: &Path,
) -> Result<(), ProfileError> {
    ensure_physical_existing_prefix(trusted_source_root)
        .map_err(|_| ProfileError::ProfileSourceUntrusted)?;
    ensure_physical_existing_prefix(target_project_root)
        .map_err(|_| ProfileError::ProfileSourceUntrusted)?;
    let path = fs::canonicalize(path).map_err(|_| ProfileError::ProfileSourceUntrusted)?;
    let trusted =
        fs::canonicalize(trusted_source_root).map_err(|_| ProfileError::ProfileSourceUntrusted)?;
    let target =
        fs::canonicalize(target_project_root).map_err(|_| ProfileError::ProfileSourceUntrusted)?;
    if !path.starts_with(&trusted) || path.starts_with(&target) {
        return Err(ProfileError::ProfileSourceUntrusted);
    }
    Ok(())
}

fn ensure_physical_file(path: &Path) -> Result<(), ()> {
    ensure_physical_existing_prefix(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_file() {
        return Err(());
    }
    Ok(())
}

fn ensure_physical_directory(path: &Path) -> Result<(), ()> {
    ensure_physical_existing_prefix(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_dir() {
        return Err(());
    }
    Ok(())
}

fn ensure_physical_existing_prefix(path: &Path) -> Result<(), ()> {
    if !path.is_absolute() {
        return Err(());
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir | Component::ParentDir => return Err(()),
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Err(()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

fn exact_posix_tokens(command_text: &str) -> Option<[&str; 4]> {
    if command_text.is_empty()
        || !command_text.is_ascii()
        || command_text.bytes().any(is_forbidden_command_byte)
    {
        return None;
    }
    let mut tokens = command_text.split(' ');
    let parsed = [
        tokens.next()?,
        tokens.next()?,
        tokens.next()?,
        tokens.next()?,
    ];
    if tokens.next().is_some() || parsed.iter().any(|token| token.is_empty()) {
        return None;
    }
    Some(parsed)
}

fn is_safe_path_token(path: &Path) -> bool {
    path.to_str().is_some_and(is_safe_token) && path.is_absolute()
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.is_absolute()
        && path.to_str().is_some_and(is_safe_token)
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_safe_path_component(value: &str) -> bool {
    let mut components = Path::new(value).components();
    is_safe_token(value)
        && matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
}

fn is_safe_token(token: &str) -> bool {
    !token.is_empty()
        && token.is_ascii()
        && token
            .bytes()
            .all(|byte| byte != b' ' && !is_forbidden_command_byte(byte))
}

fn is_forbidden_command_byte(byte: u8) -> bool {
    byte.is_ascii_control()
        || matches!(
            byte,
            b'"' | b'\'' | b'`' | b'\\' | b';' | b'&' | b'|' | b'<' | b'>' | b'(' | b')' | b'$'
        )
}

fn parse_sentinel(value: &str) -> Option<M0Sentinel> {
    match value {
        "high" => Some(M0Sentinel::High),
        "low" => Some(M0Sentinel::Low),
        "info" => Some(M0Sentinel::Info),
        _ => None,
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

pub fn embedded_profile_bytes(client: M0ProfileClient) -> &'static [u8] {
    match client {
        M0ProfileClient::Claude => {
            include_bytes!("../tests/fixtures/m0/profiles/claude-2.1.220-macos-arm64.json")
        }
        M0ProfileClient::Codex => {
            include_bytes!("../tests/fixtures/m0/profiles/codex-0.146.0-macos-arm64.json")
        }
    }
}

pub fn embedded_profile_digest(client: M0ProfileClient) -> String {
    sha256_label(embedded_profile_bytes(client))
}
