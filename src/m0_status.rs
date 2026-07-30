#![cfg(feature = "m0-test-profile")]

use crate::m0::{Client, M0EventType};
use crate::strict_json::{canonical_bytes, required_nullable};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;
use thiserror::Error;

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactKind {
    Test,
    Production,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ScopeFixture {
    #[serde(rename = "ON")]
    On,
    #[serde(rename = "OFF")]
    Off,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginState {
    InstalledEnabled,
    InstalledDisabled,
    NotInstalled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchMode {
    Normal,
    Unknown,
    ClaudeBare,
    ClaudeSimple,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexHooksFeature {
    Enabled,
    Disabled,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingSource {
    CodexUserConfig,
    CodexProjectConfig,
    ClaudeUserSettings,
    ClaudeProjectSettings,
    ClaudeLocalSettings,
    ClaudeManagedSettings,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingClaim {
    CodexHooksFeatureEnabled,
    CodexHooksFeatureDisabled,
    ClaudeDisableAllHooksTrue,
    ClaudeDisableAllHooksFalse,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookSource {
    CodexUserPlugin,
    CodexUserConfig,
    CodexProjectConfig,
    ClaudeUserPlugin,
    ClaudeProjectPlugin,
    ClaudeLocalPlugin,
    ClaudeUserSettings,
    ClaudeProjectSettings,
    ClaudeLocalSettings,
    ClaudeManagedSettings,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookDisposition {
    LoadedActive,
    Skipped,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookReason {
    SelectedReviewedDefinition,
    SelectedEnabledSource,
    UnreviewedDefinition,
    ReviewedDigestStale,
    SessionPredatesReview,
    UntrustedProjectSource,
    HooksDisabled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductHookReview {
    Unverified,
    Verified,
    Stale,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    ExistingBeforeReview,
    NewAfterReview,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    NotRun,
    Passed,
    Failed,
    Stale,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceScope {
    Current,
    Historical,
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientTrust {
    Verified,
    Unverified,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EffectiveProtection {
    #[serde(rename = "VERIFIED_ACTIVE")]
    VerifiedActive,
    #[serde(rename = "OFF")]
    Off,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestProfileState {
    Loaded,
    Rejected,
    NotSupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestProfileRejectionReason {
    ProfileMissing,
    DigestMismatch,
    ProfileSourceUntrusted,
    ProductionNotSupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SentinelBindingResult {
    Matched,
    HelperHashMismatch,
    ArgvMismatch,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NextCheck {
    InstallPlugin,
    EnableHooks,
    ReviewCurrentHookDefinition,
    StartNewClientSession,
    RunStandaloneSelfTest,
    InspectClientHookStatus,
    VerifyEffectiveCwdBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientExecutable {
    pub invoked_path: String,
    pub resolved_path: String,
    pub sha256: String,
    pub version_output: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientRuntimeArtifactRole {
    ResolvedExecutable,
    NativeBackend,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientRuntimeArtifact {
    pub role: ClientRuntimeArtifactRole,
    pub absolute_path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SettingEvidence {
    pub source: SettingSource,
    pub source_digest: String,
    pub claim: SettingClaim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientModeEvidence {
    pub plugin_state: PluginState,
    pub launch_mode: LaunchMode,
    #[serde(deserialize_with = "required_nullable")]
    pub explicit_plugin_supplied: Option<bool>,
    #[serde(deserialize_with = "required_nullable")]
    pub disable_all_hooks: Option<bool>,
    pub codex_hooks_feature: CodexHooksFeature,
    pub setting_evidence: Vec<SettingEvidence>,
    #[serde(deserialize_with = "required_nullable")]
    pub evidence_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HookEvidence {
    pub source: HookSource,
    pub definition_digest: String,
    pub disposition: HookDisposition,
    pub reason: HookReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundCheck {
    pub status: CheckStatus,
    pub evidence_scope: EvidenceScope,
    #[serde(deserialize_with = "required_nullable")]
    pub session_fixture_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub hook_source: Option<HookSource>,
    #[serde(deserialize_with = "required_nullable")]
    pub hook_definition_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInspection {
    pub method: String,
    pub build_manifest_digest: String,
    pub bound_artifact_digest: String,
    pub forbidden_components: Vec<String>,
    pub forbidden_component_count: u64,
    pub black_box_profile_probe: String,
    pub production_emitted_m0_schema_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct M0ObjectCounts {
    pub hook_envelope: u64,
    pub m0_action_request: u64,
    pub m0_action_decision: u64,
    pub m0_event: u64,
    pub m0_status_report: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct M0CanonicalDigests {
    pub hook_envelope: Vec<String>,
    pub m0_action_request: Vec<String>,
    pub m0_action_decision: Vec<String>,
    pub m0_event: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct M0ForbiddenObservations {
    pub target_process_start_count: u64,
    pub target_marker_count: u64,
    pub operator_approval_count: u64,
    pub secure_onboard_approval_count: u64,
    pub uncorrelated_result_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct M0RunEvidence {
    pub object_counts: M0ObjectCounts,
    pub canonical_digests: M0CanonicalDigests,
    pub ordered_events: Vec<M0EventType>,
    pub observations: M0ForbiddenObservations,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct M0StatusReport {
    pub schema_version: String,
    pub phase: String,
    pub report_source: String,
    pub test_case_id: String,
    pub test_run_id: String,
    pub client: Client,
    #[serde(deserialize_with = "required_nullable")]
    pub client_version: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub plugin_version: Option<String>,
    pub os: OperatingSystem,
    pub architecture: Architecture,
    pub client_executable: ClientExecutable,
    pub client_runtime_artifact: ClientRuntimeArtifact,
    pub artifact_kind: ArtifactKind,
    pub artifact_digest: String,
    #[serde(deserialize_with = "required_nullable")]
    pub configured_scope_fixture: Option<ScopeFixture>,
    #[serde(deserialize_with = "required_nullable")]
    pub plugin_installed: Option<bool>,
    #[serde(deserialize_with = "required_nullable")]
    pub hooks_enabled: Option<bool>,
    pub client_mode_evidence: ClientModeEvidence,
    #[serde(deserialize_with = "required_nullable")]
    pub session_fixture_id: Option<String>,
    pub session_state: SessionState,
    pub hook_evidence: Vec<HookEvidence>,
    #[serde(deserialize_with = "required_nullable")]
    pub bundled_hook_definition_digest: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub reviewed_hook_definition_digest: Option<String>,
    pub product_hook_review: ProductHookReview,
    pub heartbeat: BoundCheck,
    pub self_test: BoundCheck,
    pub client_trust: ClientTrust,
    pub effective_protection: EffectiveProtection,
    pub test_profile: TestProfileState,
    #[serde(deserialize_with = "required_nullable")]
    pub test_profile_expected_digest: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub test_profile_supplied_digest: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub test_profile_rejection_reason: Option<TestProfileRejectionReason>,
    pub sentinel_binding_result: SentinelBindingResult,
    pub next_checks: Vec<NextCheck>,
    #[serde(deserialize_with = "required_nullable")]
    pub run_evidence: Option<M0RunEvidence>,
    #[serde(deserialize_with = "required_nullable")]
    pub artifact_inspection: Option<ArtifactInspection>,
    pub reasons: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OsStringEncoding {
    UnixBytes,
    WindowsUtf16le,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelevantEnvironment {
    pub name_base64url: String,
    #[serde(deserialize_with = "required_nullable")]
    pub value_base64url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrderedSettingSource {
    pub source: SettingSource,
    pub source_bytes_base64url: String,
    pub claim: SettingClaim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientModeEvidenceInput {
    pub os_string_encoding: OsStringEncoding,
    pub launch_argv_base64url: Vec<String>,
    pub relevant_environment: Vec<RelevantEnvironment>,
    #[serde(deserialize_with = "required_nullable")]
    pub plugin_list_output_base64url: Option<String>,
    pub ordered_setting_sources: Vec<OrderedSettingSource>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum StatusError {
    #[error("invalid common status fields")]
    Common,
    #[error("client executable evidence is invalid")]
    ClientExecutable,
    #[error("client mode evidence is invalid")]
    ModeEvidence,
    #[error("status uses evidence from another client")]
    ClientSource,
    #[error("hook/session evidence is inconsistent")]
    SessionEvidence,
    #[error("effective protection is inconsistent")]
    EffectiveProtection,
    #[error("test profile state is inconsistent")]
    TestProfile,
    #[error("production artifact inspection is inconsistent")]
    ArtifactInspection,
    #[error("M0 run evidence is inconsistent")]
    RunEvidence,
}

pub fn client_mode_evidence_digest(input: &ClientModeEvidenceInput) -> Result<String, StatusError> {
    validate_base64_input(input)?;
    let canonical = canonical_bytes(input).map_err(|_| StatusError::ModeEvidence)?;
    let mut hasher = Sha256::new();
    hasher.update(b"secure-onboard:m0-client-mode-evidence/v1\n");
    hasher.update(canonical);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub fn validate_status(
    report: &M0StatusReport,
    mode_input: Option<&ClientModeEvidenceInput>,
) -> Result<(), StatusError> {
    validate_common(report)?;
    validate_mode(report, mode_input)?;
    validate_hooks_and_session(report)?;
    validate_effective_protection(report)?;
    validate_profile_state(report)?;
    validate_artifact_inspection(report)?;
    validate_run_evidence(report)
}

fn validate_common(report: &M0StatusReport) -> Result<(), StatusError> {
    if report.schema_version != "m0-status-report/v1"
        || report.phase != "m0"
        || report.report_source != "test_harness"
        || report.test_case_id.is_empty()
        || report.test_run_id.is_empty()
        || !is_sha256_label(&report.artifact_digest)
        || !Path::new(&report.client_executable.invoked_path).is_absolute()
        || !Path::new(&report.client_executable.resolved_path).is_absolute()
        || !is_sha256_label(&report.client_executable.sha256)
        || !Path::new(&report.client_runtime_artifact.absolute_path).is_absolute()
        || !is_sha256_label(&report.client_runtime_artifact.sha256)
    {
        return Err(StatusError::Common);
    }
    match report.client {
        Client::Claude
            if report.client_runtime_artifact.role
                == ClientRuntimeArtifactRole::ResolvedExecutable
                && report.client_runtime_artifact.absolute_path
                    == report.client_executable.resolved_path
                && report.client_runtime_artifact.sha256 == report.client_executable.sha256 => {}
        Client::Codex
            if report.client_runtime_artifact.role == ClientRuntimeArtifactRole::NativeBackend => {}
        _ => return Err(StatusError::ClientExecutable),
    }
    let parsed_version = match report.client {
        Client::Codex => report
            .client_executable
            .version_output
            .strip_prefix("codex-cli "),
        Client::Claude => report
            .client_executable
            .version_output
            .strip_suffix(" (Claude Code)"),
    };
    match (
        report.client_version.as_deref(),
        parsed_version.filter(|version| !version.is_empty()),
    ) {
        (Some(expected), Some(parsed)) if expected == parsed => Ok(()),
        (None, None) => Ok(()),
        _ => Err(StatusError::ClientExecutable),
    }
}

fn validate_mode(
    report: &M0StatusReport,
    mode_input: Option<&ClientModeEvidenceInput>,
) -> Result<(), StatusError> {
    let mode = &report.client_mode_evidence;
    let client_shape = match report.client {
        Client::Codex => {
            matches!(mode.launch_mode, LaunchMode::Normal | LaunchMode::Unknown)
                && mode.explicit_plugin_supplied.is_none()
                && mode.disable_all_hooks.is_none()
                && mode.codex_hooks_feature != CodexHooksFeature::NotApplicable
        }
        Client::Claude => {
            matches!(
                mode.launch_mode,
                LaunchMode::Normal
                    | LaunchMode::Unknown
                    | LaunchMode::ClaudeBare
                    | LaunchMode::ClaudeSimple
            ) && mode.codex_hooks_feature == CodexHooksFeature::NotApplicable
        }
    };
    if !client_shape {
        return Err(StatusError::ModeEvidence);
    }
    if mode
        .setting_evidence
        .windows(2)
        .any(|pair| setting_precedence(pair[0].source) >= setting_precedence(pair[1].source))
    {
        return Err(StatusError::ModeEvidence);
    }

    for setting in &mode.setting_evidence {
        if !setting_source_for_client(setting.source, report.client)
            || !setting_claim_for_client(setting.claim, report.client)
            || !is_sha256_label(&setting.source_digest)
        {
            return Err(StatusError::ClientSource);
        }
    }
    if let Some(first) = mode.setting_evidence.first() {
        match (report.client, first.claim) {
            (Client::Codex, SettingClaim::CodexHooksFeatureEnabled)
                if mode.codex_hooks_feature == CodexHooksFeature::Enabled => {}
            (Client::Codex, SettingClaim::CodexHooksFeatureDisabled)
                if mode.codex_hooks_feature == CodexHooksFeature::Disabled => {}
            (Client::Claude, SettingClaim::ClaudeDisableAllHooksTrue)
                if mode.disable_all_hooks == Some(true) => {}
            (Client::Claude, SettingClaim::ClaudeDisableAllHooksFalse)
                if mode.disable_all_hooks == Some(false) => {}
            _ => return Err(StatusError::ModeEvidence),
        }
    }

    let observed = mode.plugin_state != PluginState::Unknown
        || mode.launch_mode != LaunchMode::Unknown
        || mode.explicit_plugin_supplied.is_some()
        || mode.disable_all_hooks.is_some()
        || !matches!(
            mode.codex_hooks_feature,
            CodexHooksFeature::Unknown | CodexHooksFeature::NotApplicable
        );
    match (observed, &mode.evidence_digest, mode_input) {
        (true, Some(expected), Some(input)) => {
            if input_encoding(input) != report.os
                || client_mode_evidence_digest(input)? != *expected
                || input.ordered_setting_sources.len() != mode.setting_evidence.len()
            {
                return Err(StatusError::ModeEvidence);
            }
            validate_input_client_environment(input, report.client)?;
            validate_launch_mode(input, report)?;
            for (raw, evidence) in input
                .ordered_setting_sources
                .iter()
                .zip(&mode.setting_evidence)
            {
                let bytes = decode_base64url(&raw.source_bytes_base64url)
                    .ok_or(StatusError::ModeEvidence)?;
                if raw.source != evidence.source
                    || raw.claim != evidence.claim
                    || sha256_label(&bytes) != evidence.source_digest
                    || derive_setting_claim(raw.source, &bytes) != Some(raw.claim)
                {
                    return Err(StatusError::ModeEvidence);
                }
            }
        }
        (false, None, None) => {}
        _ => return Err(StatusError::ModeEvidence),
    }
    Ok(())
}

fn derive_setting_claim(source: SettingSource, bytes: &[u8]) -> Option<SettingClaim> {
    match source {
        SettingSource::CodexUserConfig | SettingSource::CodexProjectConfig => {
            derive_codex_hooks_claim(bytes)
        }
        SettingSource::ClaudeUserSettings
        | SettingSource::ClaudeProjectSettings
        | SettingSource::ClaudeLocalSettings
        | SettingSource::ClaudeManagedSettings => {
            let value: serde_json::Value = crate::strict_json::from_slice(bytes).ok()?;
            match value.get("disableAllHooks")?.as_bool()? {
                true => Some(SettingClaim::ClaudeDisableAllHooksTrue),
                false => Some(SettingClaim::ClaudeDisableAllHooksFalse),
            }
        }
    }
}

fn derive_codex_hooks_claim(bytes: &[u8]) -> Option<SettingClaim> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut in_features = false;
    let mut hooks = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_features = line == "[features]";
            continue;
        }
        if in_features {
            let value = line.strip_prefix("hooks")?.trim_start();
            let value = value.strip_prefix('=')?.trim();
            let parsed = match value {
                "true" => true,
                "false" => false,
                _ => return None,
            };
            if hooks.replace(parsed).is_some() {
                return None;
            }
        }
    }
    match hooks? {
        true => Some(SettingClaim::CodexHooksFeatureEnabled),
        false => Some(SettingClaim::CodexHooksFeatureDisabled),
    }
}

fn validate_launch_mode(
    input: &ClientModeEvidenceInput,
    report: &M0StatusReport,
) -> Result<(), StatusError> {
    if report.os != OperatingSystem::Macos {
        return Err(StatusError::ModeEvidence);
    }
    let argv = input
        .launch_argv_base64url
        .iter()
        .map(|value| decode_base64url(value).ok_or(StatusError::ModeEvidence))
        .collect::<Result<Vec<_>, _>>()?;
    match report.client {
        Client::Codex => {
            if report.client_mode_evidence.launch_mode != LaunchMode::Normal {
                return Err(StatusError::ModeEvidence);
            }
        }
        Client::Claude => {
            let bare = argv.iter().skip(1).any(|argument| argument == b"--bare");
            let explicit_plugin = explicit_plugin_flag(&argv)?;
            let simple = input.relevant_environment.iter().any(|variable| {
                decode_base64url(&variable.name_base64url).as_deref() == Some(b"CLAUDE_CODE_SIMPLE")
                    && variable
                        .value_base64url
                        .as_ref()
                        .and_then(|value| decode_base64url(value))
                        .as_deref()
                        == Some(b"1")
            });
            if bare && simple {
                return Err(StatusError::ModeEvidence);
            }
            let expected = if bare {
                LaunchMode::ClaudeBare
            } else if simple {
                LaunchMode::ClaudeSimple
            } else {
                LaunchMode::Normal
            };
            if report.client_mode_evidence.launch_mode != expected {
                return Err(StatusError::ModeEvidence);
            }
            if matches!(expected, LaunchMode::ClaudeBare | LaunchMode::ClaudeSimple)
                && report.client_mode_evidence.explicit_plugin_supplied != Some(explicit_plugin)
            {
                return Err(StatusError::ModeEvidence);
            }
        }
    }
    Ok(())
}

fn explicit_plugin_flag(argv: &[Vec<u8>]) -> Result<bool, StatusError> {
    let mut found = false;
    let mut index = 1;
    while index < argv.len() {
        let argument = argv[index].as_slice();
        if argument == b"--plugin-dir" {
            let Some(path) = argv.get(index + 1) else {
                return Err(StatusError::ModeEvidence);
            };
            if path.is_empty() || path.starts_with(b"-") {
                return Err(StatusError::ModeEvidence);
            }
            found = true;
            index += 2;
            continue;
        }
        if let Some(path) = argument.strip_prefix(b"--plugin-dir=") {
            if path.is_empty() {
                return Err(StatusError::ModeEvidence);
            }
            found = true;
        }
        index += 1;
    }
    Ok(found)
}

fn validate_hooks_and_session(report: &M0StatusReport) -> Result<(), StatusError> {
    if matches!(
        report.session_state,
        SessionState::ExistingBeforeReview | SessionState::NewAfterReview
    ) && report.session_fixture_id.is_none()
    {
        return Err(StatusError::SessionEvidence);
    }

    let mut loaded = Vec::new();
    for evidence in &report.hook_evidence {
        if !hook_source_for_client(evidence.source, report.client)
            || !is_sha256_label(&evidence.definition_digest)
        {
            return Err(StatusError::ClientSource);
        }
        if evidence.disposition == HookDisposition::LoadedActive {
            let expected_reason = match report.client {
                Client::Codex => HookReason::SelectedReviewedDefinition,
                Client::Claude => HookReason::SelectedEnabledSource,
            };
            if evidence.reason != expected_reason {
                return Err(StatusError::SessionEvidence);
            }
            loaded.push(evidence);
        }
    }
    validate_bound_check(report, &report.heartbeat, &loaded)?;
    validate_bound_check(report, &report.self_test, &loaded)?;

    if report.client == Client::Claude
        && report.product_hook_review != ProductHookReview::NotApplicable
    {
        return Err(StatusError::SessionEvidence);
    }
    if report.client == Client::Codex && report.product_hook_review == ProductHookReview::Verified {
        let (Some(bundled), Some(reviewed)) = (
            &report.bundled_hook_definition_digest,
            &report.reviewed_hook_definition_digest,
        ) else {
            return Err(StatusError::SessionEvidence);
        };
        if bundled != reviewed || !is_sha256_label(bundled) {
            return Err(StatusError::SessionEvidence);
        }
    }
    if report.client == Client::Codex && report.product_hook_review == ProductHookReview::Stale {
        let (Some(bundled), Some(reviewed)) = (
            &report.bundled_hook_definition_digest,
            &report.reviewed_hook_definition_digest,
        ) else {
            return Err(StatusError::SessionEvidence);
        };
        if !is_sha256_label(bundled) || !is_sha256_label(reviewed) || bundled == reviewed {
            return Err(StatusError::SessionEvidence);
        }
    }
    validate_codex_review_case(report)?;
    Ok(())
}

fn validate_codex_review_case(report: &M0StatusReport) -> Result<(), StatusError> {
    let bundled = report.bundled_hook_definition_digest.as_ref();
    let reviewed = report.reviewed_hook_definition_digest.as_ref();
    let user_hook_matches = |disposition, reason| {
        bundled.is_some_and(|digest| {
            report
                .hook_evidence
                .iter()
                .filter(|evidence| evidence.source == HookSource::CodexUserPlugin)
                .filter(|evidence| {
                    evidence.definition_digest == *digest
                        && evidence.disposition == disposition
                        && evidence.reason == reason
                })
                .count()
                == 1
        })
    };
    let checks_not_run = report.heartbeat.status == CheckStatus::NotRun
        && report.self_test.status == CheckStatus::NotRun;
    let valid = match report.test_case_id.as_str() {
        "T13" => {
            report.client == Client::Codex
                && report.client_trust == ClientTrust::Unknown
                && report.product_hook_review == ProductHookReview::Unverified
                && reviewed.is_none()
                && report.session_fixture_id.is_none()
                && report.session_state == SessionState::Unknown
                && checks_not_run
                && user_hook_matches(HookDisposition::Skipped, HookReason::UnreviewedDefinition)
        }
        "T14" => {
            report.client == Client::Codex
                && report.client_trust == ClientTrust::Unknown
                && report.product_hook_review == ProductHookReview::Verified
                && report.session_fixture_id.is_some()
                && report.session_state == SessionState::ExistingBeforeReview
                && checks_not_run
                && user_hook_matches(HookDisposition::Skipped, HookReason::SessionPredatesReview)
        }
        "T15" => {
            report.client == Client::Codex
                && report.client_trust == ClientTrust::Unknown
                && report.product_hook_review == ProductHookReview::Verified
                && report.session_fixture_id.is_some()
                && report.session_state == SessionState::NewAfterReview
                && report.heartbeat.status == CheckStatus::Passed
                && report.self_test.status == CheckStatus::Passed
                && user_hook_matches(
                    HookDisposition::LoadedActive,
                    HookReason::SelectedReviewedDefinition,
                )
        }
        "T16" => {
            report.client == Client::Codex
                && report.client_trust == ClientTrust::Unknown
                && report.product_hook_review == ProductHookReview::Stale
                && report.session_fixture_id.is_none()
                && report.session_state == SessionState::Unknown
                && user_hook_matches(HookDisposition::Skipped, HookReason::ReviewedDigestStale)
                && reviewed.is_some_and(|digest| {
                    [&report.heartbeat, &report.self_test].iter().all(|check| {
                        check.status == CheckStatus::Stale
                            && check.evidence_scope == EvidenceScope::Historical
                            && check.hook_source == Some(HookSource::CodexUserPlugin)
                            && check.hook_definition_digest.as_ref() == Some(digest)
                    })
                })
        }
        _ => true,
    };
    valid.then_some(()).ok_or(StatusError::SessionEvidence)
}

fn validate_bound_check(
    report: &M0StatusReport,
    check: &BoundCheck,
    loaded: &[&HookEvidence],
) -> Result<(), StatusError> {
    match (check.status, check.evidence_scope) {
        (CheckStatus::NotRun, EvidenceScope::None) => {
            if check.session_fixture_id.is_some()
                || check.hook_source.is_some()
                || check.hook_definition_digest.is_some()
            {
                return Err(StatusError::SessionEvidence);
            }
        }
        (CheckStatus::Passed, EvidenceScope::Current) => {
            let (Some(session), Some(source), Some(digest)) = (
                &check.session_fixture_id,
                check.hook_source,
                &check.hook_definition_digest,
            ) else {
                return Err(StatusError::SessionEvidence);
            };
            if report.session_fixture_id.as_ref() != Some(session)
                || loaded
                    .iter()
                    .filter(|evidence| {
                        evidence.source == source && evidence.definition_digest == *digest
                    })
                    .count()
                    != 1
            {
                return Err(StatusError::SessionEvidence);
            }
        }
        (CheckStatus::Stale, EvidenceScope::Historical) => {
            let (Some(session), Some(source), Some(digest)) = (
                &check.session_fixture_id,
                check.hook_source,
                &check.hook_definition_digest,
            ) else {
                return Err(StatusError::SessionEvidence);
            };
            if report.session_fixture_id.as_ref() == Some(session)
                || loaded.iter().any(|evidence| {
                    evidence.source == source && evidence.definition_digest == *digest
                })
            {
                return Err(StatusError::SessionEvidence);
            }
        }
        (CheckStatus::Failed, EvidenceScope::Current) => {
            if check.session_fixture_id.is_none()
                || check.hook_source.is_none()
                || check.hook_definition_digest.is_none()
            {
                return Err(StatusError::SessionEvidence);
            }
        }
        (CheckStatus::Failed, EvidenceScope::None) => {
            if check.session_fixture_id.is_some()
                || check.hook_source.is_some()
                || check.hook_definition_digest.is_some()
            {
                return Err(StatusError::SessionEvidence);
            }
        }
        _ => return Err(StatusError::SessionEvidence),
    }
    Ok(())
}

fn validate_effective_protection(report: &M0StatusReport) -> Result<(), StatusError> {
    let mode = &report.client_mode_evidence;
    let plugin_state_matches = match mode.plugin_state {
        PluginState::InstalledEnabled | PluginState::InstalledDisabled => {
            report.plugin_installed == Some(true)
        }
        PluginState::NotInstalled => {
            report.plugin_installed == Some(false) && report.plugin_version.is_none()
        }
        PluginState::Unknown => true,
    };
    if !plugin_state_matches {
        return Err(StatusError::EffectiveProtection);
    }
    if report
        .hook_evidence
        .iter()
        .any(|evidence| evidence.disposition == HookDisposition::LoadedActive)
        && report.hooks_enabled != Some(true)
    {
        return Err(StatusError::EffectiveProtection);
    }

    if report.configured_scope_fixture == Some(ScopeFixture::Off) {
        if report.effective_protection != EffectiveProtection::Off {
            return Err(StatusError::EffectiveProtection);
        }
        return Ok(());
    }

    let forced_off = mode.plugin_state == PluginState::NotInstalled
        || mode.plugin_state == PluginState::InstalledDisabled
        || mode.disable_all_hooks == Some(true)
        || (matches!(
            mode.launch_mode,
            LaunchMode::ClaudeBare | LaunchMode::ClaudeSimple
        ) && mode.explicit_plugin_supplied == Some(false))
        || mode.codex_hooks_feature == CodexHooksFeature::Disabled;
    if forced_off {
        if report
            .hook_evidence
            .iter()
            .any(|evidence| evidence.disposition == HookDisposition::LoadedActive)
        {
            return Err(StatusError::EffectiveProtection);
        }
        let top_level = match mode.plugin_state {
            PluginState::NotInstalled => {
                report.plugin_installed == Some(false)
                    && report.plugin_version.is_none()
                    && report.hooks_enabled == Some(false)
            }
            PluginState::InstalledDisabled => {
                report.plugin_installed == Some(true) && report.hooks_enabled == Some(false)
            }
            _ => report.hooks_enabled == Some(false),
        };
        if !top_level || report.effective_protection != EffectiveProtection::Off {
            return Err(StatusError::EffectiveProtection);
        }
        return Ok(());
    }

    match report.effective_protection {
        EffectiveProtection::VerifiedActive => {
            let expected_hook_source = match report.client {
                Client::Claude => HookSource::ClaudeUserPlugin,
                Client::Codex => HookSource::CodexUserPlugin,
            };
            let supported_client_version = match report.client {
                Client::Claude => report.client_version.as_deref() == Some("2.1.220"),
                Client::Codex => report.client_version.as_deref() == Some("0.146.0"),
            };
            if report.configured_scope_fixture != Some(ScopeFixture::On)
                || !supported_client_version
                || report.plugin_installed != Some(true)
                || report.plugin_version.as_deref() != Some("0.1.0")
                || report.hooks_enabled != Some(true)
                || mode.plugin_state != PluginState::InstalledEnabled
                || mode.launch_mode != LaunchMode::Normal
                || mode.evidence_digest.is_none()
                || report.session_state != SessionState::NewAfterReview
                || report.heartbeat.status != CheckStatus::Passed
                || report.self_test.status != CheckStatus::Passed
                || report.heartbeat.session_fixture_id != report.self_test.session_fixture_id
                || report.heartbeat.hook_source != report.self_test.hook_source
                || report.heartbeat.hook_definition_digest
                    != report.self_test.hook_definition_digest
                || report.heartbeat.hook_source != Some(expected_hook_source)
                || (report.client == Client::Codex
                    && report.heartbeat.hook_definition_digest.as_ref()
                        != report.bundled_hook_definition_digest.as_ref())
                || (report.client == Client::Codex
                    && mode.codex_hooks_feature != CodexHooksFeature::Enabled)
                || (report.client == Client::Codex
                    && report.product_hook_review != ProductHookReview::Verified)
            {
                return Err(StatusError::EffectiveProtection);
            }
        }
        EffectiveProtection::Unknown => {
            if report.next_checks.is_empty() {
                return Err(StatusError::EffectiveProtection);
            }
        }
        EffectiveProtection::Off => return Err(StatusError::EffectiveProtection),
    }
    Ok(())
}

fn validate_profile_state(report: &M0StatusReport) -> Result<(), StatusError> {
    if matches!(
        report.test_case_id.as_str(),
        "T19-A-HIGH" | "T19-A-LOW" | "T19-A-INFO"
    ) && report.sentinel_binding_result != SentinelBindingResult::Matched
    {
        return Err(StatusError::TestProfile);
    }
    if report.test_case_id == "T19-B-HELPER"
        && report.sentinel_binding_result != SentinelBindingResult::HelperHashMismatch
    {
        return Err(StatusError::TestProfile);
    }
    if report.test_case_id == "T19-B-ARGV"
        && report.sentinel_binding_result != SentinelBindingResult::ArgvMismatch
    {
        return Err(StatusError::TestProfile);
    }
    if report.test_case_id == "T19-B-MISSING"
        && (report.test_profile_supplied_digest.is_some()
            || report.test_profile_rejection_reason
                != Some(TestProfileRejectionReason::ProfileMissing))
    {
        return Err(StatusError::TestProfile);
    }
    if report.test_case_id == "T19-B-DIGEST"
        && report.test_profile_rejection_reason != Some(TestProfileRejectionReason::DigestMismatch)
    {
        return Err(StatusError::TestProfile);
    }
    if report.test_case_id == "T19-B-SOURCE"
        && report.test_profile_rejection_reason
            != Some(TestProfileRejectionReason::ProfileSourceUntrusted)
    {
        return Err(StatusError::TestProfile);
    }

    match report.artifact_kind {
        ArtifactKind::Test => {
            let Some(expected) = &report.test_profile_expected_digest else {
                return Err(StatusError::TestProfile);
            };
            if !is_sha256_label(expected) {
                return Err(StatusError::TestProfile);
            }
            match (
                report.test_profile,
                report.test_profile_supplied_digest.as_ref(),
                report.test_profile_rejection_reason,
                report.sentinel_binding_result,
            ) {
                (
                    TestProfileState::Loaded,
                    Some(supplied),
                    None,
                    SentinelBindingResult::Matched
                    | SentinelBindingResult::HelperHashMismatch
                    | SentinelBindingResult::ArgvMismatch
                    | SentinelBindingResult::NotEvaluated,
                ) if supplied == expected => Ok(()),
                (
                    TestProfileState::Rejected,
                    None,
                    Some(TestProfileRejectionReason::ProfileMissing),
                    SentinelBindingResult::NotEvaluated,
                ) => Ok(()),
                (
                    TestProfileState::Rejected,
                    Some(supplied),
                    Some(TestProfileRejectionReason::DigestMismatch),
                    SentinelBindingResult::NotEvaluated,
                ) if is_sha256_label(supplied) && supplied != expected => Ok(()),
                (
                    TestProfileState::Rejected,
                    Some(supplied),
                    Some(TestProfileRejectionReason::ProfileSourceUntrusted),
                    SentinelBindingResult::NotEvaluated,
                ) if supplied == expected => Ok(()),
                _ => Err(StatusError::TestProfile),
            }
        }
        ArtifactKind::Production => {
            if report.test_profile == TestProfileState::NotSupported
                && report.test_profile_expected_digest.is_none()
                && report
                    .test_profile_supplied_digest
                    .as_ref()
                    .is_some_and(|digest| is_sha256_label(digest))
                && report.test_profile_rejection_reason
                    == Some(TestProfileRejectionReason::ProductionNotSupported)
                && report.sentinel_binding_result == SentinelBindingResult::NotEvaluated
            {
                Ok(())
            } else {
                Err(StatusError::TestProfile)
            }
        }
    }
}

fn validate_artifact_inspection(report: &M0StatusReport) -> Result<(), StatusError> {
    match (report.artifact_kind, &report.artifact_inspection) {
        (ArtifactKind::Test, None) => Ok(()),
        (ArtifactKind::Production, Some(inspection))
            if report.test_case_id == "T19-C"
                && inspection.method == "bound-build-manifest-plus-black-box-profile-probe/v1"
                && is_sha256_label(&inspection.build_manifest_digest)
                && inspection.bound_artifact_digest == report.artifact_digest
                && inspection.forbidden_components
                    == [
                        "m0_test_profile_loader",
                        "m0_sentinel_rules",
                        "m0_status_constructor",
                    ]
                && inspection.forbidden_component_count == 0
                && inspection.black_box_profile_probe == "not_supported"
                && inspection.production_emitted_m0_schema_count == 0 =>
        {
            Ok(())
        }
        _ => Err(StatusError::ArtifactInspection),
    }
}

fn validate_run_evidence(report: &M0StatusReport) -> Result<(), StatusError> {
    let is_t19 = report.test_case_id.starts_with("T19-");
    if !is_t19 {
        return if report.run_evidence.is_none() {
            Ok(())
        } else {
            Err(StatusError::RunEvidence)
        };
    }
    let evidence = report
        .run_evidence
        .as_ref()
        .ok_or(StatusError::RunEvidence)?;
    let counts = &evidence.object_counts;
    let digests = &evidence.canonical_digests;
    if counts.m0_status_report != 1
        || digests.hook_envelope.len() as u64 != counts.hook_envelope
        || digests.m0_action_request.len() as u64 != counts.m0_action_request
        || digests.m0_action_decision.len() as u64 != counts.m0_action_decision
        || digests.m0_event.len() as u64 != counts.m0_event
        || digests
            .hook_envelope
            .iter()
            .chain(&digests.m0_action_request)
            .chain(&digests.m0_action_decision)
            .chain(&digests.m0_event)
            .any(|digest| !is_sha256_label(digest))
        || evidence.observations.secure_onboard_approval_count != 0
        || evidence.observations.uncorrelated_result_count != 0
    {
        return Err(StatusError::RunEvidence);
    }

    let expected = match (report.test_case_id.as_str(), report.client) {
        ("T19-A-HIGH", _) => (
            [1, 1, 1, 2],
            vec![M0EventType::HighDetected, M0EventType::HighBlocked],
            [0, 0, 0],
        ),
        ("T19-A-LOW", Client::Claude) => (
            [2, 1, 1, 2],
            vec![M0EventType::WarnedLow, M0EventType::ToolCompleted],
            [1, 1, 1],
        ),
        ("T19-A-INFO", Client::Claude) => (
            [2, 1, 1, 2],
            vec![M0EventType::AllowedInfo, M0EventType::ToolCompleted],
            [1, 1, 1],
        ),
        ("T19-A-LOW", Client::Codex) => ([1, 1, 1, 1], vec![M0EventType::WarnedLow], [1, 1, 1]),
        ("T19-A-INFO", Client::Codex) => ([1, 1, 1, 1], vec![M0EventType::AllowedInfo], [1, 1, 1]),
        ("T19-B-MISSING" | "T19-B-DIGEST" | "T19-B-SOURCE" | "T19-C", _) => {
            ([0, 0, 0, 0], vec![], [0, 0, 0])
        }
        ("T19-B-HELPER" | "T19-B-ARGV", Client::Claude) => ([2, 0, 0, 0], vec![], [1, 1, 1]),
        ("T19-B-HELPER" | "T19-B-ARGV", Client::Codex) => ([1, 0, 0, 0], vec![], [1, 1, 1]),
        _ => return Err(StatusError::RunEvidence),
    };
    if [
        counts.hook_envelope,
        counts.m0_action_request,
        counts.m0_action_decision,
        counts.m0_event,
    ] != expected.0
        || evidence.ordered_events != expected.1
        || [
            evidence.observations.target_process_start_count,
            evidence.observations.target_marker_count,
            evidence.observations.operator_approval_count,
        ] != expected.2
    {
        return Err(StatusError::RunEvidence);
    }
    Ok(())
}

fn validate_base64_input(input: &ClientModeEvidenceInput) -> Result<(), StatusError> {
    if input.launch_argv_base64url.is_empty()
        || input
            .launch_argv_base64url
            .iter()
            .any(|value| decode_base64url(value).is_none())
        || input.relevant_environment.iter().any(|value| {
            decode_base64url(&value.name_base64url).is_none()
                || value
                    .value_base64url
                    .as_ref()
                    .is_some_and(|raw| decode_base64url(raw).is_none())
        })
        || input
            .plugin_list_output_base64url
            .as_ref()
            .is_some_and(|value| decode_base64url(value).is_none())
        || input
            .ordered_setting_sources
            .iter()
            .any(|value| decode_base64url(&value.source_bytes_base64url).is_none())
    {
        return Err(StatusError::ModeEvidence);
    }
    let mut names = HashSet::new();
    for value in &input.relevant_environment {
        if !names.insert(decode_base64url(&value.name_base64url).expect("validated")) {
            return Err(StatusError::ModeEvidence);
        }
    }
    let mut sources = HashSet::new();
    if input
        .ordered_setting_sources
        .iter()
        .any(|value| !sources.insert(value.source))
    {
        return Err(StatusError::ModeEvidence);
    }
    Ok(())
}

fn validate_input_client_environment(
    input: &ClientModeEvidenceInput,
    client: Client,
) -> Result<(), StatusError> {
    match client {
        Client::Codex if input.relevant_environment.is_empty() => Ok(()),
        Client::Claude if input.relevant_environment.len() == 1 => {
            let name = decode_base64url(&input.relevant_environment[0].name_base64url)
                .ok_or(StatusError::ModeEvidence)?;
            if name == b"CLAUDE_CODE_SIMPLE" {
                Ok(())
            } else {
                Err(StatusError::ModeEvidence)
            }
        }
        _ => Err(StatusError::ModeEvidence),
    }
}

fn input_encoding(input: &ClientModeEvidenceInput) -> OperatingSystem {
    match input.os_string_encoding {
        OsStringEncoding::UnixBytes => OperatingSystem::Macos,
        OsStringEncoding::WindowsUtf16le => OperatingSystem::Windows,
    }
}

fn setting_source_for_client(source: SettingSource, client: Client) -> bool {
    matches!(
        (client, source),
        (
            Client::Codex,
            SettingSource::CodexUserConfig | SettingSource::CodexProjectConfig
        ) | (
            Client::Claude,
            SettingSource::ClaudeUserSettings
                | SettingSource::ClaudeProjectSettings
                | SettingSource::ClaudeLocalSettings
                | SettingSource::ClaudeManagedSettings
        )
    )
}

fn setting_precedence(source: SettingSource) -> u8 {
    match source {
        SettingSource::CodexProjectConfig | SettingSource::ClaudeManagedSettings => 0,
        SettingSource::ClaudeLocalSettings => 1,
        SettingSource::ClaudeProjectSettings => 2,
        SettingSource::CodexUserConfig | SettingSource::ClaudeUserSettings => 3,
    }
}

fn setting_claim_for_client(claim: SettingClaim, client: Client) -> bool {
    matches!(
        (client, claim),
        (
            Client::Codex,
            SettingClaim::CodexHooksFeatureEnabled | SettingClaim::CodexHooksFeatureDisabled
        ) | (
            Client::Claude,
            SettingClaim::ClaudeDisableAllHooksTrue | SettingClaim::ClaudeDisableAllHooksFalse
        )
    )
}

fn hook_source_for_client(source: HookSource, client: Client) -> bool {
    matches!(
        (client, source),
        (
            Client::Codex,
            HookSource::CodexUserPlugin
                | HookSource::CodexUserConfig
                | HookSource::CodexProjectConfig
        ) | (
            Client::Claude,
            HookSource::ClaudeUserPlugin
                | HookSource::ClaudeProjectPlugin
                | HookSource::ClaudeLocalPlugin
                | HookSource::ClaudeUserSettings
                | HookSource::ClaudeProjectSettings
                | HookSource::ClaudeLocalSettings
                | HookSource::ClaudeManagedSettings
        )
    )
}

fn is_sha256_label(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|byte| **byte == b'=').count();
    if padding > 2 || bytes[..bytes.len() - padding].contains(&b'=') {
        return None;
    }
    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let is_last = index == bytes.len() / 4 - 1;
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            if !is_last || padding != 2 {
                return None;
            }
            0
        } else {
            base64_value(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            if !is_last || padding == 0 {
                return None;
            }
            0
        } else {
            base64_value(chunk[3])?
        };
        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            output.push((c << 6) | d);
        }
    }
    Some(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}
