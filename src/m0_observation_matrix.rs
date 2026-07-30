use crate::m0::Client;
use crate::m0_fixture_manifest::{Architecture, OperatingSystem, validate_fixture_manifest};
use crate::strict_json::{canonical_sha256, from_slice, required_nullable};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

pub const M0_CASE_IDS: [&str; 46] = [
    "T01",
    "T02",
    "T03",
    "T04",
    "T05-A",
    "T05-B",
    "T05-C",
    "T05-D",
    "T05-E",
    "T05-F",
    "T05-G",
    "T05-H-Codex",
    "T05-I",
    "T05-J",
    "T05-K",
    "T06-A",
    "T06-B",
    "T06-C",
    "T06-D",
    "T06-E",
    "T07",
    "T08",
    "T09",
    "T10-LOW",
    "T10-INFO",
    "T11",
    "T12",
    "T13",
    "T14",
    "T15",
    "T16",
    "T17",
    "T18",
    "T19-A-HIGH",
    "T19-A-LOW",
    "T19-A-INFO",
    "T19-B-MISSING",
    "T19-B-DIGEST",
    "T19-B-SOURCE",
    "T19-B-HELPER",
    "T19-B-ARGV",
    "T19-C",
    "T20-A",
    "T20-B",
    "T20-C",
    "T20-D",
];

const UNVERIFIED_APPROVAL: &str = "unverified_noninteractive_bypass_mode_no_operator_approval";
pub const MAX_HARNESS_SOURCE_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Verified,
    ContractOnly,
    ObservedUnsupported,
    Unverified,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageEffect {
    Included,
    Excluded,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum M0Gate {
    #[serde(rename = "OBSERVATION_COMPLETE_WITH_EXCLUSIONS")]
    ObservationCompleteWithExclusions,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum M1Gate {
    #[serde(rename = "NO_GO")]
    NoGo,
}

impl M1Gate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoGo => "NO_GO",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ObservationHost {
    pub os: String,
    pub os_version: String,
    pub os_build: String,
    pub architecture: String,
    pub process_observer: String,
    pub approval_boundary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientManifestBinding {
    pub client: Client,
    pub client_version: String,
    pub manifest_evidence_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MatrixClients {
    pub claude: ClientManifestBinding,
    pub codex: ClientManifestBinding,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    ContractTest,
    NativeFixture,
    StaticManifest,
    ObservationResult,
    ProbeDefinition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCatalogEntry {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub relative_path: String,
    pub content_sha256: String,
    #[serde(deserialize_with = "required_nullable")]
    pub selector: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientObservation {
    pub status: ObservationStatus,
    pub coverage_effect: CoverageEffect,
    pub reason: String,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CaseObservation {
    pub case_id: String,
    pub claude: ClientObservation,
    pub codex: ClientObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct M0ObservationMatrix {
    pub schema_version: String,
    pub assessed_at: String,
    pub host: ObservationHost,
    pub m0_gate: M0Gate,
    pub m1_gate: M1Gate,
    pub clients: MatrixClients,
    pub evidence_catalog: Vec<EvidenceCatalogEntry>,
    pub cases: Vec<CaseObservation>,
}

#[derive(Debug, Error)]
pub enum ObservationMatrixError {
    #[error("invalid strict observation matrix JSON: {0}")]
    Json(String),
    #[error("invalid observation matrix contract")]
    Contract,
    #[error("invalid observation evidence path: {0}")]
    EvidencePath(String),
    #[error("observation evidence digest mismatch: {0}")]
    EvidenceDigest(String),
    #[error("invalid observation evidence selector: {0}")]
    EvidenceSelector(String),
    #[error("invalid native harness source output: {0}")]
    SourceOutput(String),
}

pub struct HarnessSourceOutputs<'a> {
    pub claude_live: &'a [u8],
    pub codex_high: &'a [u8],
    pub codex_result_failure: &'a [u8],
    pub adapter_faults: &'a [u8],
    pub prompt_continuation: &'a [u8],
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ObservationClaimClassification {
    Verified,
    ObservedUnsupported,
    Unverified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ObservationClaim {
    classification: ObservationClaimClassification,
    client: Client,
    case_ids: Vec<String>,
    fact_selector: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProbeDefinition {
    client: Client,
    case_ids: Vec<String>,
    required_observations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProbeDefinitionDocument {
    schema_version: String,
    definitions: BTreeMap<String, ProbeDefinition>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct NativeObservationResult {
    schema_version: String,
    assessed_at: String,
    provenance: NativeObservationProvenance,
    host: NativeObservationHost,
    claude: ClaudeNativeObservations,
    codex: CodexNativeObservations,
    claims: BTreeMap<String, ObservationClaim>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct NativeObservationProvenance {
    recorded_at: String,
    harness_summary_relative_path: String,
    harness_summary_content_sha256: String,
    case_results_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct NativeObservationHost {
    os: String,
    os_version: String,
    os_build: String,
    architecture: String,
    process_observer: String,
    #[serde(deserialize_with = "required_nullable")]
    target_process_started: Option<u64>,
    approval_boundary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ClaudeNativeObservations {
    client_version: String,
    live_markers: ClaudeLiveMarkers,
    adapter_faults: Vec<AdapterFaultObservation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ClaudeLiveMarkers {
    high_marker_exists: bool,
    low_marker_exists: bool,
    info_marker_exists: bool,
    #[serde(deserialize_with = "required_nullable")]
    target_process_started: Option<u64>,
    approval_boundary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CodexNativeObservations {
    client_version: String,
    live: CodexLiveObservation,
    adapter_faults: Vec<AdapterFaultObservation>,
    prompt_continuation: PromptContinuationObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CodexLiveObservation {
    effective_per_call_workdir_available: bool,
    success_tool_response: String,
    failure_tool_response: String,
    result_outcome: String,
    high_marker_exists: bool,
    system_message_in_exec_json: bool,
    interactive_ui: String,
    #[serde(deserialize_with = "required_nullable")]
    target_process_started: Option<u64>,
    approval_boundary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct AdapterFaultObservation {
    case_id: String,
    target_marker_exists: bool,
    #[serde(deserialize_with = "required_nullable")]
    target_process_started: Option<u64>,
    approval_boundary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct PromptContinuationObservation {
    claude_user_prompt_submit_field: String,
    claude_prompt_preserved_trailing_lf: bool,
    user_prompt_submit_count: u64,
    stop_count: u64,
    stop_hook_active: Vec<bool>,
    continuation_transport: String,
    second_user_prompt_submit_observed: bool,
    provenance: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct HarnessSummaryDocument {
    schema_version: String,
    recorded_at: String,
    host: NativeObservationHost,
    clients: HarnessSummaryClients,
    harness_runs: HarnessRuns,
    case_results_sha256: String,
    case_results: HarnessCaseResults,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct HarnessSummaryClients {
    claude: HarnessClientArtifacts,
    codex: HarnessClientArtifacts,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct HarnessClientArtifacts {
    client: Client,
    client_version: String,
    manifest_relative_path: String,
    manifest_content_sha256: String,
    client_executable_sha256: String,
    client_runtime_artifact_sha256: String,
    product_hook_sha256: String,
    product_core_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct HarnessRuns {
    claude_live: HarnessRunBinding,
    codex_high: HarnessRunBinding,
    codex_result_failure: HarnessRunBinding,
    adapter_faults: HarnessRunBinding,
    prompt_continuation: HarnessRunBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct HarnessRunBinding {
    harness_relative_path: String,
    harness_content_sha256: String,
    observation_scope: HarnessObservationScope,
    source_output_sha256: String,
    source_output_bytes: u64,
    result_selectors: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum HarnessObservationScope {
    FinalProductArtifact,
    ClientNativeBoundaryNoProductClaim,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct HarnessCaseResults {
    claude: ClaudeNativeObservations,
    codex: CodexNativeObservations,
}

#[derive(Clone, Debug)]
struct ValidatedEvidence {
    kind: EvidenceKind,
    observation_claim: Option<ObservationClaim>,
    probe_definition: Option<ProbeDefinition>,
    static_manifest: Option<StaticManifestIdentity>,
}

#[derive(Clone, Debug)]
struct StaticManifestIdentity {
    client: Client,
    client_version: String,
    os: OperatingSystem,
    architecture: Architecture,
}

pub fn validate_observation_matrix(
    bytes: &[u8],
    repository_root: &Path,
) -> Result<M0ObservationMatrix, ObservationMatrixError> {
    let matrix: M0ObservationMatrix =
        from_slice(bytes).map_err(|error| ObservationMatrixError::Json(error.to_string()))?;

    validate_header(&matrix)?;
    validate_repository_root(repository_root)?;
    let catalog = validate_evidence_catalog(&matrix.evidence_catalog, repository_root)?;

    let mut referenced_evidence = HashSet::new();
    validate_client_binding(
        &matrix.clients.claude,
        Client::Claude,
        "2.1.220",
        &catalog,
        &mut referenced_evidence,
    )?;
    validate_client_binding(
        &matrix.clients.codex,
        Client::Codex,
        "0.146.0",
        &catalog,
        &mut referenced_evidence,
    )?;

    let mut verified_count = 0;
    let mut included_count = 0;
    for (case, expected_id) in matrix.cases.iter().zip(M0_CASE_IDS) {
        if case.case_id != expected_id {
            return Err(ObservationMatrixError::Contract);
        }
        validate_observation(
            &case.claude,
            Client::Claude,
            expected_id,
            &catalog,
            &mut referenced_evidence,
        )?;
        validate_observation(
            &case.codex,
            Client::Codex,
            expected_id,
            &catalog,
            &mut referenced_evidence,
        )?;
        verified_count += [&case.claude, &case.codex]
            .into_iter()
            .filter(|observation| observation.status == ObservationStatus::Verified)
            .count();
        included_count += [&case.claude, &case.codex]
            .into_iter()
            .filter(|observation| observation.coverage_effect == CoverageEffect::Included)
            .count();
    }

    if verified_count != 0
        || included_count != 0
        || referenced_evidence.len() != matrix.evidence_catalog.len()
    {
        return Err(ObservationMatrixError::Contract);
    }

    Ok(matrix)
}

pub fn validate_harness_source_outputs(
    harness_summary_bytes: &[u8],
    source_outputs: HarnessSourceOutputs<'_>,
) -> Result<(), ObservationMatrixError> {
    let summary_value: Value = from_slice(harness_summary_bytes)
        .map_err(|error| ObservationMatrixError::Json(error.to_string()))?;
    let summary: HarnessSummaryDocument = from_slice(harness_summary_bytes)
        .map_err(|error| ObservationMatrixError::Json(error.to_string()))?;
    let case_results = summary_value
        .get("case_results")
        .ok_or_else(|| source_error("harness-summary"))?;
    let computed_case_results_sha256 =
        canonical_sha256(case_results).map_err(|_| source_error("harness-summary"))?;
    if summary.schema_version != "m0-harness-summary/v1"
        || summary.case_results_sha256 != computed_case_results_sha256
    {
        return Err(source_error("harness-summary"));
    }

    validate_source_binding(
        "claude-live",
        &summary.harness_runs.claude_live,
        source_outputs.claude_live,
    )?;
    validate_source_binding(
        "codex-high",
        &summary.harness_runs.codex_high,
        source_outputs.codex_high,
    )?;
    validate_source_binding(
        "codex-result-failure",
        &summary.harness_runs.codex_result_failure,
        source_outputs.codex_result_failure,
    )?;
    validate_source_binding(
        "adapter-faults",
        &summary.harness_runs.adapter_faults,
        source_outputs.adapter_faults,
    )?;
    validate_source_binding(
        "prompt-continuation",
        &summary.harness_runs.prompt_continuation,
        source_outputs.prompt_continuation,
    )?;

    let claude_live = strict_source_value("claude-live", source_outputs.claude_live)?;
    let codex_high = strict_source_value("codex-high", source_outputs.codex_high)?;
    let codex_result_failure =
        strict_source_value("codex-result-failure", source_outputs.codex_result_failure)?;
    let adapter_faults = strict_source_value("adapter-faults", source_outputs.adapter_faults)?;
    let prompt_continuation =
        strict_source_value("prompt-continuation", source_outputs.prompt_continuation)?;

    validate_claude_live_source(
        &claude_live,
        &summary.clients.claude,
        &summary.case_results.claude,
    )?;
    validate_codex_source(
        "codex-high",
        &codex_high,
        "high_pre_tool",
        true,
        &summary.clients.codex,
        &summary.case_results.codex,
    )?;
    validate_codex_source(
        "codex-result-failure",
        &codex_result_failure,
        "result_failure",
        false,
        &summary.clients.codex,
        &summary.case_results.codex,
    )?;
    validate_adapter_fault_source(&adapter_faults, &summary.case_results)?;
    validate_prompt_source(&prompt_continuation, &summary.case_results)?;
    Ok(())
}

fn validate_source_binding(
    label: &str,
    binding: &HarnessRunBinding,
    bytes: &[u8],
) -> Result<(), ObservationMatrixError> {
    let byte_count = u64::try_from(bytes.len()).map_err(|_| source_error(label))?;
    if byte_count == 0
        || byte_count > MAX_HARNESS_SOURCE_OUTPUT_BYTES
        || binding.source_output_sha256 != sha256_label(bytes)
        || binding.source_output_bytes != byte_count
    {
        return Err(source_error(label));
    }
    Ok(())
}

fn strict_source_value(label: &str, bytes: &[u8]) -> Result<Value, ObservationMatrixError> {
    from_slice(bytes).map_err(|_| source_error(label))
}

fn validate_claude_live_source(
    source: &Value,
    artifacts: &HarnessClientArtifacts,
    normalized: &ClaudeNativeObservations,
) -> Result<(), ObservationMatrixError> {
    const TOP_LEVEL: &[&str] = &[
        "schema_version",
        "claude_executable",
        "claude_version",
        "environment_binding",
        "product_artifacts",
        "run_root",
        "kernel_network_confinement",
        "proxy_egress_observations",
        "results",
    ];
    if !has_exact_keys(source, TOP_LEVEL)
        || source_string(source, "/schema_version") != Some("m0-claude-native-harness-result/v1")
        || source_string(source, "/claude_version") != Some("2.1.220 (Claude Code)")
        || source_string(source, "/environment_binding/os_build") != Some("25F84")
        || source_string(source, "/environment_binding/architecture") != Some("arm64")
        || source_string(source, "/environment_binding/client_sha256")
            != Some(artifacts.client_executable_sha256.as_str())
        || source_string(source, "/environment_binding/client_version_output")
            != Some("2.1.220 (Claude Code)")
        || source_string(source, "/product_artifacts/hook_sha256")
            != Some(artifacts.product_hook_sha256.as_str())
        || source_string(source, "/product_artifacts/core_sha256")
            != Some(artifacts.product_core_sha256.as_str())
        || source_string(source, "/kernel_network_confinement")
            != Some("unavailable_sandbox_exec_operation_not_permitted")
        || source_u64(source, "/proxy_egress_observations") != Some(0)
        || normalized.client_version != artifacts.client_version
    {
        return Err(source_error("claude-live"));
    }

    let Some(results) = source.pointer("/results").and_then(Value::as_array) else {
        return Err(source_error("claude-live"));
    };
    let expected = [
        (
            "high",
            "high",
            "default",
            "none",
            false,
            Value::Null,
            Value::Null,
        ),
        (
            "low",
            "low",
            "default",
            "none",
            true,
            Value::Null,
            Value::Bool(true),
        ),
        (
            "info",
            "info",
            "default",
            "none",
            true,
            Value::Null,
            Value::Null,
        ),
        (
            "low-failure-helper",
            "low",
            "failure",
            "none",
            true,
            Value::Null,
            Value::Bool(true),
        ),
        (
            "info-failure-helper",
            "info",
            "failure",
            "none",
            true,
            Value::Null,
            Value::Null,
        ),
        (
            "info-core-timeout",
            "info",
            "default",
            "timeout",
            false,
            Value::Null,
            Value::Null,
        ),
        (
            "info-core-nonzero",
            "info",
            "default",
            "nonzero",
            false,
            Value::Null,
            Value::Null,
        ),
        (
            "info-core-schema-invalid",
            "info",
            "default",
            "schema-invalid",
            false,
            Value::Null,
            Value::Null,
        ),
        (
            "high-sibling",
            "high",
            "default",
            "none",
            false,
            Value::Bool(true),
            Value::Null,
        ),
    ];
    if results.len() != expected.len() {
        return Err(source_error("claude-live"));
    }
    for (result, (case, sentinel, helper, fault, marker, sibling, warning)) in
        results.iter().zip(expected)
    {
        if source_string(result, "/case") != Some(case)
            || source_string(result, "/sentinel") != Some(sentinel)
            || source_string(result, "/helper") != Some(helper)
            || source_string(result, "/core_fault") != Some(fault)
            || source_bool(result, "/marker_exists") != Some(marker)
            || result.pointer("/target_process_started") != Some(&Value::Null)
            || source_u64(result, "/target_process_observation_count") != Some(0)
            || source_string(result, "/target_process_observer")
                != Some("unavailable_operation_not_permitted")
            || result.pointer("/sibling_marker_exists") != Some(&sibling)
            || result.pointer("/warning_stream_received_before_target") != Some(&warning)
        {
            return Err(source_error("claude-live"));
        }
    }
    if normalized.live_markers.high_marker_exists
        || !normalized.live_markers.low_marker_exists
        || !normalized.live_markers.info_marker_exists
        || normalized.live_markers.target_process_started.is_some()
        || normalized.live_markers.approval_boundary != UNVERIFIED_APPROVAL
    {
        return Err(source_error("claude-live"));
    }
    Ok(())
}

fn validate_codex_source(
    label: &str,
    source: &Value,
    expected_probe: &str,
    high_probe: bool,
    artifacts: &HarnessClientArtifacts,
    normalized: &CodexNativeObservations,
) -> Result<(), ObservationMatrixError> {
    const TOP_LEVEL: &[&str] = &[
        "schema_version",
        "codex_executable",
        "codex_version",
        "environment_binding",
        "product_artifacts",
        "run_root",
        "kernel_network_confinement",
        "proxy_egress_observations",
        "cwd_binding",
        "coverage",
        "probe_kind",
        "target_marker_exists",
        "high_marker_exists",
        "system_message_observed",
        "result_outcome",
        "evidence_counts",
    ];
    let expected_high = if high_probe {
        Some(&Value::Bool(true))
    } else {
        Some(&Value::Null)
    };
    if !has_exact_keys(source, TOP_LEVEL)
        || source_string(source, "/schema_version") != Some("m0-codex-native-harness-result/v1")
        || source_string(source, "/codex_version") != Some("codex-cli 0.146.0")
        || source_string(source, "/environment_binding/os_build") != Some("25F84")
        || source_string(source, "/environment_binding/architecture") != Some("arm64")
        || source_string(source, "/environment_binding/client_invoked_path")
            != Some("/opt/homebrew/bin/codex")
        || source_string(source, "/environment_binding/client_resolved_path")
            != Some("/opt/homebrew/lib/node_modules/@openai/codex/bin/codex.js")
        || source_string(source, "/environment_binding/client_sha256")
            != Some(artifacts.client_executable_sha256.as_str())
        || source_string(source, "/environment_binding/client_version_output")
            != Some("codex-cli 0.146.0")
        || source_string(source, "/product_artifacts/hook_sha256")
            != Some(artifacts.product_hook_sha256.as_str())
        || source_string(source, "/product_artifacts/core_sha256")
            != Some(artifacts.product_core_sha256.as_str())
        || source_string(source, "/kernel_network_confinement")
            != Some("unavailable_sandbox_exec_operation_not_permitted")
        || source_u64(source, "/proxy_egress_observations") != Some(0)
        || source_string(source, "/cwd_binding") != Some("unverified")
        || source_string(source, "/coverage") != Some("excluded")
        || source_string(source, "/probe_kind") != Some(expected_probe)
        || source_bool(source, "/target_marker_exists") != Some(true)
        || source.pointer("/high_marker_exists") != expected_high
        || source_bool(source, "/system_message_observed") != Some(false)
        || source_string(source, "/result_outcome") != Some("unverified")
        || normalized.client_version != "0.146.0"
        || normalized.live.effective_per_call_workdir_available
        || !normalized.live.success_tool_response.is_empty()
        || !normalized.live.failure_tool_response.is_empty()
        || normalized.live.result_outcome != "ambiguous_rejected"
        || !normalized.live.high_marker_exists
        || normalized.live.system_message_in_exec_json
        || normalized.live.interactive_ui != "unverified"
        || normalized.live.target_process_started.is_some()
        || normalized.live.approval_boundary != UNVERIFIED_APPROVAL
    {
        return Err(source_error(label));
    }
    Ok(())
}

fn validate_adapter_fault_source(
    source: &Value,
    normalized: &HarnessCaseResults,
) -> Result<(), ObservationMatrixError> {
    const TOP_LEVEL: &[&str] = &[
        "schema_version",
        "run_root",
        "host",
        "network",
        "approval_boundary",
        "interpretation",
        "observational_failures",
        "unsupported_or_unverified",
        "clients",
    ];
    if !has_exact_keys(source, TOP_LEVEL)
        || source_string(source, "/schema_version") != Some("m0-adapter-fault-observations/v1")
        || source_string(source, "/host/platform") != Some("darwin")
        || source_string(source, "/host/architecture") != Some("arm64")
        || source_string(source, "/host/node_version") != Some("v26.5.0")
        || source_string(source, "/approval_boundary") != Some(UNVERIFIED_APPROVAL)
        || source
            .pointer("/observational_failures")
            .and_then(Value::as_array)
            .is_none_or(|failures| !failures.is_empty())
        || source_string(source, "/clients/claude/version") != Some("2.1.220 (Claude Code)")
        || source_string(source, "/clients/codex/version") != Some("codex-cli 0.146.0")
    {
        return Err(source_error("adapter-faults"));
    }
    validate_fault_source_client(source, "claude", &normalized.claude.adapter_faults)?;
    validate_fault_source_client(source, "codex", &normalized.codex.adapter_faults)?;
    Ok(())
}

fn validate_fault_source_client(
    source: &Value,
    client: &str,
    normalized: &[AdapterFaultObservation],
) -> Result<(), ObservationMatrixError> {
    let pointer = format!("/clients/{client}/observations");
    let Some(observations) = source.pointer(&pointer).and_then(Value::as_array) else {
        return Err(source_error("adapter-faults"));
    };
    let expected_order: &[&str] = if client == "claude" {
        &[
            "T05-D", "T05-E", "T05-F", "T05-G", "T05-I", "T05-J", "T05-K",
        ]
    } else {
        &[
            "T05-D",
            "T05-E",
            "T05-F",
            "T05-G",
            "T05-I",
            "T05-J",
            "T05-K",
            "T05-H-Codex",
        ]
    };
    if observations.len() != expected_order.len()
        || observations
            .iter()
            .zip(expected_order)
            .any(|(observation, case_id)| source_string(observation, "/case_id") != Some(*case_id))
    {
        return Err(source_error("adapter-faults"));
    }
    for source_observation in observations {
        let Some(case_id) = source_string(source_observation, "/case_id") else {
            return Err(source_error("adapter-faults"));
        };
        let Some(normalized_observation) = normalized
            .iter()
            .find(|observation| observation.case_id == case_id)
        else {
            return Err(source_error("adapter-faults"));
        };
        if source_string(source_observation, "/case_id")
            != Some(normalized_observation.case_id.as_str())
            || source_bool(source_observation, "/target_marker_exists")
                != Some(normalized_observation.target_marker_exists)
            || source_observation.pointer("/target_process_started") != Some(&Value::Null)
            || source_string(source_observation, "/target_process_observer")
                != Some("unavailable_not_instrumented")
            || source_string(source_observation, "/approval_boundary") != Some(UNVERIFIED_APPROVAL)
            || source_bool(source_observation, "/protection_claim") != Some(false)
            || normalized_observation.target_process_started.is_some()
            || normalized_observation.approval_boundary != UNVERIFIED_APPROVAL
        {
            return Err(source_error("adapter-faults"));
        }
    }
    Ok(())
}

fn validate_prompt_source(
    source: &Value,
    normalized: &HarnessCaseResults,
) -> Result<(), ObservationMatrixError> {
    const TOP_LEVEL: &[&str] = &[
        "schema_version",
        "run_root",
        "human_prompt",
        "codex_stop_block_response",
        "child_timeout_ms",
        "kernel_network_confinement",
        "claude",
        "codex",
    ];
    let claude_prompts = source
        .pointer("/claude/prompt_observations")
        .and_then(Value::as_array)
        .ok_or_else(|| source_error("prompt-continuation"))?;
    let codex_prompts = source
        .pointer("/codex/prompt_observations")
        .and_then(Value::as_array)
        .ok_or_else(|| source_error("prompt-continuation"))?;
    let codex_stops = source
        .pointer("/codex/stop_observations")
        .and_then(Value::as_array)
        .ok_or_else(|| source_error("prompt-continuation"))?;
    let claude_prompt = claude_prompts
        .first()
        .ok_or_else(|| source_error("prompt-continuation"))?;
    let claude_prompt_text = source_string(claude_prompt, "/payload/prompt")
        .ok_or_else(|| source_error("prompt-continuation"))?;
    let continuation = source_string(source, "/codex/automatic_continuation/local_api_input")
        .ok_or_else(|| source_error("prompt-continuation"))?;
    let prompt = &normalized.codex.prompt_continuation;
    if !has_exact_keys(source, TOP_LEVEL)
        || source_string(source, "/schema_version") != Some("m0-prompt-observations/v1")
        || source_string(source, "/human_prompt") != Some("SECURE_ONBOARD_HUMAN_PROMPT")
        || source_string(source, "/codex_stop_block_response/decision") != Some("block")
        || source_string(source, "/codex_stop_block_response/reason") != Some("M0_CONTINUATION")
        || source_u64(source, "/child_timeout_ms") != Some(30_000)
        || source_string(source, "/kernel_network_confinement")
            != Some("unavailable_sandbox_exec_operation_not_permitted")
        || source_string(source, "/claude/version") != Some("2.1.220 (Claude Code)")
        || source_string(source, "/codex/version") != Some("codex-cli 0.146.0")
        || claude_prompts.len() != 1
        || source_string(claude_prompt, "/payload/hook_event_name") != Some("UserPromptSubmit")
        || source_string(claude_prompt, "/source_assurance") != Some("unverified")
        || codex_prompts.len() != 1
        || source_string(&codex_prompts[0], "/payload/hook_event_name") != Some("UserPromptSubmit")
        || source_string(&codex_prompts[0], "/observed_origin") != Some("initial_human_submission")
        || source_string(&codex_prompts[0], "/source_assurance") != Some("unverified")
        || codex_stops.len() != 2
        || source_bool(&codex_stops[0], "/payload/stop_hook_active") != Some(false)
        || source_bool(&codex_stops[1], "/payload/stop_hook_active") != Some(true)
        || !continuation.starts_with("<hook_prompt ")
        || !continuation.ends_with(">M0_CONTINUATION</hook_prompt>")
        || source_bool(
            source,
            "/codex/automatic_continuation/user_prompt_submit_observed",
        ) != Some(false)
        || source_string(source, "/codex/automatic_continuation/source_assurance")
            != Some("unverified")
        || source_bool(source, "/codex/prompt_and_stop_turn_ids_equal") != Some(true)
        || source_bool(source, "/codex/stop_turn_ids_equal") != Some(true)
        || prompt.claude_user_prompt_submit_field != "prompt"
        || prompt.claude_prompt_preserved_trailing_lf != claude_prompt_text.ends_with('\n')
        || prompt.user_prompt_submit_count != 1
        || prompt.stop_count != 2
        || prompt.stop_hook_active != [false, true]
        || prompt.continuation_transport != "api_hook_prompt"
        || prompt.second_user_prompt_submit_observed
        || prompt.provenance != "unverified"
    {
        return Err(source_error("prompt-continuation"));
    }
    Ok(())
}

fn has_exact_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

fn source_string<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn source_bool(value: &Value, pointer: &str) -> Option<bool> {
    value.pointer(pointer).and_then(Value::as_bool)
}

fn source_u64(value: &Value, pointer: &str) -> Option<u64> {
    value.pointer(pointer).and_then(Value::as_u64)
}

fn source_error(label: &str) -> ObservationMatrixError {
    ObservationMatrixError::SourceOutput(label.to_owned())
}

fn validate_header(matrix: &M0ObservationMatrix) -> Result<(), ObservationMatrixError> {
    if matrix.schema_version != "m0-observation-matrix/v1"
        || matrix.assessed_at != "2026-07-29"
        || matrix.host.os != "macos"
        || matrix.host.os_version != "26.5.2"
        || matrix.host.os_build != "25F84"
        || matrix.host.architecture != "arm64"
        || matrix.host.process_observer != "unavailable_operation_not_permitted"
        || matrix.host.approval_boundary != UNVERIFIED_APPROVAL
        || matrix.cases.len() != M0_CASE_IDS.len()
        || matrix.evidence_catalog.is_empty()
    {
        return Err(ObservationMatrixError::Contract);
    }
    Ok(())
}

fn validate_repository_root(repository_root: &Path) -> Result<(), ObservationMatrixError> {
    if !repository_root.is_absolute() {
        return Err(ObservationMatrixError::EvidencePath(
            repository_root.display().to_string(),
        ));
    }
    let metadata = fs::symlink_metadata(repository_root)
        .map_err(|_| ObservationMatrixError::EvidencePath(repository_root.display().to_string()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ObservationMatrixError::EvidencePath(
            repository_root.display().to_string(),
        ));
    }
    Ok(())
}

fn validate_evidence_catalog(
    entries: &[EvidenceCatalogEntry],
    repository_root: &Path,
) -> Result<HashMap<String, ValidatedEvidence>, ObservationMatrixError> {
    let mut catalog = HashMap::with_capacity(entries.len());
    let mut previous_id: Option<&str> = None;
    let mut path_selectors = HashSet::new();

    for entry in entries {
        if !valid_evidence_id(&entry.evidence_id)
            || previous_id.is_some_and(|previous| previous >= entry.evidence_id.as_str())
            || !is_sha256(&entry.content_sha256)
            || !path_selectors.insert((entry.relative_path.as_str(), entry.selector.as_deref()))
        {
            return Err(ObservationMatrixError::Contract);
        }
        previous_id = Some(&entry.evidence_id);

        let path = evidence_path(repository_root, &entry.relative_path)?;
        let evidence_bytes = fs::read(&path)
            .map_err(|_| ObservationMatrixError::EvidencePath(entry.relative_path.clone()))?;
        if sha256_label(&evidence_bytes) != entry.content_sha256 {
            return Err(ObservationMatrixError::EvidenceDigest(
                entry.evidence_id.clone(),
            ));
        }

        let validated = match entry.kind {
            EvidenceKind::ContractTest => validate_contract_test(entry, &path, &evidence_bytes)?,
            EvidenceKind::NativeFixture => {
                require_null_selector(entry)?;
                from_slice::<Value>(&evidence_bytes)
                    .map_err(|error| ObservationMatrixError::Json(error.to_string()))?;
                ValidatedEvidence {
                    kind: entry.kind,
                    observation_claim: None,
                    probe_definition: None,
                    static_manifest: None,
                }
            }
            EvidenceKind::StaticManifest => {
                require_null_selector(entry)?;
                let fixture_root = repository_root.join("tests/fixtures/m0");
                let manifest = validate_fixture_manifest(&evidence_bytes, &fixture_root)
                    .map_err(|_| ObservationMatrixError::Contract)?;
                ValidatedEvidence {
                    kind: entry.kind,
                    observation_claim: None,
                    probe_definition: None,
                    static_manifest: Some(StaticManifestIdentity {
                        client: manifest.client(),
                        client_version: manifest.client_version().to_owned(),
                        os: manifest.os(),
                        architecture: manifest.architecture(),
                    }),
                }
            }
            EvidenceKind::ObservationResult => {
                validate_observation_result(entry, &evidence_bytes, repository_root)?
            }
            EvidenceKind::ProbeDefinition => validate_probe_definition(entry, &evidence_bytes)?,
        };
        if catalog
            .insert(entry.evidence_id.clone(), validated)
            .is_some()
        {
            return Err(ObservationMatrixError::Contract);
        }
    }
    Ok(catalog)
}

fn validate_contract_test(
    entry: &EvidenceCatalogEntry,
    path: &Path,
    bytes: &[u8],
) -> Result<ValidatedEvidence, ObservationMatrixError> {
    let selector = required_selector(entry)?;
    if path.extension().and_then(|extension| extension.to_str()) != Some("rs")
        || !valid_rust_identifier(selector)
    {
        return Err(ObservationMatrixError::EvidenceSelector(
            entry.evidence_id.clone(),
        ));
    }
    let source = std::str::from_utf8(bytes)
        .map_err(|_| ObservationMatrixError::EvidenceSelector(entry.evidence_id.clone()))?;
    let selected_test = format!("#[test]\nfn {selector}(");
    if !source.contains(&selected_test) {
        return Err(ObservationMatrixError::EvidenceSelector(
            entry.evidence_id.clone(),
        ));
    }
    Ok(ValidatedEvidence {
        kind: entry.kind,
        observation_claim: None,
        probe_definition: None,
        static_manifest: None,
    })
}

fn validate_observation_result(
    entry: &EvidenceCatalogEntry,
    bytes: &[u8],
    repository_root: &Path,
) -> Result<ValidatedEvidence, ObservationMatrixError> {
    let selector = required_selector(entry)?;
    let value: Value =
        from_slice(bytes).map_err(|error| ObservationMatrixError::Json(error.to_string()))?;
    let document: NativeObservationResult =
        from_slice(bytes).map_err(|error| ObservationMatrixError::Json(error.to_string()))?;
    validate_native_observation_result(&document, &value, repository_root)?;
    let selected = value
        .pointer(selector)
        .ok_or_else(|| ObservationMatrixError::EvidenceSelector(entry.evidence_id.clone()))?;
    let claim: ObservationClaim = serde_json::from_value(selected.clone())
        .map_err(|_| ObservationMatrixError::EvidenceSelector(entry.evidence_id.clone()))?;
    if !document
        .claims
        .values()
        .any(|candidate| candidate == &claim)
    {
        return Err(ObservationMatrixError::EvidenceSelector(
            entry.evidence_id.clone(),
        ));
    }
    Ok(ValidatedEvidence {
        kind: entry.kind,
        observation_claim: Some(claim),
        probe_definition: None,
        static_manifest: None,
    })
}

fn validate_probe_definition(
    entry: &EvidenceCatalogEntry,
    bytes: &[u8],
) -> Result<ValidatedEvidence, ObservationMatrixError> {
    let selector = required_selector(entry)?;
    let value: Value =
        from_slice(bytes).map_err(|error| ObservationMatrixError::Json(error.to_string()))?;
    let document: ProbeDefinitionDocument =
        from_slice(bytes).map_err(|error| ObservationMatrixError::Json(error.to_string()))?;
    validate_probe_document(&document)?;
    let selected = value
        .pointer(selector)
        .ok_or_else(|| ObservationMatrixError::EvidenceSelector(entry.evidence_id.clone()))?;
    let definition: ProbeDefinition = serde_json::from_value(selected.clone())
        .map_err(|_| ObservationMatrixError::EvidenceSelector(entry.evidence_id.clone()))?;
    if !document
        .definitions
        .values()
        .any(|candidate| candidate == &definition)
    {
        return Err(ObservationMatrixError::EvidenceSelector(
            entry.evidence_id.clone(),
        ));
    }
    Ok(ValidatedEvidence {
        kind: entry.kind,
        observation_claim: None,
        probe_definition: Some(definition),
        static_manifest: None,
    })
}

fn validate_native_observation_result(
    document: &NativeObservationResult,
    value: &Value,
    repository_root: &Path,
) -> Result<(), ObservationMatrixError> {
    if document.schema_version != "m0-native-observation-result/v1"
        || document.assessed_at != "2026-07-29"
        || !valid_recorded_at(&document.provenance.recorded_at)
        || document.provenance.harness_summary_relative_path
            != "tests/fixtures/m0/observations/harness-summary.json"
        || !is_sha256(&document.provenance.harness_summary_content_sha256)
        || !is_sha256(&document.provenance.case_results_sha256)
        || document.host.os != "macos"
        || document.host.os_version != "26.5.2"
        || document.host.os_build != "25F84"
        || document.host.architecture != "arm64"
        || document.host.process_observer != "unavailable_operation_not_permitted"
        || document.host.target_process_started.is_some()
        || document.host.approval_boundary != UNVERIFIED_APPROVAL
        || document.claude.client_version != "2.1.220"
        || document.claude.live_markers.high_marker_exists
        || !document.claude.live_markers.low_marker_exists
        || !document.claude.live_markers.info_marker_exists
        || document
            .claude
            .live_markers
            .target_process_started
            .is_some()
        || document.claude.live_markers.approval_boundary != UNVERIFIED_APPROVAL
        || document.codex.client_version != "0.146.0"
        || document.codex.live.effective_per_call_workdir_available
        || !document.codex.live.success_tool_response.is_empty()
        || !document.codex.live.failure_tool_response.is_empty()
        || document.codex.live.result_outcome != "ambiguous_rejected"
        || !document.codex.live.high_marker_exists
        || document.codex.live.system_message_in_exec_json
        || document.codex.live.interactive_ui != "unverified"
        || document.codex.live.target_process_started.is_some()
        || document.codex.live.approval_boundary != UNVERIFIED_APPROVAL
    {
        return Err(ObservationMatrixError::Contract);
    }

    validate_harness_summary(document, repository_root)?;

    validate_faults(
        &document.claude.adapter_faults,
        &[
            ("T05-D", true),
            ("T05-E", true),
            ("T05-F", true),
            ("T05-G", true),
            ("T05-I", true),
            ("T05-J", false),
            ("T05-K", false),
        ],
    )?;
    validate_faults(
        &document.codex.adapter_faults,
        &[
            ("T05-D", true),
            ("T05-E", true),
            ("T05-F", true),
            ("T05-G", true),
            ("T05-H-Codex", true),
            ("T05-I", true),
            ("T05-J", false),
            ("T05-K", false),
        ],
    )?;

    let prompt = &document.codex.prompt_continuation;
    if prompt.claude_user_prompt_submit_field != "prompt"
        || !prompt.claude_prompt_preserved_trailing_lf
        || prompt.user_prompt_submit_count != 1
        || prompt.stop_count != 2
        || prompt.stop_hook_active != [false, true]
        || prompt.continuation_transport != "api_hook_prompt"
        || prompt.second_user_prompt_submit_observed
        || prompt.provenance != "unverified"
    {
        return Err(ObservationMatrixError::Contract);
    }

    let expected_claims = [
        (
            "claude_adapter_faults",
            ObservationClaimClassification::Unverified,
            Client::Claude,
            &[
                "T05-D", "T05-E", "T05-F", "T05-G", "T05-I", "T05-J", "T05-K",
            ][..],
            "/claude/adapter_faults",
        ),
        (
            "codex_adapter_faults",
            ObservationClaimClassification::Unverified,
            Client::Codex,
            &[
                "T05-D",
                "T05-E",
                "T05-F",
                "T05-G",
                "T05-H-Codex",
                "T05-I",
                "T05-J",
                "T05-K",
            ][..],
            "/codex/adapter_faults",
        ),
        (
            "codex_effective_cwd_unavailable",
            ObservationClaimClassification::ObservedUnsupported,
            Client::Codex,
            &[
                "T02",
                "T03",
                "T04",
                "T05-A",
                "T05-B",
                "T05-C",
                "T07",
                "T09",
                "T18",
                "T19-A-HIGH",
                "T19-A-LOW",
                "T19-A-INFO",
                "T19-B-HELPER",
                "T19-B-ARGV",
            ][..],
            "/codex/live/effective_per_call_workdir_available",
        ),
        (
            "codex_prompt_continuation",
            ObservationClaimClassification::Unverified,
            Client::Codex,
            &["T11"][..],
            "/codex/prompt_continuation",
        ),
        (
            "codex_result_ambiguous",
            ObservationClaimClassification::ObservedUnsupported,
            Client::Codex,
            &["T10-LOW", "T10-INFO"][..],
            "/codex/live/result_outcome",
        ),
        (
            "codex_system_message_display",
            ObservationClaimClassification::Unverified,
            Client::Codex,
            &["T20-A", "T20-B", "T20-C", "T20-D"][..],
            "/codex/live/interactive_ui",
        ),
    ];
    if document.claims.len() != expected_claims.len() {
        return Err(ObservationMatrixError::Contract);
    }
    for (id, classification, client, case_ids, fact_selector) in expected_claims {
        let Some(claim) = document.claims.get(id) else {
            return Err(ObservationMatrixError::Contract);
        };
        if claim.classification != classification
            || claim.client != client
            || claim
                .case_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != case_ids
            || claim.fact_selector != fact_selector
            || value.pointer(fact_selector).is_none()
        {
            return Err(ObservationMatrixError::Contract);
        }
    }
    Ok(())
}

fn validate_harness_summary(
    observation: &NativeObservationResult,
    repository_root: &Path,
) -> Result<(), ObservationMatrixError> {
    let relative = &observation.provenance.harness_summary_relative_path;
    let path = evidence_path(repository_root, relative)?;
    let bytes =
        fs::read(&path).map_err(|_| ObservationMatrixError::EvidencePath(relative.clone()))?;
    if sha256_label(&bytes) != observation.provenance.harness_summary_content_sha256 {
        return Err(ObservationMatrixError::EvidenceDigest(
            "native-observation-provenance".into(),
        ));
    }
    let value: Value =
        from_slice(&bytes).map_err(|error| ObservationMatrixError::Json(error.to_string()))?;
    let summary: HarnessSummaryDocument =
        from_slice(&bytes).map_err(|error| ObservationMatrixError::Json(error.to_string()))?;
    let case_results = value
        .get("case_results")
        .ok_or(ObservationMatrixError::Contract)?;
    let computed_case_results_sha256 =
        canonical_sha256(case_results).map_err(|_| ObservationMatrixError::Contract)?;

    if summary.schema_version != "m0-harness-summary/v1"
        || summary.recorded_at != observation.provenance.recorded_at
        || summary.host != observation.host
        || summary.case_results.claude != observation.claude
        || summary.case_results.codex != observation.codex
        || summary.case_results_sha256 != computed_case_results_sha256
        || observation.provenance.case_results_sha256 != computed_case_results_sha256
    {
        return Err(ObservationMatrixError::Contract);
    }

    validate_harness_client_artifacts(
        &summary.clients.claude,
        Client::Claude,
        "2.1.220",
        "tests/fixtures/m0/manifests/claude-2.1.220-macos-arm64.json",
        repository_root,
    )?;
    validate_harness_client_artifacts(
        &summary.clients.codex,
        Client::Codex,
        "0.146.0",
        "tests/fixtures/m0/manifests/codex-0.146.0-macos-arm64.json",
        repository_root,
    )?;

    let expected_runs = [
        (
            &summary.harness_runs.claude_live,
            "tests/native-harness/run-claude-m0.mjs",
            HarnessObservationScope::FinalProductArtifact,
            &["/case_results/claude/live_markers"][..],
        ),
        (
            &summary.harness_runs.codex_high,
            "tests/native-harness/run-codex-m0.mjs",
            HarnessObservationScope::FinalProductArtifact,
            &[
                "/case_results/codex/live/effective_per_call_workdir_available",
                "/case_results/codex/live/high_marker_exists",
                "/case_results/codex/live/success_tool_response",
                "/case_results/codex/live/system_message_in_exec_json",
            ][..],
        ),
        (
            &summary.harness_runs.codex_result_failure,
            "tests/native-harness/run-codex-m0.mjs",
            HarnessObservationScope::FinalProductArtifact,
            &[
                "/case_results/codex/live/failure_tool_response",
                "/case_results/codex/live/result_outcome",
            ][..],
        ),
        (
            &summary.harness_runs.adapter_faults,
            "tests/native-harness/run-adapter-fault-observations.mjs",
            HarnessObservationScope::ClientNativeBoundaryNoProductClaim,
            &[
                "/case_results/claude/adapter_faults",
                "/case_results/codex/adapter_faults",
            ][..],
        ),
        (
            &summary.harness_runs.prompt_continuation,
            "tests/native-harness/run-prompt-observations.mjs",
            HarnessObservationScope::ClientNativeBoundaryNoProductClaim,
            &["/case_results/codex/prompt_continuation"][..],
        ),
    ];
    let mut output_digests = HashSet::new();
    for (run, expected_path, expected_scope, expected_selectors) in expected_runs {
        if run.harness_relative_path != expected_path
            || run.observation_scope != expected_scope
            || !is_sha256(&run.harness_content_sha256)
            || !is_sha256(&run.source_output_sha256)
            || run.source_output_bytes == 0
            || run.source_output_bytes > MAX_HARNESS_SOURCE_OUTPUT_BYTES
            || run
                .result_selectors
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != expected_selectors
            || !output_digests.insert(run.source_output_sha256.as_str())
        {
            return Err(ObservationMatrixError::Contract);
        }
        let harness_path = evidence_path(repository_root, &run.harness_relative_path)?;
        let harness_bytes = fs::read(harness_path)
            .map_err(|_| ObservationMatrixError::EvidencePath(run.harness_relative_path.clone()))?;
        if sha256_label(&harness_bytes) != run.harness_content_sha256
            || run
                .result_selectors
                .iter()
                .any(|selector| value.pointer(selector).is_none())
        {
            return Err(ObservationMatrixError::Contract);
        }
    }
    Ok(())
}

fn validate_harness_client_artifacts(
    artifacts: &HarnessClientArtifacts,
    expected_client: Client,
    expected_version: &str,
    expected_manifest_path: &str,
    repository_root: &Path,
) -> Result<(), ObservationMatrixError> {
    if artifacts.client != expected_client
        || artifacts.client_version != expected_version
        || artifacts.manifest_relative_path != expected_manifest_path
        || !is_sha256(&artifacts.manifest_content_sha256)
        || !is_sha256(&artifacts.client_executable_sha256)
        || !is_sha256(&artifacts.client_runtime_artifact_sha256)
        || !is_sha256(&artifacts.product_hook_sha256)
        || !is_sha256(&artifacts.product_core_sha256)
    {
        return Err(ObservationMatrixError::Contract);
    }
    let manifest_path = evidence_path(repository_root, &artifacts.manifest_relative_path)?;
    let manifest_bytes = fs::read(&manifest_path).map_err(|_| {
        ObservationMatrixError::EvidencePath(artifacts.manifest_relative_path.clone())
    })?;
    if sha256_label(&manifest_bytes) != artifacts.manifest_content_sha256 {
        return Err(ObservationMatrixError::EvidenceDigest(
            artifacts.manifest_relative_path.clone(),
        ));
    }
    let fixture_root = repository_root.join("tests/fixtures/m0");
    let manifest = validate_fixture_manifest(&manifest_bytes, &fixture_root)
        .map_err(|_| ObservationMatrixError::Contract)?;
    if manifest.client() != expected_client || manifest.client_version() != expected_version {
        return Err(ObservationMatrixError::Contract);
    }
    let manifest_value: Value = from_slice(&manifest_bytes)
        .map_err(|error| ObservationMatrixError::Json(error.to_string()))?;
    for (pointer, expected) in [
        (
            "/client_executable/sha256",
            artifacts.client_executable_sha256.as_str(),
        ),
        (
            "/client_runtime_artifact/sha256",
            artifacts.client_runtime_artifact_sha256.as_str(),
        ),
        (
            "/product_artifact/sha256",
            artifacts.product_hook_sha256.as_str(),
        ),
        (
            "/core_artifact/sha256",
            artifacts.product_core_sha256.as_str(),
        ),
    ] {
        if manifest_value.pointer(pointer).and_then(Value::as_str) != Some(expected) {
            return Err(ObservationMatrixError::Contract);
        }
    }
    Ok(())
}

fn validate_faults(
    actual: &[AdapterFaultObservation],
    expected: &[(&str, bool)],
) -> Result<(), ObservationMatrixError> {
    if actual.len() != expected.len() {
        return Err(ObservationMatrixError::Contract);
    }
    for (observation, (case_id, marker_exists)) in actual.iter().zip(expected) {
        if observation.case_id != *case_id
            || observation.target_marker_exists != *marker_exists
            || observation.target_process_started.is_some()
            || observation.approval_boundary != UNVERIFIED_APPROVAL
        {
            return Err(ObservationMatrixError::Contract);
        }
    }
    Ok(())
}

fn valid_recorded_at(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && &bytes[..11] == b"2026-07-29T"
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && [11, 12, 14, 15, 17, 18]
            .into_iter()
            .all(|index| bytes[index].is_ascii_digit())
        && decimal_pair(bytes[11], bytes[12]).is_some_and(|hour| hour <= 23)
        && decimal_pair(bytes[14], bytes[15]).is_some_and(|minute| minute <= 59)
        && decimal_pair(bytes[17], bytes[18]).is_some_and(|second| second <= 59)
}

fn decimal_pair(tens: u8, ones: u8) -> Option<u8> {
    Some((tens.checked_sub(b'0')? * 10) + ones.checked_sub(b'0')?)
}

fn validate_probe_document(
    document: &ProbeDefinitionDocument,
) -> Result<(), ObservationMatrixError> {
    let expected = [
        (
            "claude_sibling_hook",
            Client::Claude,
            &["T09"][..],
            &[
                "target_process_started",
                "native_approval",
                "sibling_effect_separated_from_target",
            ][..],
        ),
        (
            "claude_system_message_display",
            Client::Claude,
            &["T20-A", "T20-B", "T20-C"][..],
            &[
                "interactive_rendered_bytes",
                "render_timestamp_before_target",
                "truncation_and_newline_handling",
            ][..],
        ),
        (
            "codex_project_hook_spoof",
            Client::Codex,
            &["T17"][..],
            &[
                "trusted_user_hook_source",
                "project_hook_exclusion",
                "heartbeat_source_binding",
            ][..],
        ),
    ];
    if document.schema_version != "m0-probe-definitions/v1"
        || document.definitions.len() != expected.len()
    {
        return Err(ObservationMatrixError::Contract);
    }
    for (id, client, case_ids, required_observations) in expected {
        let Some(definition) = document.definitions.get(id) else {
            return Err(ObservationMatrixError::Contract);
        };
        if definition.client != client
            || definition
                .case_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != case_ids
            || definition
                .required_observations
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                != required_observations
        {
            return Err(ObservationMatrixError::Contract);
        }
    }
    Ok(())
}

fn validate_client_binding(
    binding: &ClientManifestBinding,
    expected_client: Client,
    expected_version: &str,
    catalog: &HashMap<String, ValidatedEvidence>,
    referenced_evidence: &mut HashSet<String>,
) -> Result<(), ObservationMatrixError> {
    if binding.client != expected_client || binding.client_version != expected_version {
        return Err(ObservationMatrixError::Contract);
    }
    let evidence = catalog
        .get(&binding.manifest_evidence_id)
        .ok_or(ObservationMatrixError::Contract)?;
    let manifest = evidence
        .static_manifest
        .as_ref()
        .filter(|_| evidence.kind == EvidenceKind::StaticManifest)
        .ok_or(ObservationMatrixError::Contract)?;
    if manifest.client != expected_client
        || manifest.client_version != expected_version
        || manifest.os != OperatingSystem::Macos
        || manifest.architecture != Architecture::Arm64
    {
        return Err(ObservationMatrixError::Contract);
    }
    referenced_evidence.insert(binding.manifest_evidence_id.clone());
    Ok(())
}

fn validate_observation(
    observation: &ClientObservation,
    client: Client,
    case_id: &str,
    catalog: &HashMap<String, ValidatedEvidence>,
    referenced_evidence: &mut HashSet<String>,
) -> Result<(), ObservationMatrixError> {
    let valid_pair = matches!(
        (observation.status, observation.coverage_effect),
        (ObservationStatus::Verified, CoverageEffect::Included)
            | (
                ObservationStatus::ContractOnly
                    | ObservationStatus::ObservedUnsupported
                    | ObservationStatus::Unverified,
                CoverageEffect::Excluded
            )
            | (
                ObservationStatus::NotApplicable,
                CoverageEffect::NotApplicable
            )
    );
    if !valid_pair
        || observation.reason.is_empty()
        || observation.reason.trim() != observation.reason
        || observation.reason.len() > 512
        || observation.reason.chars().any(char::is_control)
        || (observation.status == ObservationStatus::NotApplicable
            && !observation.evidence_ids.is_empty())
        || (observation.status != ObservationStatus::NotApplicable
            && observation.evidence_ids.is_empty())
        || !strictly_sorted(&observation.evidence_ids)
    {
        return Err(ObservationMatrixError::Contract);
    }

    let mut has_contract_evidence = false;
    let mut has_matching_result = false;
    let mut has_matching_probe = false;
    let mut has_non_contract_evidence = false;
    for evidence_id in &observation.evidence_ids {
        let evidence = catalog
            .get(evidence_id)
            .ok_or(ObservationMatrixError::Contract)?;
        referenced_evidence.insert(evidence_id.clone());
        has_contract_evidence |= matches!(
            evidence.kind,
            EvidenceKind::ContractTest | EvidenceKind::NativeFixture | EvidenceKind::StaticManifest
        );
        has_non_contract_evidence |= matches!(
            evidence.kind,
            EvidenceKind::ObservationResult | EvidenceKind::ProbeDefinition
        );
        if let Some(claim) = &evidence.observation_claim {
            let expected_classification = match observation.status {
                ObservationStatus::Verified => Some(ObservationClaimClassification::Verified),
                ObservationStatus::ObservedUnsupported => {
                    Some(ObservationClaimClassification::ObservedUnsupported)
                }
                ObservationStatus::Unverified => Some(ObservationClaimClassification::Unverified),
                ObservationStatus::ContractOnly | ObservationStatus::NotApplicable => None,
            };
            has_matching_result |= expected_classification == Some(claim.classification)
                && claim.client == client
                && claim.case_ids.iter().any(|candidate| candidate == case_id);
        }
        if let Some(definition) = &evidence.probe_definition
            && (definition.client != client
                || !definition
                    .case_ids
                    .iter()
                    .any(|candidate| candidate == case_id))
        {
            return Err(ObservationMatrixError::Contract);
        }
        has_matching_probe |= evidence
            .probe_definition
            .as_ref()
            .is_some_and(|definition| {
                definition.client == client
                    && definition
                        .case_ids
                        .iter()
                        .any(|candidate| candidate == case_id)
            });
    }

    match observation.status {
        ObservationStatus::Verified | ObservationStatus::ObservedUnsupported
            if !has_matching_result =>
        {
            Err(ObservationMatrixError::Contract)
        }
        ObservationStatus::ContractOnly if !has_contract_evidence || has_non_contract_evidence => {
            Err(ObservationMatrixError::Contract)
        }
        ObservationStatus::Unverified if !has_matching_result && !has_matching_probe => {
            Err(ObservationMatrixError::Contract)
        }
        _ => Ok(()),
    }
}

fn required_selector(entry: &EvidenceCatalogEntry) -> Result<&str, ObservationMatrixError> {
    let selector = entry
        .selector
        .as_deref()
        .filter(|selector| {
            !selector.is_empty()
                && selector.trim() == *selector
                && !selector.chars().any(char::is_control)
        })
        .ok_or_else(|| ObservationMatrixError::EvidenceSelector(entry.evidence_id.clone()))?;
    Ok(selector)
}

fn require_null_selector(entry: &EvidenceCatalogEntry) -> Result<(), ObservationMatrixError> {
    if entry.selector.is_some() {
        return Err(ObservationMatrixError::EvidenceSelector(
            entry.evidence_id.clone(),
        ));
    }
    Ok(())
}

fn evidence_path(
    repository_root: &Path,
    relative: &str,
) -> Result<PathBuf, ObservationMatrixError> {
    let relative_path = Path::new(relative);
    if relative.is_empty()
        || relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ObservationMatrixError::EvidencePath(relative.into()));
    }

    let mut path = repository_root.to_path_buf();
    for component in relative_path.components() {
        let Component::Normal(part) = component else {
            return Err(ObservationMatrixError::EvidencePath(relative.into()));
        };
        path.push(part);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| ObservationMatrixError::EvidencePath(relative.into()))?;
        if metadata.file_type().is_symlink() {
            return Err(ObservationMatrixError::EvidencePath(relative.into()));
        }
    }
    if !path.is_file() {
        return Err(ObservationMatrixError::EvidencePath(relative.into()));
    }
    Ok(path)
}

fn valid_evidence_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn valid_rust_identifier(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn strictly_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_sha256(value: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::valid_recorded_at;

    #[test]
    fn recorded_at_is_an_exact_utc_second_on_the_assessment_date() {
        assert!(valid_recorded_at("2026-07-29T00:00:00Z"));
        assert!(valid_recorded_at("2026-07-29T23:59:59Z"));
        for invalid in [
            "2026-07-28T23:59:59Z",
            "2026-07-29T24:00:00Z",
            "2026-07-29T12:60:00Z",
            "2026-07-29T12:00:60Z",
            "2026-07-29T12:00:00.1Z",
            "2026-07-29T120000Z",
        ] {
            assert!(!valid_recorded_at(invalid), "{invalid}");
        }
    }
}
