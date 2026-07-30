#![cfg(feature = "m0-test-profile")]

use crate::contracts::{HookEnvelope, HookEvent, ToolOutcome};
use crate::m0::{
    Client, M0ActionDecision, M0ActionRequest, M0Event, M0EventType, Outcome, validate_decision,
    validate_event,
};
use crate::m0_physical_file::validate_digest;
use crate::m0_status::{
    ArtifactKind, ClientModeEvidenceInput, M0CanonicalDigests, M0ForbiddenObservations,
    M0ObjectCounts, M0RunEvidence, M0StatusReport, StatusError, client_mode_evidence_digest,
    validate_status,
};
use crate::strict_json::{canonical_bytes, canonical_sha256, from_slice};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub struct M0StatusFileBindings<'a> {
    pub client_invoked_path: &'a Path,
    pub client_runtime_artifact_path: &'a Path,
    pub product_artifact_path: &'a Path,
    pub production_evidence: Option<M0ProductionEvidence<'a>>,
}

#[derive(Clone, Copy)]
pub struct M0ProductionEvidence<'a> {
    pub bound_build_manifest_bytes: &'a [u8],
    pub component_probe_stdout: &'a [u8],
    pub component_probe_stderr: &'a [u8],
    pub profile_probe_stdout: &'a [u8],
    pub profile_probe_stderr: &'a [u8],
}

pub struct T19RunObjects {
    pub hook_envelopes: Vec<HookEnvelope>,
    pub action_requests: Vec<M0ActionRequest>,
    pub action_decisions: Vec<M0ActionDecision>,
    pub events: Vec<M0Event>,
}

pub struct T19RunObservations {
    pub target_process_start_count: u64,
    pub target_marker_count: u64,
    pub operator_approval_count: u64,
    pub secure_onboard_approval_count: u64,
    pub uncorrelated_result_count: u64,
}

#[derive(Debug)]
pub struct ValidatedT19Status {
    pub report: M0StatusReport,
    pub status_report_digest: String,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum StatusHarnessError {
    #[error("status report contract is invalid: {0}")]
    Status(#[from] StatusError),
    #[error("status file binding is invalid")]
    FileBinding,
    #[error("T19 object correlation is invalid")]
    ObjectCorrelation,
    #[error("T19 canonical digest could not be computed")]
    CanonicalDigest,
}

pub fn construct_status(
    mut report: M0StatusReport,
    mode_input: &ClientModeEvidenceInput,
    bindings: M0StatusFileBindings<'_>,
) -> Result<M0StatusReport, StatusHarnessError> {
    report.client_mode_evidence.evidence_digest = Some(client_mode_evidence_digest(mode_input)?);
    validate_file_bindings(&report, bindings)?;
    validate_status(&report, Some(mode_input))?;
    Ok(report)
}

pub fn construct_t19_status(
    mut report: M0StatusReport,
    mode_input: &ClientModeEvidenceInput,
    bindings: M0StatusFileBindings<'_>,
    objects: T19RunObjects,
    observations: T19RunObservations,
) -> Result<ValidatedT19Status, StatusHarnessError> {
    validate_t19_objects(&report, &objects)?;
    report.run_evidence = Some(M0RunEvidence {
        object_counts: M0ObjectCounts {
            hook_envelope: objects.hook_envelopes.len() as u64,
            m0_action_request: objects.action_requests.len() as u64,
            m0_action_decision: objects.action_decisions.len() as u64,
            m0_event: objects.events.len() as u64,
            m0_status_report: 1,
        },
        canonical_digests: M0CanonicalDigests {
            hook_envelope: canonical_digests(&objects.hook_envelopes)?,
            m0_action_request: canonical_digests(&objects.action_requests)?,
            m0_action_decision: canonical_digests(&objects.action_decisions)?,
            m0_event: canonical_digests(&objects.events)?,
        },
        ordered_events: objects
            .events
            .iter()
            .map(|event| event.event_type)
            .collect(),
        observations: M0ForbiddenObservations {
            target_process_start_count: observations.target_process_start_count,
            target_marker_count: observations.target_marker_count,
            operator_approval_count: observations.operator_approval_count,
            secure_onboard_approval_count: observations.secure_onboard_approval_count,
            uncorrelated_result_count: observations.uncorrelated_result_count,
        },
    });
    let report = construct_status(report, mode_input, bindings)?;
    let status_report_digest =
        canonical_sha256(&report).map_err(|_| StatusHarnessError::CanonicalDigest)?;
    Ok(ValidatedT19Status {
        report,
        status_report_digest,
    })
}

fn validate_file_bindings(
    report: &M0StatusReport,
    bindings: M0StatusFileBindings<'_>,
) -> Result<(), StatusHarnessError> {
    let invoked = bindings.client_invoked_path;
    if invoked != Path::new(&report.client_executable.invoked_path)
        || bindings.client_runtime_artifact_path
            != Path::new(&report.client_runtime_artifact.absolute_path)
    {
        return Err(StatusHarnessError::FileBinding);
    }
    let resolved = physical_file(Path::new(&report.client_executable.resolved_path))?;
    if fs::canonicalize(invoked).ok().as_deref() != Some(resolved.as_path()) {
        return Err(StatusHarnessError::FileBinding);
    }
    validate_digest(&resolved, &report.client_executable.sha256)
        .map_err(|_| StatusHarnessError::FileBinding)?;
    validate_digest(
        bindings.client_runtime_artifact_path,
        &report.client_runtime_artifact.sha256,
    )
    .map_err(|_| StatusHarnessError::FileBinding)?;
    validate_digest(bindings.product_artifact_path, &report.artifact_digest)
        .map_err(|_| StatusHarnessError::FileBinding)?;
    match (report.artifact_kind, bindings.production_evidence) {
        (ArtifactKind::Test, None) => {}
        (ArtifactKind::Production, Some(evidence)) => {
            let inspection = report
                .artifact_inspection
                .as_ref()
                .ok_or(StatusHarnessError::FileBinding)?;
            validate_production_artifact_evidence(
                bindings.product_artifact_path,
                inspection,
                evidence,
            )?;
        }
        _ => return Err(StatusHarnessError::FileBinding),
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundBuildManifest {
    schema_version: String,
    artifact_sha256: String,
    component_manifest_sha256: String,
    components: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ComponentManifest {
    schema_version: String,
    components: Vec<String>,
}

pub fn validate_production_artifact_evidence(
    product_artifact_path: &Path,
    inspection: &crate::m0_status::ArtifactInspection,
    evidence: M0ProductionEvidence<'_>,
) -> Result<(), StatusHarnessError> {
    validate_digest(product_artifact_path, &inspection.bound_artifact_digest)
        .map_err(|_| StatusHarnessError::FileBinding)?;
    let product_digest = &inspection.bound_artifact_digest;
    let component_json = evidence
        .component_probe_stdout
        .strip_suffix(b"\n")
        .ok_or(StatusHarnessError::FileBinding)?;
    let component: ComponentManifest =
        from_slice(component_json).map_err(|_| StatusHarnessError::FileBinding)?;
    if !evidence.component_probe_stderr.is_empty()
        || component.schema_version != "secure-onboard-build-components/v1"
        || component.components != ["production_profile_rejection"]
    {
        return Err(StatusHarnessError::FileBinding);
    }
    let manifest: BoundBuildManifest =
        parse_canonical_document(evidence.bound_build_manifest_bytes)?;
    let forbidden = [
        "m0_test_profile_loader",
        "m0_sentinel_rules",
        "m0_status_constructor",
    ];
    let sorted = manifest.components.windows(2).all(|pair| pair[0] < pair[1]);
    if manifest.schema_version != "secure-onboard-bound-build-manifest/v1"
        || manifest.artifact_sha256 != *product_digest
        || manifest.component_manifest_sha256 != sha256_bytes(evidence.component_probe_stdout)
        || manifest.components != component.components
        || !sorted
        || manifest
            .components
            .iter()
            .any(|component| forbidden.contains(&component.as_str()))
        || evidence.profile_probe_stdout != b"{\"profile\":\"not_supported\"}\n"
        || !evidence.profile_probe_stderr.is_empty()
    {
        return Err(StatusHarnessError::FileBinding);
    }
    if inspection.build_manifest_digest != sha256_bytes(evidence.bound_build_manifest_bytes) {
        return Err(StatusHarnessError::FileBinding);
    }
    Ok(())
}

fn parse_canonical_document<T>(bytes: &[u8]) -> Result<T, StatusHarnessError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let json = bytes
        .strip_suffix(b"\n")
        .ok_or(StatusHarnessError::FileBinding)?;
    let value: T = from_slice(json).map_err(|_| StatusHarnessError::FileBinding)?;
    let mut expected = canonical_bytes(&value).map_err(|_| StatusHarnessError::FileBinding)?;
    expected.push(b'\n');
    if bytes != expected {
        return Err(StatusHarnessError::FileBinding);
    }
    Ok(value)
}

fn physical_file(path: &Path) -> Result<PathBuf, StatusHarnessError> {
    if !path.is_absolute() {
        return Err(StatusHarnessError::FileBinding);
    }
    let physical = fs::canonicalize(path).map_err(|_| StatusHarnessError::FileBinding)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| StatusHarnessError::FileBinding)?;
    if !metadata.file_type().is_file() || physical != path {
        return Err(StatusHarnessError::FileBinding);
    }
    Ok(physical)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn canonical_digests<T: serde::Serialize>(
    objects: &[T],
) -> Result<Vec<String>, StatusHarnessError> {
    objects
        .iter()
        .map(|object| canonical_sha256(object).map_err(|_| StatusHarnessError::CanonicalDigest))
        .collect()
}

fn validate_t19_objects(
    report: &M0StatusReport,
    objects: &T19RunObjects,
) -> Result<(), StatusHarnessError> {
    if !report.test_case_id.starts_with("T19-") {
        return Err(StatusHarnessError::ObjectCorrelation);
    }
    for envelope in &objects.hook_envelopes {
        envelope
            .validate()
            .map_err(|_| StatusHarnessError::ObjectCorrelation)?;
        if envelope_client(envelope) != report.client {
            return Err(StatusHarnessError::ObjectCorrelation);
        }
    }
    validate_envelope_sequence(&objects.hook_envelopes)?;

    for request in &objects.action_requests {
        if request.test_case_id != report.test_case_id
            || request.test_run_id != report.test_run_id
            || request.client != report.client
            || report.test_profile_supplied_digest.as_ref() != Some(&request.test_profile_digest)
        {
            return Err(StatusHarnessError::ObjectCorrelation);
        }
    }
    for decision in &objects.action_decisions {
        validate_decision(decision).map_err(|_| StatusHarnessError::ObjectCorrelation)?;
        let request = objects
            .action_requests
            .iter()
            .find(|request| request.action_id == decision.action_id)
            .ok_or(StatusHarnessError::ObjectCorrelation)?;
        if decision.test_case_id != request.test_case_id
            || decision.test_run_id != request.test_run_id
            || decision.client != request.client
            || decision.session_fixture_id != request.session_fixture_id
            || decision.native_tool_call_id != request.native_tool_call_id
        {
            return Err(StatusHarnessError::ObjectCorrelation);
        }
    }
    for event in &objects.events {
        let decision = objects
            .action_decisions
            .iter()
            .find(|decision| decision.action_id == event.action_id)
            .ok_or(StatusHarnessError::ObjectCorrelation)?;
        validate_event(event, decision).map_err(|_| StatusHarnessError::ObjectCorrelation)?;
    }
    validate_request_envelope_correlation(objects)?;
    Ok(())
}

fn validate_envelope_sequence(envelopes: &[HookEnvelope]) -> Result<(), StatusHarnessError> {
    match envelopes {
        [] => Ok(()),
        [pre] if pre.hook_event() == HookEvent::PreToolUse => Ok(()),
        [pre, result]
            if pre.hook_event() == HookEvent::PreToolUse
                && result.hook_event() == HookEvent::ToolResult
                && envelope_session(pre) == envelope_session(result)
                && envelope_tool_call(pre) == envelope_tool_call(result) =>
        {
            Ok(())
        }
        _ => Err(StatusHarnessError::ObjectCorrelation),
    }
}

fn validate_request_envelope_correlation(
    objects: &T19RunObjects,
) -> Result<(), StatusHarnessError> {
    if objects.action_requests.is_empty() {
        return Ok(());
    }
    let [request] = objects.action_requests.as_slice() else {
        return Err(StatusHarnessError::ObjectCorrelation);
    };
    let Some(pre) = objects.hook_envelopes.first() else {
        return Err(StatusHarnessError::ObjectCorrelation);
    };
    if envelope_session(pre) != request.session_fixture_id
        || envelope_tool_call(pre) != request.native_tool_call_id
        || envelope_id(pre) != request.envelope_id
    {
        return Err(StatusHarnessError::ObjectCorrelation);
    }
    if let Some(result) = objects.hook_envelopes.get(1) {
        let result_outcome = match result {
            HookEnvelope::ToolResult { outcome, .. } => *outcome,
            _ => return Err(StatusHarnessError::ObjectCorrelation),
        };
        let result_event = objects
            .events
            .iter()
            .find(|event| {
                matches!(
                    event.event_type,
                    M0EventType::ToolCompleted | M0EventType::ToolFailed
                )
            })
            .ok_or(StatusHarnessError::ObjectCorrelation)?;
        let expected = match result_outcome {
            ToolOutcome::Success => Outcome::Success,
            ToolOutcome::Failure => Outcome::Failure,
        };
        if result_event.outcome != Some(expected) {
            return Err(StatusHarnessError::ObjectCorrelation);
        }
    }
    Ok(())
}

fn envelope_client(envelope: &HookEnvelope) -> Client {
    match envelope {
        HookEnvelope::PreToolUse { client, .. }
        | HookEnvelope::ToolResult { client, .. }
        | HookEnvelope::AssistantStop { client, .. } => *client,
    }
}

fn envelope_session(envelope: &HookEnvelope) -> &str {
    match envelope {
        HookEnvelope::PreToolUse { session_id, .. }
        | HookEnvelope::ToolResult { session_id, .. }
        | HookEnvelope::AssistantStop { session_id, .. } => session_id,
    }
}

fn envelope_tool_call(envelope: &HookEnvelope) -> &str {
    match envelope {
        HookEnvelope::PreToolUse {
            native_tool_call_id,
            ..
        }
        | HookEnvelope::ToolResult {
            native_tool_call_id,
            ..
        } => native_tool_call_id,
        HookEnvelope::AssistantStop { .. } => "",
    }
}

fn envelope_id(envelope: &HookEnvelope) -> &str {
    match envelope {
        HookEnvelope::PreToolUse { envelope_id, .. }
        | HookEnvelope::ToolResult { envelope_id, .. }
        | HookEnvelope::AssistantStop { envelope_id, .. } => envelope_id,
    }
}
