use crate::strict_json::required_nullable;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Client {
    Claude,
    Codex,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Sentinel {
    High,
    Low,
    Info,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Severity {
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "LOW")]
    Low,
    #[serde(rename = "INFO")]
    Info,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GateDecision {
    Deny,
    Continue,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSource {
    Core,
    AdapterFallback,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum M0EventType {
    HighDetected,
    HighBlocked,
    WarnedLow,
    AllowedInfo,
    ToolCompleted,
    ToolFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Failure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Invocation {
    #[serde(rename = "shell_text")]
    ShellText {
        shell_executable: String,
        shell_flags: Vec<String>,
        dialect: String,
        command_text: String,
        shell_resolution_source: String,
        shell_resolution_fingerprint: String,
    },
}

impl Invocation {
    pub fn command_text(&self) -> &str {
        match self {
            Self::ShellText { command_text, .. } => command_text,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct M0ActionRequest {
    pub schema_version: String,
    pub phase: String,
    pub test_case_id: String,
    pub test_run_id: String,
    pub test_profile_digest: String,
    pub action_id: String,
    pub envelope_id: String,
    pub client: Client,
    pub session_fixture_id: String,
    pub native_tool_call_id: String,
    pub sentinel: Sentinel,
    pub invocation: Invocation,
    pub physical_cwd_fixture: String,
    pub cwd_resolution_source: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationMetadata {
    pub decision_id: String,
    pub event_ids: [String; 2],
    pub observed_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultMetadata {
    pub event_id: String,
    pub observed_at: String,
    pub client: Client,
    pub session_fixture_id: String,
    pub native_tool_call_id: String,
    pub outcome: Outcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct M0ActionDecision {
    pub schema_version: String,
    pub phase: String,
    pub test_case_id: String,
    pub test_run_id: String,
    pub decision_id: String,
    pub action_id: String,
    pub client: Client,
    pub session_fixture_id: String,
    pub native_tool_call_id: String,
    pub severity: Severity,
    pub gate_decision: GateDecision,
    pub rule_id: String,
    pub decision_source: DecisionSource,
    #[serde(deserialize_with = "required_nullable")]
    pub failure_code: Option<String>,
    pub cache_status: String,
    #[serde(deserialize_with = "required_nullable")]
    pub pending_action_ref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct M0Event {
    pub schema_version: String,
    pub phase: String,
    pub test_case_id: String,
    pub test_run_id: String,
    pub event_id: String,
    pub observed_at: String,
    pub event_type: M0EventType,
    pub client: Client,
    pub session_fixture_id: String,
    pub action_id: String,
    pub native_tool_call_id: String,
    pub severity: Severity,
    pub rule_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub outcome: Option<Outcome>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct M0CoreOutput {
    pub decision: M0ActionDecision,
    pub events: Vec<M0Event>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct M0CoreInput {
    pub schema_version: String,
    pub request: M0ActionRequest,
    pub metadata: EvaluationMetadata,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum M0Error {
    #[error("invalid schema version")]
    SchemaVersion,
    #[error("invalid phase")]
    Phase,
    #[error("invalid M0 contract combination")]
    Contract,
    #[error("result hook does not correlate to its decision")]
    ResultCorrelation,
    #[error("HIGH decisions cannot have a result event")]
    HighResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackFailure {
    CoreTimeout,
    CoreNonzero,
    CoreSchemaInvalid,
}

impl FallbackFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CoreTimeout => "core_timeout",
            Self::CoreNonzero => "core_nonzero",
            Self::CoreSchemaInvalid => "core_schema_invalid",
        }
    }
}

pub fn evaluate(
    request: M0ActionRequest,
    metadata: EvaluationMetadata,
) -> Result<M0CoreOutput, M0Error> {
    if request.schema_version != "m0-action-request/v1" {
        return Err(M0Error::SchemaVersion);
    }
    if request.phase != "m0" {
        return Err(M0Error::Phase);
    }

    let (severity, gate_decision, rule_id, event_types) = match request.sentinel {
        Sentinel::High => (
            Severity::High,
            GateDecision::Deny,
            "m0.sentinel.high",
            [
                Some(M0EventType::HighDetected),
                Some(M0EventType::HighBlocked),
            ],
        ),
        Sentinel::Low => (
            Severity::Low,
            GateDecision::Continue,
            "m0.sentinel.low",
            [Some(M0EventType::WarnedLow), None],
        ),
        Sentinel::Info => (
            Severity::Info,
            GateDecision::Continue,
            "m0.sentinel.info",
            [Some(M0EventType::AllowedInfo), None],
        ),
    };

    let decision = M0ActionDecision {
        schema_version: "m0-action-decision/v1".into(),
        phase: "m0".into(),
        test_case_id: request.test_case_id.clone(),
        test_run_id: request.test_run_id.clone(),
        decision_id: metadata.decision_id,
        action_id: request.action_id.clone(),
        client: request.client,
        session_fixture_id: request.session_fixture_id.clone(),
        native_tool_call_id: request.native_tool_call_id.clone(),
        severity,
        gate_decision,
        rule_id: rule_id.into(),
        decision_source: DecisionSource::Core,
        failure_code: None,
        cache_status: "bypass".into(),
        pending_action_ref: None,
    };

    let events = event_types
        .into_iter()
        .enumerate()
        .filter_map(|(index, event_type)| {
            event_type.map(|event_type| M0Event {
                schema_version: "m0-event/v1".into(),
                phase: "m0".into(),
                test_case_id: request.test_case_id.clone(),
                test_run_id: request.test_run_id.clone(),
                event_id: metadata.event_ids[index].clone(),
                observed_at: metadata.observed_at.clone(),
                event_type,
                client: request.client,
                session_fixture_id: request.session_fixture_id.clone(),
                action_id: request.action_id.clone(),
                native_tool_call_id: request.native_tool_call_id.clone(),
                severity,
                rule_id: rule_id.into(),
                outcome: None,
            })
        })
        .collect();

    validate_decision(&decision)?;
    for event in &events {
        validate_event(event, &decision)?;
    }

    Ok(M0CoreOutput { decision, events })
}

pub fn fallback(
    request: &M0ActionRequest,
    metadata: EvaluationMetadata,
    failure: FallbackFailure,
) -> M0CoreOutput {
    let decision = M0ActionDecision {
        schema_version: "m0-action-decision/v1".into(),
        phase: "m0".into(),
        test_case_id: request.test_case_id.clone(),
        test_run_id: request.test_run_id.clone(),
        decision_id: metadata.decision_id,
        action_id: request.action_id.clone(),
        client: request.client,
        session_fixture_id: request.session_fixture_id.clone(),
        native_tool_call_id: request.native_tool_call_id.clone(),
        severity: Severity::High,
        gate_decision: GateDecision::Deny,
        rule_id: "guardrail.scan_failure".into(),
        decision_source: DecisionSource::AdapterFallback,
        failure_code: Some(failure.as_str().into()),
        cache_status: "bypass".into(),
        pending_action_ref: None,
    };
    let events = [M0EventType::HighDetected, M0EventType::HighBlocked]
        .into_iter()
        .enumerate()
        .map(|(index, event_type)| M0Event {
            schema_version: "m0-event/v1".into(),
            phase: "m0".into(),
            test_case_id: request.test_case_id.clone(),
            test_run_id: request.test_run_id.clone(),
            event_id: metadata.event_ids[index].clone(),
            observed_at: metadata.observed_at.clone(),
            event_type,
            client: request.client,
            session_fixture_id: request.session_fixture_id.clone(),
            action_id: request.action_id.clone(),
            native_tool_call_id: request.native_tool_call_id.clone(),
            severity: Severity::High,
            rule_id: "guardrail.scan_failure".into(),
            outcome: None,
        })
        .collect();

    M0CoreOutput { decision, events }
}

pub fn record_result(
    decision: &M0ActionDecision,
    metadata: ResultMetadata,
) -> Result<M0Event, M0Error> {
    validate_decision(decision)?;
    if decision.client != metadata.client
        || decision.session_fixture_id != metadata.session_fixture_id
        || decision.native_tool_call_id != metadata.native_tool_call_id
    {
        return Err(M0Error::ResultCorrelation);
    }
    if decision.severity == Severity::High {
        return Err(M0Error::HighResult);
    }

    let event = M0Event {
        schema_version: "m0-event/v1".into(),
        phase: "m0".into(),
        test_case_id: decision.test_case_id.clone(),
        test_run_id: decision.test_run_id.clone(),
        event_id: metadata.event_id,
        observed_at: metadata.observed_at,
        event_type: match metadata.outcome {
            Outcome::Success => M0EventType::ToolCompleted,
            Outcome::Failure => M0EventType::ToolFailed,
        },
        client: metadata.client,
        session_fixture_id: metadata.session_fixture_id,
        action_id: decision.action_id.clone(),
        native_tool_call_id: metadata.native_tool_call_id,
        severity: decision.severity,
        rule_id: decision.rule_id.clone(),
        outcome: Some(metadata.outcome),
    };
    validate_event(&event, decision)?;
    Ok(event)
}

pub fn validate_decision(decision: &M0ActionDecision) -> Result<(), M0Error> {
    if decision.schema_version != "m0-action-decision/v1" {
        return Err(M0Error::SchemaVersion);
    }
    if decision.phase != "m0" {
        return Err(M0Error::Phase);
    }
    if decision.cache_status != "bypass" || decision.pending_action_ref.is_some() {
        return Err(M0Error::Contract);
    }

    let valid = matches!(
        (
            decision.severity,
            decision.gate_decision,
            decision.rule_id.as_str(),
            decision.decision_source,
            decision.failure_code.as_deref(),
        ),
        (
            Severity::High,
            GateDecision::Deny,
            "m0.sentinel.high",
            DecisionSource::Core,
            None
        ) | (
            Severity::Low,
            GateDecision::Continue,
            "m0.sentinel.low",
            DecisionSource::Core,
            None
        ) | (
            Severity::Info,
            GateDecision::Continue,
            "m0.sentinel.info",
            DecisionSource::Core,
            None,
        ) | (
            Severity::High,
            GateDecision::Deny,
            "guardrail.scan_failure",
            DecisionSource::AdapterFallback,
            Some("core_timeout" | "core_nonzero" | "core_schema_invalid"),
        )
    );
    valid.then_some(()).ok_or(M0Error::Contract)
}

pub fn validate_event(event: &M0Event, decision: &M0ActionDecision) -> Result<(), M0Error> {
    validate_decision(decision)?;
    if event.schema_version != "m0-event/v1" {
        return Err(M0Error::SchemaVersion);
    }
    if event.phase != "m0" {
        return Err(M0Error::Phase);
    }
    if event.test_case_id != decision.test_case_id
        || event.test_run_id != decision.test_run_id
        || event.client != decision.client
        || event.session_fixture_id != decision.session_fixture_id
        || event.action_id != decision.action_id
        || event.native_tool_call_id != decision.native_tool_call_id
        || event.severity != decision.severity
        || event.rule_id != decision.rule_id
    {
        return Err(M0Error::Contract);
    }

    let valid = match event.event_type {
        M0EventType::HighDetected | M0EventType::HighBlocked => {
            event.severity == Severity::High
                && matches!(
                    event.rule_id.as_str(),
                    "m0.sentinel.high" | "guardrail.scan_failure"
                )
                && event.outcome.is_none()
        }
        M0EventType::WarnedLow => {
            event.severity == Severity::Low
                && event.rule_id == "m0.sentinel.low"
                && event.outcome.is_none()
        }
        M0EventType::AllowedInfo => {
            event.severity == Severity::Info
                && event.rule_id == "m0.sentinel.info"
                && event.outcome.is_none()
        }
        M0EventType::ToolCompleted => {
            matches!(event.severity, Severity::Low | Severity::Info)
                && event.outcome == Some(Outcome::Success)
        }
        M0EventType::ToolFailed => {
            matches!(event.severity, Severity::Low | Severity::Info)
                && event.outcome == Some(Outcome::Failure)
        }
    };
    valid.then_some(()).ok_or(M0Error::Contract)
}

pub fn validate_core_output(
    request: &M0ActionRequest,
    metadata: &EvaluationMetadata,
    output: &M0CoreOutput,
) -> Result<(), M0Error> {
    validate_decision(&output.decision)?;
    let decision = &output.decision;
    if decision.test_case_id != request.test_case_id
        || decision.test_run_id != request.test_run_id
        || decision.action_id != request.action_id
        || decision.client != request.client
        || decision.session_fixture_id != request.session_fixture_id
        || decision.native_tool_call_id != request.native_tool_call_id
        || decision.decision_id != metadata.decision_id
    {
        return Err(M0Error::Contract);
    }

    let expected_types: &[M0EventType] = match request.sentinel {
        Sentinel::High => &[M0EventType::HighDetected, M0EventType::HighBlocked],
        Sentinel::Low => &[M0EventType::WarnedLow],
        Sentinel::Info => &[M0EventType::AllowedInfo],
    };
    if output.events.len() != expected_types.len() {
        return Err(M0Error::Contract);
    }
    for (index, event) in output.events.iter().enumerate() {
        validate_event(event, decision)?;
        if event.event_type != expected_types[index]
            || event.event_id != metadata.event_ids[index]
            || event.observed_at != metadata.observed_at
        {
            return Err(M0Error::Contract);
        }
    }
    Ok(())
}
