use crate::contracts::{
    CwdAssurance, CwdResolutionSource, HookEnvelope, HookEnvelopeError, ToolOutcome,
};
use crate::m0::Client;
use crate::strict_json::{StrictJsonError, from_slice, required_nullable};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CwdBinding {
    VerifiedSimpleInvocation,
    UnsupportedPerCallWorkdir,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceAssurance {
    Unverified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativePromptObservation {
    pub schema_version: String,
    pub client: Client,
    pub session_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub adapter_turn_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub native_prompt_id: Option<String>,
    pub native_session_cwd: String,
    pub prompt: String,
    pub source_assurance: SourceAssurance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeMapContext {
    pub envelope_id: String,
    pub occurred_at: String,
    pub cwd_binding: CwdBinding,
}

#[derive(Debug, Error)]
pub enum NativeMapError {
    #[error("invalid native hook schema: {0}")]
    Schema(String),
    #[error("unsupported native hook event")]
    UnsupportedEvent,
    #[error("unsupported native tool")]
    UnsupportedTool,
    #[error("Codex result shape has not been verified")]
    UnverifiedCodexResult,
    #[error("invalid normalized HookEnvelope: {0}")]
    Envelope(#[from] HookEnvelopeError),
}

impl From<StrictJsonError> for NativeMapError {
    fn from(error: StrictJsonError) -> Self {
        Self::Schema(error.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreResponse {
    High {
        system_message: String,
        reason: String,
    },
    Low {
        system_message: String,
    },
    Info,
    Neutral,
}

#[derive(Debug, Error)]
pub enum NativeResponseError {
    #[error("could not encode native hook response: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Serialize)]
struct DenyResponse<'a> {
    #[serde(rename = "systemMessage")]
    system_message: &'a str,
    #[serde(rename = "hookSpecificOutput")]
    hook_specific_output: DenyHookOutput<'a>,
}

#[derive(Serialize)]
struct DenyHookOutput<'a> {
    #[serde(rename = "hookEventName")]
    hook_event_name: &'static str,
    #[serde(rename = "permissionDecision")]
    permission_decision: &'static str,
    #[serde(rename = "permissionDecisionReason")]
    permission_decision_reason: &'a str,
}

#[derive(Serialize)]
struct WarningResponse<'a> {
    #[serde(rename = "systemMessage")]
    system_message: &'a str,
}

pub fn encode_pre_response(
    client: Client,
    response: &PreResponse,
) -> Result<Vec<u8>, NativeResponseError> {
    let mut bytes = match (client, response) {
        (
            Client::Claude | Client::Codex,
            PreResponse::High {
                system_message,
                reason,
            },
        ) => serde_json::to_vec(&DenyResponse {
            system_message,
            hook_specific_output: DenyHookOutput {
                hook_event_name: "PreToolUse",
                permission_decision: "deny",
                permission_decision_reason: reason,
            },
        })?,
        (Client::Claude | Client::Codex, PreResponse::Low { system_message }) => {
            serde_json::to_vec(&WarningResponse { system_message })?
        }
        (Client::Claude | Client::Codex, PreResponse::Info | PreResponse::Neutral) => {
            serde_json::to_vec(&json!({}))?
        }
    };
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn map_claude_native(
    bytes: &[u8],
    context: &NativeMapContext,
) -> Result<HookEnvelope, NativeMapError> {
    let event = native_event_name(bytes)?;
    let envelope = match event.as_str() {
        "PreToolUse" => {
            let raw: ClaudePre = from_slice(bytes)?;
            if raw.tool_name != "Bash" {
                return Err(NativeMapError::UnsupportedTool);
            }
            let command = shell_command(&raw.tool_input)?;
            let (physical_cwd, cwd_assurance, cwd_resolution_source) =
                cwd_values(&raw.cwd, context.cwd_binding)?;
            HookEnvelope::PreToolUse {
                schema_version: "hook-envelope/v1".into(),
                envelope_id: context.envelope_id.clone(),
                occurred_at: context.occurred_at.clone(),
                client: Client::Claude,
                session_id: raw.session_id,
                adapter_turn_id: None,
                native_tool_call_id: raw.tool_use_id,
                prompt_context_id: None,
                native_tool_name: raw.tool_name,
                native_tool_input: raw.tool_input,
                tool_name: "shell_exec".into(),
                tool_input: json!({"command_text": command}),
                native_session_cwd: raw.cwd,
                physical_cwd,
                cwd_assurance,
                cwd_resolution_source,
            }
        }
        "PostToolUse" => {
            let raw: ClaudePost = from_slice(bytes)?;
            HookEnvelope::ToolResult {
                schema_version: "hook-envelope/v1".into(),
                envelope_id: context.envelope_id.clone(),
                occurred_at: context.occurred_at.clone(),
                client: Client::Claude,
                session_id: raw.session_id,
                adapter_turn_id: None,
                native_tool_call_id: raw.tool_use_id,
                prompt_context_id: None,
                native_tool_response: raw.tool_response,
                outcome: ToolOutcome::Success,
                exit_code: None,
            }
        }
        "PostToolUseFailure" => {
            let raw: ClaudeFailure = from_slice(bytes)?;
            HookEnvelope::ToolResult {
                schema_version: "hook-envelope/v1".into(),
                envelope_id: context.envelope_id.clone(),
                occurred_at: context.occurred_at.clone(),
                client: Client::Claude,
                session_id: raw.session_id,
                adapter_turn_id: None,
                native_tool_call_id: raw.tool_use_id,
                prompt_context_id: None,
                native_tool_response: json!({
                    "error": raw.error,
                    "is_interrupt": raw.is_interrupt
                }),
                outcome: ToolOutcome::Failure,
                exit_code: None,
            }
        }
        "Stop" => {
            let raw: ClaudeStop = from_slice(bytes)?;
            HookEnvelope::AssistantStop {
                schema_version: "hook-envelope/v1".into(),
                envelope_id: context.envelope_id.clone(),
                occurred_at: context.occurred_at.clone(),
                client: Client::Claude,
                session_id: raw.session_id,
                adapter_turn_id: None,
                native_tool_call_id: None,
                prompt_context_id: None,
                last_assistant_message: raw.last_assistant_message,
            }
        }
        _ => return Err(NativeMapError::UnsupportedEvent),
    };
    envelope.validate()?;
    Ok(envelope)
}

pub fn map_claude_prompt(bytes: &[u8]) -> Result<NativePromptObservation, NativeMapError> {
    let raw: ClaudePrompt = from_slice(bytes)?;
    if raw.hook_event_name != "UserPromptSubmit" {
        return Err(NativeMapError::UnsupportedEvent);
    }
    Ok(NativePromptObservation {
        schema_version: "m0-prompt-observation/v1".into(),
        client: Client::Claude,
        session_id: raw.session_id,
        adapter_turn_id: None,
        native_prompt_id: Some(raw.prompt_id),
        native_session_cwd: raw.cwd,
        prompt: raw.prompt,
        source_assurance: SourceAssurance::Unverified,
    })
}

pub fn map_codex_prompt(bytes: &[u8]) -> Result<NativePromptObservation, NativeMapError> {
    let raw: CodexPrompt = from_slice(bytes)?;
    if raw.hook_event_name != "UserPromptSubmit" {
        return Err(NativeMapError::UnsupportedEvent);
    }
    Ok(NativePromptObservation {
        schema_version: "m0-prompt-observation/v1".into(),
        client: Client::Codex,
        session_id: raw.session_id,
        adapter_turn_id: Some(raw.turn_id),
        native_prompt_id: None,
        native_session_cwd: raw.cwd,
        prompt: raw.prompt,
        source_assurance: SourceAssurance::Unverified,
    })
}

pub fn map_codex_native(
    bytes: &[u8],
    context: &NativeMapContext,
) -> Result<HookEnvelope, NativeMapError> {
    let event = native_event_name(bytes)?;
    let envelope = match event.as_str() {
        "PreToolUse" => {
            let raw: CodexPre = from_slice(bytes)?;
            if raw.tool_name != "Bash" {
                return Err(NativeMapError::UnsupportedTool);
            }
            let command = shell_command(&raw.tool_input)?;
            let (physical_cwd, cwd_assurance, cwd_resolution_source) =
                cwd_values(&raw.cwd, CwdBinding::UnsupportedPerCallWorkdir)?;
            HookEnvelope::PreToolUse {
                schema_version: "hook-envelope/v1".into(),
                envelope_id: context.envelope_id.clone(),
                occurred_at: context.occurred_at.clone(),
                client: Client::Codex,
                session_id: raw.session_id,
                adapter_turn_id: Some(raw.turn_id),
                native_tool_call_id: raw.tool_use_id,
                prompt_context_id: None,
                native_tool_name: raw.tool_name,
                native_tool_input: raw.tool_input,
                tool_name: "shell_exec".into(),
                tool_input: json!({"command_text": command}),
                native_session_cwd: raw.cwd,
                physical_cwd,
                cwd_assurance,
                cwd_resolution_source,
            }
        }
        "PostToolUse" => {
            let _: CodexPost = from_slice(bytes)?;
            return Err(NativeMapError::UnverifiedCodexResult);
        }
        "Stop" => {
            let raw: CodexStop = from_slice(bytes)?;
            HookEnvelope::AssistantStop {
                schema_version: "hook-envelope/v1".into(),
                envelope_id: context.envelope_id.clone(),
                occurred_at: context.occurred_at.clone(),
                client: Client::Codex,
                session_id: raw.session_id,
                adapter_turn_id: Some(raw.turn_id),
                native_tool_call_id: None,
                prompt_context_id: None,
                last_assistant_message: raw.last_assistant_message,
            }
        }
        _ => return Err(NativeMapError::UnsupportedEvent),
    };
    envelope.validate()?;
    Ok(envelope)
}

fn native_event_name(bytes: &[u8]) -> Result<String, NativeMapError> {
    let value: Value = from_slice(bytes)?;
    value
        .get("hook_event_name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(NativeMapError::UnsupportedEvent)
}

fn shell_command(tool_input: &Value) -> Result<String, NativeMapError> {
    let input: BashToolInput = serde_json::from_value(tool_input.clone())
        .map_err(|error| NativeMapError::Schema(format!("invalid Bash tool input: {error}")))?;
    Ok(input.command)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BashToolInput {
    command: String,
    #[serde(default, rename = "description")]
    _description: Option<String>,
}

fn cwd_values(
    native_cwd: &str,
    binding: CwdBinding,
) -> Result<(Option<String>, CwdAssurance, CwdResolutionSource), NativeMapError> {
    match binding {
        CwdBinding::VerifiedSimpleInvocation => {
            let path = Path::new(native_cwd);
            let physical = fs::canonicalize(path)
                .map_err(|_| NativeMapError::Schema("native cwd is unavailable".into()))?;
            if !path.is_absolute()
                || !fs::metadata(&physical).is_ok_and(|metadata| metadata.is_dir())
            {
                return Err(NativeMapError::Schema(
                    "native cwd is not an existing directory".into(),
                ));
            }
            let physical = physical
                .into_os_string()
                .into_string()
                .map_err(|_| NativeMapError::Schema("native cwd is not UTF-8".into()))?;
            Ok((
                Some(physical),
                CwdAssurance::Verified,
                CwdResolutionSource::M0EffectiveCwdBinding,
            ))
        }
        CwdBinding::UnsupportedPerCallWorkdir => Ok((
            None,
            CwdAssurance::Unverified,
            CwdResolutionSource::Unavailable,
        )),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ClaudePre {
    session_id: String,
    transcript_path: String,
    cwd: String,
    prompt_id: String,
    permission_mode: String,
    #[serde(default)]
    effort: Option<ClaudeEffort>,
    hook_event_name: String,
    tool_name: String,
    tool_input: Value,
    tool_use_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ClaudePrompt {
    session_id: String,
    transcript_path: String,
    cwd: String,
    prompt_id: String,
    permission_mode: String,
    #[serde(default)]
    effort: Option<ClaudeEffort>,
    hook_event_name: String,
    prompt: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ClaudePost {
    session_id: String,
    transcript_path: String,
    cwd: String,
    prompt_id: String,
    permission_mode: String,
    #[serde(default)]
    effort: Option<ClaudeEffort>,
    hook_event_name: String,
    tool_name: String,
    tool_input: Value,
    tool_response: Value,
    tool_use_id: String,
    duration_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ClaudeFailure {
    session_id: String,
    transcript_path: String,
    cwd: String,
    prompt_id: String,
    permission_mode: String,
    #[serde(default)]
    effort: Option<ClaudeEffort>,
    hook_event_name: String,
    tool_name: String,
    tool_input: Value,
    tool_use_id: String,
    error: String,
    is_interrupt: bool,
    duration_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ClaudeStop {
    session_id: String,
    transcript_path: String,
    cwd: String,
    prompt_id: String,
    permission_mode: String,
    #[serde(default)]
    effort: Option<ClaudeEffort>,
    hook_event_name: String,
    stop_hook_active: bool,
    #[serde(deserialize_with = "required_nullable")]
    last_assistant_message: Option<String>,
    background_tasks: Vec<Value>,
    session_crons: Vec<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ClaudeEffort {
    level: ClaudeEffortLevel,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum ClaudeEffortLevel {
    Low,
    Medium,
    High,
    Xhigh,
    Max,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct CodexPre {
    session_id: String,
    turn_id: String,
    #[serde(deserialize_with = "required_nullable")]
    transcript_path: Option<String>,
    cwd: String,
    hook_event_name: String,
    model: String,
    permission_mode: String,
    tool_name: String,
    tool_input: Value,
    tool_use_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct CodexPrompt {
    session_id: String,
    turn_id: String,
    #[serde(deserialize_with = "required_nullable")]
    transcript_path: Option<String>,
    cwd: String,
    hook_event_name: String,
    model: String,
    permission_mode: String,
    prompt: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct CodexPost {
    session_id: String,
    turn_id: String,
    #[serde(deserialize_with = "required_nullable")]
    transcript_path: Option<String>,
    cwd: String,
    hook_event_name: String,
    model: String,
    permission_mode: String,
    tool_name: String,
    tool_input: Value,
    tool_response: Value,
    tool_use_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct CodexStop {
    session_id: String,
    turn_id: String,
    #[serde(deserialize_with = "required_nullable")]
    transcript_path: Option<String>,
    cwd: String,
    hook_event_name: String,
    model: String,
    permission_mode: String,
    stop_hook_active: bool,
    #[serde(deserialize_with = "required_nullable")]
    last_assistant_message: Option<String>,
}
