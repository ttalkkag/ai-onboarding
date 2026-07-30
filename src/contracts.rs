use crate::m0::Client;
use crate::strict_json::required_nullable;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookEvent {
    PreToolUse,
    ToolResult,
    AssistantStop,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CwdAssurance {
    Verified,
    Unverified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CwdResolutionSource {
    NativeEffectiveCwd,
    M0EffectiveCwdBinding,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolOutcome {
    Success,
    Failure,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "hook_event", rename_all = "snake_case", deny_unknown_fields)]
pub enum HookEnvelope {
    PreToolUse {
        schema_version: String,
        envelope_id: String,
        occurred_at: String,
        client: Client,
        session_id: String,
        #[serde(deserialize_with = "required_nullable")]
        adapter_turn_id: Option<String>,
        native_tool_call_id: String,
        #[serde(deserialize_with = "required_nullable")]
        prompt_context_id: Option<String>,
        native_tool_name: String,
        native_tool_input: Value,
        tool_name: String,
        tool_input: Value,
        native_session_cwd: String,
        #[serde(deserialize_with = "required_nullable")]
        physical_cwd: Option<String>,
        cwd_assurance: CwdAssurance,
        cwd_resolution_source: CwdResolutionSource,
    },
    ToolResult {
        schema_version: String,
        envelope_id: String,
        occurred_at: String,
        client: Client,
        session_id: String,
        #[serde(deserialize_with = "required_nullable")]
        adapter_turn_id: Option<String>,
        native_tool_call_id: String,
        #[serde(deserialize_with = "required_nullable")]
        prompt_context_id: Option<String>,
        native_tool_response: Value,
        outcome: ToolOutcome,
        #[serde(deserialize_with = "required_nullable")]
        exit_code: Option<i32>,
    },
    AssistantStop {
        schema_version: String,
        envelope_id: String,
        occurred_at: String,
        client: Client,
        session_id: String,
        #[serde(deserialize_with = "required_nullable")]
        adapter_turn_id: Option<String>,
        #[serde(deserialize_with = "required_nullable")]
        native_tool_call_id: Option<String>,
        #[serde(deserialize_with = "required_nullable")]
        prompt_context_id: Option<String>,
        #[serde(deserialize_with = "required_nullable")]
        last_assistant_message: Option<String>,
    },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HookEnvelopeError {
    #[error("invalid HookEnvelope schema version")]
    SchemaVersion,
    #[error("Codex envelope is missing its native turn ID")]
    CodexTurnId,
    #[error("invalid effective cwd binding")]
    CwdBinding,
    #[error("Stop envelope must not identify a tool call")]
    StopToolCall,
}

impl HookEnvelope {
    pub fn hook_event(&self) -> HookEvent {
        match self {
            Self::PreToolUse { .. } => HookEvent::PreToolUse,
            Self::ToolResult { .. } => HookEvent::ToolResult,
            Self::AssistantStop { .. } => HookEvent::AssistantStop,
        }
    }

    pub fn validate(&self) -> Result<(), HookEnvelopeError> {
        let (schema_version, client, adapter_turn_id) = match self {
            Self::PreToolUse {
                schema_version,
                client,
                adapter_turn_id,
                ..
            }
            | Self::ToolResult {
                schema_version,
                client,
                adapter_turn_id,
                ..
            }
            | Self::AssistantStop {
                schema_version,
                client,
                adapter_turn_id,
                ..
            } => (schema_version, client, adapter_turn_id),
        };

        if schema_version != "hook-envelope/v1" {
            return Err(HookEnvelopeError::SchemaVersion);
        }
        if *client == Client::Codex && adapter_turn_id.is_none() {
            return Err(HookEnvelopeError::CodexTurnId);
        }

        match self {
            Self::PreToolUse {
                physical_cwd,
                cwd_assurance,
                cwd_resolution_source,
                ..
            } => match (cwd_assurance, cwd_resolution_source, physical_cwd) {
                (
                    CwdAssurance::Verified,
                    CwdResolutionSource::NativeEffectiveCwd
                    | CwdResolutionSource::M0EffectiveCwdBinding,
                    Some(_),
                )
                | (CwdAssurance::Unverified, CwdResolutionSource::Unavailable, None) => Ok(()),
                _ => Err(HookEnvelopeError::CwdBinding),
            },
            Self::AssistantStop {
                native_tool_call_id,
                ..
            } if native_tool_call_id.is_some() => Err(HookEnvelopeError::StopToolCall),
            _ => Ok(()),
        }
    }
}
