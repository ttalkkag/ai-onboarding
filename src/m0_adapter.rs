#![cfg(feature = "m0-test-profile")]

use crate::adapter_runtime::{CoreChild, CoreChildError, run_core_child};
use crate::contracts::{HookEnvelope, ToolOutcome};
use crate::m0::{
    Client, EvaluationMetadata, Invocation, M0ActionDecision, M0ActionRequest, M0Error, M0Event,
    Outcome, ResultMetadata, fallback, record_result,
};
use crate::m0_profile::{
    BindingResult, LoadProfileRequest, M0ProfileClient, M0Sentinel, ProfileError, load_profile,
};
use crate::m0_secure_fs::{create_private_file, require_private_directory, require_private_file};
use crate::native::{
    CwdBinding, NativeMapContext, NativeMapError, NativeResponseError, PreResponse,
    encode_pre_response, map_claude_native, map_codex_native,
};
use crate::strict_json::{canonical_bytes, from_slice};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SentinelBinding {
    Matched,
    HelperHashMismatch,
    ArgvMismatch,
    CwdUnverified,
}

#[derive(Clone, Debug)]
pub struct AdapterConfig {
    pub client: Client,
    pub profile_path: PathBuf,
    pub expected_profile_digest: String,
    pub trusted_source_root: PathBuf,
    pub target_project_root: PathBuf,
    pub observed_runtime_version_output: String,
    pub observed_shell_resolution_fingerprint: String,
    pub cwd_binding: CwdBinding,
    pub test_case_id: String,
    pub test_run_id: String,
    pub action_id: String,
    pub envelope_id: String,
    pub decision_id: String,
    pub event_ids: [String; 2],
    pub observed_at: String,
    pub core: CoreChild,
}

#[derive(Clone, Debug)]
pub struct ResultConfig {
    pub client: Client,
    pub envelope_id: String,
    pub observed_at: String,
    pub event_id: String,
    pub cwd_binding: CwdBinding,
}

#[derive(Clone, Debug)]
pub struct M0PreOutcome {
    pub envelope: HookEnvelope,
    pub binding: SentinelBinding,
    pub request: Option<M0ActionRequest>,
    pub decision: Option<M0ActionDecision>,
    pub events: Vec<M0Event>,
    pub native_response: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct M0ResultOutcome {
    pub envelope: HookEnvelope,
    pub event: Option<M0Event>,
    pub native_response: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum M0AdapterError {
    #[error("native payload mapping failed: {0}")]
    Native(#[from] NativeMapError),
    #[error("test profile could not be loaded: {0}")]
    Profile(#[from] ProfileError),
    #[error("test profile client does not match the native client")]
    ClientMismatch,
    #[error("core child failed without a valid adapter fallback: {0}")]
    Core(#[from] CoreChildError),
    #[error("M0 correlation store failed")]
    Store,
    #[error("M0 result has no matching decision")]
    MissingDecision,
    #[error("M0 contract failed: {0}")]
    Contract(#[from] M0Error),
    #[error("native response encoding failed: {0}")]
    Response(#[from] NativeResponseError),
}

#[derive(Clone, Debug)]
pub struct CorrelationStore {
    root: PathBuf,
}

#[derive(Debug, Default)]
pub struct CorrelationPreparation {
    delivery: Option<(PathBuf, Vec<u8>)>,
}

impl CorrelationPreparation {
    pub fn mark_delivered(&self) -> Result<(), M0AdapterError> {
        let Some((path, expected_bytes)) = &self.delivery else {
            return Ok(());
        };
        match create_private_file(path, expected_bytes) {
            Ok(()) => Ok(()),
            Err(_) if path.exists() => {
                require_private_file(path).map_err(|_| M0AdapterError::Store)?;
                if fs::read(path).map_err(|_| M0AdapterError::Store)? == *expected_bytes {
                    Ok(())
                } else {
                    Err(M0AdapterError::Store)
                }
            }
            Err(_) => Err(M0AdapterError::Store),
        }
    }
}

impl CorrelationStore {
    pub fn new(root: PathBuf) -> Result<Self, M0AdapterError> {
        require_private_directory(&root).map_err(|_| M0AdapterError::Store)?;
        Ok(Self { root })
    }

    fn save(&self, decision: &M0ActionDecision) -> Result<CorrelationPreparation, M0AdapterError> {
        let path = self.path(
            decision.client,
            &decision.session_fixture_id,
            &decision.native_tool_call_id,
        );
        let mut bytes = canonical_bytes(decision).map_err(|_| M0AdapterError::Store)?;
        bytes.push(b'\n');
        let delivery = Some((
            self.delivery_path(
                decision.client,
                &decision.session_fixture_id,
                &decision.native_tool_call_id,
            ),
            delivery_bytes(&bytes),
        ));
        match create_private_file(&path, &bytes) {
            Ok(()) => Ok(CorrelationPreparation { delivery }),
            Err(_) if path.exists() => {
                require_private_file(&path).map_err(|_| M0AdapterError::Store)?;
                let existing = fs::read(path).map_err(|_| M0AdapterError::Store)?;
                let existing: M0ActionDecision =
                    from_slice(&existing).map_err(|_| M0AdapterError::Store)?;
                if existing == *decision {
                    Ok(CorrelationPreparation { delivery })
                } else {
                    Err(M0AdapterError::Store)
                }
            }
            Err(_) => Err(M0AdapterError::Store),
        }
    }

    fn load(
        &self,
        client: Client,
        session_fixture_id: &str,
        native_tool_call_id: &str,
    ) -> Result<M0ActionDecision, M0AdapterError> {
        let path = self.path(client, session_fixture_id, native_tool_call_id);
        if path.exists() {
            require_private_file(&path).map_err(|_| M0AdapterError::Store)?;
        }
        let bytes = fs::read(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                M0AdapterError::MissingDecision
            } else {
                M0AdapterError::Store
            }
        })?;
        let delivery_path = self.delivery_path(client, session_fixture_id, native_tool_call_id);
        if delivery_path.exists() {
            require_private_file(&delivery_path).map_err(|_| M0AdapterError::Store)?;
        }
        let delivered = fs::read(delivery_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                M0AdapterError::MissingDecision
            } else {
                M0AdapterError::Store
            }
        })?;
        if delivered != delivery_bytes(&bytes) {
            return Err(M0AdapterError::Store);
        }
        from_slice(&bytes).map_err(|_| M0AdapterError::Store)
    }

    fn path(&self, client: Client, session_id: &str, tool_id: &str) -> PathBuf {
        self.root.join(format!(
            "{}.json",
            correlation_key(client, session_id, tool_id)
        ))
    }

    fn delivery_path(&self, client: Client, session_id: &str, tool_id: &str) -> PathBuf {
        self.root.join(format!(
            "{}.delivered",
            correlation_key(client, session_id, tool_id)
        ))
    }
}

fn correlation_key(client: Client, session_id: &str, tool_id: &str) -> String {
    let client = match client {
        Client::Claude => b"claude".as_slice(),
        Client::Codex => b"codex".as_slice(),
    };
    let mut hasher = Sha256::new();
    hasher.update(b"secure-onboard:m0-correlation/v1\n");
    hasher.update(client);
    hasher.update([0]);
    hasher.update(session_id.as_bytes());
    hasher.update([0]);
    hasher.update(tool_id.as_bytes());
    hex::encode(hasher.finalize())
}

fn delivery_bytes(decision_bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"secure-onboard:m0-correlation-delivered/v1\n");
    hasher.update(decision_bytes);
    format!("sha256:{}\n", hex::encode(hasher.finalize())).into_bytes()
}

pub fn prepare_pre_outcome(
    outcome: &M0PreOutcome,
    store: &CorrelationStore,
) -> Result<Option<CorrelationPreparation>, M0AdapterError> {
    if let Some(decision) = &outcome.decision
        && decision.severity != crate::m0::Severity::High
    {
        return store.save(decision).map(Some);
    }
    Ok(None)
}

pub fn handle_pre_tool_use(
    native_bytes: &[u8],
    config: &AdapterConfig,
) -> Result<M0PreOutcome, M0AdapterError> {
    let context = NativeMapContext {
        envelope_id: config.envelope_id.clone(),
        occurred_at: config.observed_at.clone(),
        cwd_binding: config.cwd_binding,
    };
    let envelope = map_native(config.client, native_bytes, &context)?;
    let profile = load_profile(LoadProfileRequest {
        profile_path: Some(&config.profile_path),
        compile_time_expected_digest: &config.expected_profile_digest,
        trusted_source_root: &config.trusted_source_root,
        target_project_root: &config.target_project_root,
        expected_client: match config.client {
            Client::Claude => M0ProfileClient::Claude,
            Client::Codex => M0ProfileClient::Codex,
        },
        expected_client_version: match config.client {
            Client::Claude => "2.1.220",
            Client::Codex => "0.146.0",
        },
        expected_os: "macos",
        expected_architecture: "arm64",
        observed_runtime_version_output: &config.observed_runtime_version_output,
        observed_shell_resolution_fingerprint: &config.observed_shell_resolution_fingerprint,
    })?;
    if profile_client(profile.client()) != config.client {
        return Err(M0AdapterError::ClientMismatch);
    }

    let (session_id, native_tool_call_id, command_text, physical_cwd, cwd_resolution_source) =
        match &envelope {
            HookEnvelope::PreToolUse {
                session_id,
                native_tool_call_id,
                tool_input,
                physical_cwd,
                cwd_resolution_source,
                ..
            } => (
                session_id,
                native_tool_call_id,
                tool_input
                    .get("command_text")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| NativeMapError::Schema("canonical command is missing".into()))?,
                physical_cwd,
                cwd_resolution_source,
            ),
            _ => return Err(NativeMapError::UnsupportedEvent.into()),
        };

    if physical_cwd.is_none() {
        return neutral(envelope, config.client, SentinelBinding::CwdUnverified);
    }
    let binding = profile.match_command(command_text, &config.test_run_id, &config.test_case_id);
    let sentinel = match binding {
        BindingResult::Matched { sentinel } => sentinel,
        BindingResult::HelperHashMismatch => {
            return neutral(envelope, config.client, SentinelBinding::HelperHashMismatch);
        }
        BindingResult::ArgvMismatch => {
            return neutral(envelope, config.client, SentinelBinding::ArgvMismatch);
        }
    };

    let request = M0ActionRequest {
        schema_version: "m0-action-request/v1".into(),
        phase: "m0".into(),
        test_case_id: config.test_case_id.clone(),
        test_run_id: config.test_run_id.clone(),
        test_profile_digest: profile.supplied_digest().into(),
        action_id: config.action_id.clone(),
        envelope_id: config.envelope_id.clone(),
        client: config.client,
        session_fixture_id: session_id.clone(),
        native_tool_call_id: native_tool_call_id.clone(),
        sentinel: m0_sentinel(sentinel),
        invocation: Invocation::ShellText {
            shell_executable: profile
                .shell_executable_path()
                .to_string_lossy()
                .into_owned(),
            shell_flags: profile.shell_flags().to_vec(),
            dialect: profile.shell_dialect().into(),
            command_text: command_text.into(),
            shell_resolution_source: "m0_runtime_probe".into(),
            shell_resolution_fingerprint: profile.shell_resolution_fingerprint().into(),
        },
        physical_cwd_fixture: physical_cwd.clone().expect("checked non-null cwd"),
        cwd_resolution_source: match cwd_resolution_source {
            crate::contracts::CwdResolutionSource::M0EffectiveCwdBinding => {
                "m0_effective_cwd_binding".into()
            }
            crate::contracts::CwdResolutionSource::NativeEffectiveCwd => {
                "native_effective_cwd".into()
            }
            crate::contracts::CwdResolutionSource::Unavailable => {
                return neutral(envelope, config.client, SentinelBinding::CwdUnverified);
            }
        },
    };
    let metadata = EvaluationMetadata {
        decision_id: config.decision_id.clone(),
        event_ids: config.event_ids.clone(),
        observed_at: config.observed_at.clone(),
    };
    let core_output = match run_core_child(&config.core, &request, &metadata) {
        Ok(output) => output,
        Err(error) => match error.fallback_failure() {
            Some(failure) => fallback(&request, metadata, failure),
            None => return Err(error.into()),
        },
    };
    let response = response_for_decision(&core_output.decision)?;

    Ok(M0PreOutcome {
        envelope,
        binding: SentinelBinding::Matched,
        request: Some(request),
        decision: Some(core_output.decision),
        events: core_output.events,
        native_response: response,
    })
}

pub fn handle_tool_result(
    native_bytes: &[u8],
    config: &ResultConfig,
    store: &CorrelationStore,
) -> Result<M0ResultOutcome, M0AdapterError> {
    let context = NativeMapContext {
        envelope_id: config.envelope_id.clone(),
        occurred_at: config.observed_at.clone(),
        cwd_binding: config.cwd_binding,
    };
    let envelope = map_native(config.client, native_bytes, &context)?;
    let (session_id, native_tool_call_id, outcome) = match &envelope {
        HookEnvelope::ToolResult {
            session_id,
            native_tool_call_id,
            outcome,
            ..
        } => (session_id, native_tool_call_id, *outcome),
        _ => return Err(NativeMapError::UnsupportedEvent.into()),
    };
    let event = match store.load(config.client, session_id, native_tool_call_id) {
        Ok(decision) => Some(record_result(
            &decision,
            ResultMetadata {
                event_id: config.event_id.clone(),
                observed_at: config.observed_at.clone(),
                client: config.client,
                session_fixture_id: session_id.clone(),
                native_tool_call_id: native_tool_call_id.clone(),
                outcome: match outcome {
                    ToolOutcome::Success => Outcome::Success,
                    ToolOutcome::Failure => Outcome::Failure,
                },
            },
        )?),
        Err(M0AdapterError::MissingDecision) => None,
        Err(error) => return Err(error),
    };
    Ok(M0ResultOutcome {
        envelope,
        event,
        native_response: encode_pre_response(config.client, &PreResponse::Neutral)?,
    })
}

fn map_native(
    client: Client,
    native_bytes: &[u8],
    context: &NativeMapContext,
) -> Result<HookEnvelope, NativeMapError> {
    match client {
        Client::Claude => map_claude_native(native_bytes, context),
        Client::Codex => map_codex_native(native_bytes, context),
    }
}

fn neutral(
    envelope: HookEnvelope,
    client: Client,
    binding: SentinelBinding,
) -> Result<M0PreOutcome, M0AdapterError> {
    Ok(M0PreOutcome {
        envelope,
        binding,
        request: None,
        decision: None,
        events: Vec::new(),
        native_response: encode_pre_response(client, &PreResponse::Neutral)?,
    })
}

fn response_for_decision(decision: &M0ActionDecision) -> Result<Vec<u8>, NativeResponseError> {
    let response = match decision.severity {
        crate::m0::Severity::High => PreResponse::High {
            system_message: "Secure Onboard M0: HIGH action blocked.".into(),
            reason: if decision.decision_source == crate::m0::DecisionSource::AdapterFallback {
                "Secure Onboard M0 core failure"
            } else {
                "Secure Onboard M0 HIGH sentinel"
            }
            .into(),
        },
        crate::m0::Severity::Low => PreResponse::Low {
            system_message: "Secure Onboard M0: LOW warning.".into(),
        },
        crate::m0::Severity::Info => PreResponse::Info,
    };
    encode_pre_response(decision.client, &response)
}

fn profile_client(client: M0ProfileClient) -> Client {
    match client {
        M0ProfileClient::Claude => Client::Claude,
        M0ProfileClient::Codex => Client::Codex,
    }
}

fn m0_sentinel(sentinel: M0Sentinel) -> crate::m0::Sentinel {
    match sentinel {
        M0Sentinel::High => crate::m0::Sentinel::High,
        M0Sentinel::Low => crate::m0::Sentinel::Low,
        M0Sentinel::Info => crate::m0::Sentinel::Info,
    }
}
