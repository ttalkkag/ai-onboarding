#![cfg(feature = "m0-test-profile")]

use secure_onboard::adapter_runtime::{CoreChild, CoreFault};
use secure_onboard::m0::Client;
use secure_onboard::m0_adapter::{
    AdapterConfig, CorrelationStore, ResultConfig, handle_pre_tool_use, handle_tool_result,
    prepare_pre_outcome,
};
use secure_onboard::m0_profile::{M0ProfileClient, embedded_profile_digest};
use secure_onboard::m0_secure_fs::{
    create_private_file, create_private_subdirectory, require_private_directory,
    require_private_file,
};
use secure_onboard::native::{
    CwdBinding, NativeMapContext, PreResponse, encode_pre_response, map_claude_native,
    map_claude_prompt, map_codex_native, map_codex_prompt,
};
use secure_onboard::strict_json::canonical_bytes;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const MAX_NATIVE_INPUT_BYTES: u64 = 1024 * 1024;
const RUNTIME_VERSION: &str = "v26.5.0";
const SHELL_FINGERPRINT: &str =
    "sha256:432334cf54611c3d90f428d656721a8919dc591f398ef34f8c7b997b2879ccd0";
static PRE_RESPONSE_ATTEMPTED: AtomicBool = AtomicBool::new(false);

fn main() -> ExitCode {
    let pre_tool_mode = is_pre_tool_mode();
    let fail_closed_client = pre_tool_client();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            if let Some(client) = fail_closed_client
                && !PRE_RESPONSE_ATTEMPTED.load(Ordering::SeqCst)
            {
                let response = encode_pre_response(
                    client,
                    &PreResponse::High {
                        system_message: "Secure Onboard M0: adapter failure blocked the action."
                            .into(),
                        reason: "Secure Onboard M0 adapter failure".into(),
                    },
                );
                if let Ok(response) = response {
                    let mut stdout = std::io::stdout().lock();
                    if stdout
                        .write_all(&response)
                        .and_then(|_| stdout.flush())
                        .is_ok()
                    {
                        let _ =
                            std::io::stderr().write_all(b"Secure Onboard M0 hook failed closed\n");
                        return ExitCode::SUCCESS;
                    }
                }
            }
            let _ = std::io::stderr().write_all(b"Secure Onboard M0 hook failed\n");
            ExitCode::from(if pre_tool_mode { 2 } else { 70 })
        }
    }
}

fn is_pre_tool_mode() -> bool {
    std::env::args_os().nth(1).is_some_and(|mode| mode == "pre")
}

fn pre_tool_client() -> Option<Client> {
    let mut arguments = std::env::args_os();
    arguments.next()?;
    if arguments.next()?.to_str()? != "pre" {
        return None;
    }
    let mut client = None;
    while let Some(key) = arguments.next() {
        let value = arguments.next()?;
        if key == "--client" {
            if client.is_some() {
                return None;
            }
            client = parse_client(value.to_str()?).ok();
        }
    }
    client
}

fn run() -> Result<(), ()> {
    let mut raw_arguments = std::env::args_os();
    let _program = raw_arguments.next();
    let mode = raw_arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(())?;
    let mut arguments = Arguments::parse(raw_arguments)?;
    let native_input = read_native_input()?;

    match mode.as_str() {
        "prompt" => run_prompt(&mut arguments, &native_input),
        "pre" => run_pre(&mut arguments, &native_input),
        "result" => run_result(&mut arguments, &native_input),
        "stop" => run_stop(&mut arguments, &native_input),
        _ => Err(()),
    }
}

fn run_prompt(arguments: &mut Arguments, native_input: &[u8]) -> Result<(), ()> {
    let client = parse_client(&arguments.take("--client")?)?;
    let evidence_root = arguments.take_path("--evidence-root")?;
    arguments.finish()?;

    record_bytes(&evidence_root, "native-input", native_input)?;
    let observation = match client {
        Client::Claude => map_claude_prompt(native_input),
        Client::Codex => map_codex_prompt(native_input),
    }
    .map_err(|_| ())?;
    record_object(&evidence_root, "m0-prompt-observation", &observation)?;
    let output = encode_pre_response(client, &PreResponse::Neutral).map_err(|_| ())?;
    record_bytes(&evidence_root, "native-output", &output)?;
    std::io::stdout().write_all(&output).map_err(|_| ())
}

fn run_pre(arguments: &mut Arguments, native_input: &[u8]) -> Result<(), ()> {
    let client = parse_client(&arguments.take("--client")?)?;
    let profile_path = arguments.take_path("--profile")?;
    let trusted_source_root = arguments.take_path("--trusted-root")?;
    let target_project_root = arguments.take_path("--target-root")?;
    let state_root = arguments.take_path("--state-root")?;
    let evidence_root = arguments.take_path("--evidence-root")?;
    let test_case_id = arguments.take("--test-case")?;
    let test_run_id = arguments.take("--test-run")?;
    let mut action_id = arguments.take("--action-id")?;
    let mut envelope_id = arguments.take("--envelope-id")?;
    let mut decision_id = arguments.take("--decision-id")?;
    let mut event_ids = [
        arguments.take("--event-id-1")?,
        arguments.take("--event-id-2")?,
    ];
    let observed_at = arguments.take("--observed-at")?;
    let core_executable = sibling_core_executable()?;
    let core_timeout_ms = arguments
        .take("--core-timeout-ms")?
        .parse::<u64>()
        .map_err(|_| ())?;
    if !(1..=4_000).contains(&core_timeout_ms) {
        return Err(());
    }
    let core_fault = parse_core_fault(&arguments.take("--core-fault")?)?;
    let cwd_binding = parse_cwd_binding(&arguments.take("--cwd-binding")?)?;
    let id_binding = parse_id_binding(
        arguments
            .take_optional("--id-binding")?
            .as_deref()
            .unwrap_or("literal"),
    )?;
    let post_response_fault = match arguments.take_optional("--post-response-fault")?.as_deref() {
        None => false,
        Some("evidence-write") => true,
        Some(_) => return Err(()),
    };
    arguments.finish()?;
    action_id = bind_id(id_binding, "action", &action_id, native_input);
    envelope_id = bind_id(id_binding, "envelope", &envelope_id, native_input);
    decision_id = bind_id(id_binding, "decision", &decision_id, native_input);
    event_ids[0] = bind_id(id_binding, "event-1", &event_ids[0], native_input);
    event_ids[1] = bind_id(id_binding, "event-2", &event_ids[1], native_input);

    record_bytes(&evidence_root, "native-input", native_input)?;
    let expected_profile_digest = embedded_profile_digest(match client {
        Client::Claude => M0ProfileClient::Claude,
        Client::Codex => M0ProfileClient::Codex,
    });
    let store = CorrelationStore::new(state_root).map_err(|_| ())?;
    let outcome = handle_pre_tool_use(
        native_input,
        &AdapterConfig {
            client,
            profile_path,
            expected_profile_digest,
            trusted_source_root: trusted_source_root.clone(),
            target_project_root,
            observed_runtime_version_output: RUNTIME_VERSION.into(),
            observed_shell_resolution_fingerprint: SHELL_FINGERPRINT.into(),
            cwd_binding,
            test_case_id,
            test_run_id,
            action_id,
            envelope_id,
            decision_id,
            event_ids,
            observed_at,
            core: CoreChild {
                executable: core_executable,
                working_directory: trusted_source_root,
                timeout: Duration::from_millis(core_timeout_ms),
                fault: core_fault,
            },
        },
    )
    .map_err(|_| ())?;

    preflight_pre_evidence(&evidence_root, &outcome)?;
    let correlation = prepare_pre_outcome(&outcome, &store).map_err(|_| ())?;
    write_pre_response(&outcome.native_response)?;
    if post_response_fault {
        return Err(());
    }

    record_object(&evidence_root, "hook-envelope", &outcome.envelope)?;
    if let Some(request) = &outcome.request {
        record_object(&evidence_root, "m0-action-request", request)?;
    }
    record_decision_evidence(&evidence_root, &outcome)?;
    record_bytes(&evidence_root, "native-output", &outcome.native_response)?;
    if let Some(correlation) = correlation {
        correlation.mark_delivered().map_err(|_| ())?;
    }
    Ok(())
}

fn preflight_pre_evidence(
    evidence_root: &Path,
    outcome: &secure_onboard::m0_adapter::M0PreOutcome,
) -> Result<(), ()> {
    preflight_object(evidence_root, "hook-envelope", &outcome.envelope)?;
    if let Some(request) = &outcome.request {
        preflight_object(evidence_root, "m0-action-request", request)?;
    }
    if let Some(decision) = &outcome.decision {
        preflight_object(evidence_root, "m0-action-decision", decision)?;
    }
    for event in &outcome.events {
        preflight_object(evidence_root, "m0-event", event)?;
    }
    preflight_bytes(evidence_root, "native-output", &outcome.native_response)
}

fn record_decision_evidence(
    evidence_root: &Path,
    outcome: &secure_onboard::m0_adapter::M0PreOutcome,
) -> Result<(), ()> {
    if let Some(decision) = &outcome.decision {
        record_object(evidence_root, "m0-action-decision", decision)?;
    }
    for event in &outcome.events {
        record_object(evidence_root, "m0-event", event)?;
    }
    Ok(())
}

fn write_pre_response(bytes: &[u8]) -> Result<(), ()> {
    PRE_RESPONSE_ATTEMPTED.store(true, Ordering::SeqCst);
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|_| stdout.flush())
        .map_err(|_| ())
}

fn run_result(arguments: &mut Arguments, native_input: &[u8]) -> Result<(), ()> {
    let client = parse_client(&arguments.take("--client")?)?;
    let state_root = arguments.take_path("--state-root")?;
    let evidence_root = arguments.take_path("--evidence-root")?;
    let mut envelope_id = arguments.take("--envelope-id")?;
    let observed_at = arguments.take("--observed-at")?;
    let mut event_id = arguments.take("--event-id")?;
    let cwd_binding = parse_cwd_binding(&arguments.take("--cwd-binding")?)?;
    let id_binding = parse_id_binding(
        arguments
            .take_optional("--id-binding")?
            .as_deref()
            .unwrap_or("literal"),
    )?;
    arguments.finish()?;
    envelope_id = bind_id(id_binding, "envelope", &envelope_id, native_input);
    event_id = bind_id(id_binding, "event", &event_id, native_input);

    record_bytes(&evidence_root, "native-input", native_input)?;
    let outcome = handle_tool_result(
        native_input,
        &ResultConfig {
            client,
            envelope_id,
            observed_at,
            event_id,
            cwd_binding,
        },
        &CorrelationStore::new(state_root).map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    record_object(&evidence_root, "hook-envelope", &outcome.envelope)?;
    if let Some(event) = &outcome.event {
        record_object(&evidence_root, "m0-event", event)?;
    }
    record_bytes(&evidence_root, "native-output", &outcome.native_response)?;
    std::io::stdout()
        .write_all(&outcome.native_response)
        .map_err(|_| ())
}

fn run_stop(arguments: &mut Arguments, native_input: &[u8]) -> Result<(), ()> {
    let client = parse_client(&arguments.take("--client")?)?;
    let evidence_root = arguments.take_path("--evidence-root")?;
    let mut envelope_id = arguments.take("--envelope-id")?;
    let observed_at = arguments.take("--observed-at")?;
    let cwd_binding = parse_cwd_binding(&arguments.take("--cwd-binding")?)?;
    let id_binding = parse_id_binding(
        arguments
            .take_optional("--id-binding")?
            .as_deref()
            .unwrap_or("literal"),
    )?;
    arguments.finish()?;
    envelope_id = bind_id(id_binding, "envelope", &envelope_id, native_input);

    record_bytes(&evidence_root, "native-input", native_input)?;
    let context = NativeMapContext {
        envelope_id,
        occurred_at: observed_at,
        cwd_binding,
    };
    let envelope = match client {
        Client::Claude => map_claude_native(native_input, &context),
        Client::Codex => map_codex_native(native_input, &context),
    }
    .map_err(|_| ())?;
    record_object(&evidence_root, "hook-envelope", &envelope)?;
    let output = encode_pre_response(client, &PreResponse::Neutral).map_err(|_| ())?;
    record_bytes(&evidence_root, "native-output", &output)?;
    std::io::stdout().write_all(&output).map_err(|_| ())
}

fn sibling_core_executable() -> Result<PathBuf, ()> {
    let hook = std::env::current_exe().map_err(|_| ())?;
    let hook_metadata = fs::symlink_metadata(&hook).map_err(|_| ())?;
    if !hook_metadata.file_type().is_file() {
        return Err(());
    }
    let core = hook.parent().ok_or(())?.join(format!(
        "secure-onboard-m0-core{}",
        std::env::consts::EXE_SUFFIX
    ));
    let core_metadata = fs::symlink_metadata(&core).map_err(|_| ())?;
    if !core_metadata.file_type().is_file() {
        return Err(());
    }
    Ok(core)
}

fn read_native_input() -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_NATIVE_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > MAX_NATIVE_INPUT_BYTES {
        return Err(());
    }
    Ok(bytes)
}

fn record_object(evidence_root: &Path, kind: &str, value: &impl Serialize) -> Result<(), ()> {
    let mut bytes = canonical_bytes(value).map_err(|_| ())?;
    bytes.push(b'\n');
    record_bytes(evidence_root, kind, &bytes)
}

fn preflight_object(evidence_root: &Path, kind: &str, value: &impl Serialize) -> Result<(), ()> {
    let mut bytes = canonical_bytes(value).map_err(|_| ())?;
    bytes.push(b'\n');
    preflight_bytes(evidence_root, kind, &bytes)
}

fn preflight_bytes(evidence_root: &Path, kind: &str, bytes: &[u8]) -> Result<(), ()> {
    require_private_directory(evidence_root).map_err(|_| ())?;
    let directory = create_private_subdirectory(evidence_root, kind).map_err(|_| ())?;
    let digest = hex::encode(Sha256::digest(bytes));
    let path = directory.join(format!("{digest}.bin"));
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            require_private_file(&path).map_err(|_| ())?;
            if fs::read(path).map_err(|_| ())? == bytes {
                Ok(())
            } else {
                Err(())
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(()),
    }
}

fn record_bytes(evidence_root: &Path, kind: &str, bytes: &[u8]) -> Result<(), ()> {
    require_private_directory(evidence_root).map_err(|_| ())?;
    let directory = create_private_subdirectory(evidence_root, kind).map_err(|_| ())?;
    let digest = hex::encode(Sha256::digest(bytes));
    let path = directory.join(format!("{digest}.bin"));
    match create_private_file(&path, bytes) {
        Ok(()) => Ok(()),
        Err(_) if path.exists() => {
            require_private_file(&path).map_err(|_| ())?;
            if fs::read(path).map_err(|_| ())? == bytes {
                Ok(())
            } else {
                Err(())
            }
        }
        Err(_) => Err(()),
    }
}

fn parse_client(value: &str) -> Result<Client, ()> {
    match value {
        "claude" => Ok(Client::Claude),
        "codex" => Ok(Client::Codex),
        _ => Err(()),
    }
}

fn parse_core_fault(value: &str) -> Result<CoreFault, ()> {
    match value {
        "none" => Ok(CoreFault::None),
        "timeout" => Ok(CoreFault::Timeout),
        "nonzero" => Ok(CoreFault::Nonzero),
        "schema-invalid" => Ok(CoreFault::SchemaInvalid),
        "oversized-stdout" => Ok(CoreFault::OversizedStdout),
        _ => Err(()),
    }
}

fn parse_cwd_binding(value: &str) -> Result<CwdBinding, ()> {
    match value {
        "verified-simple" => Ok(CwdBinding::VerifiedSimpleInvocation),
        "unsupported-per-call-workdir" => Ok(CwdBinding::UnsupportedPerCallWorkdir),
        _ => Err(()),
    }
}

#[derive(Clone, Copy)]
enum IdBinding {
    Literal,
    NativeSha256,
}

fn parse_id_binding(value: &str) -> Result<IdBinding, ()> {
    match value {
        "literal" => Ok(IdBinding::Literal),
        "native-sha256" => Ok(IdBinding::NativeSha256),
        _ => Err(()),
    }
}

fn bind_id(binding: IdBinding, domain: &str, base: &str, native_input: &[u8]) -> String {
    match binding {
        IdBinding::Literal => base.to_owned(),
        IdBinding::NativeSha256 => {
            let mut hasher = Sha256::new();
            hasher.update(b"secure-onboard:m0-native-id/v1\n");
            hasher.update(domain.as_bytes());
            hasher.update([0]);
            hasher.update(base.as_bytes());
            hasher.update([0]);
            hasher.update(native_input);
            format!("{base}-{}", hex::encode(hasher.finalize()))
        }
    }
}

struct Arguments {
    values: BTreeMap<String, OsString>,
}

impl Arguments {
    fn parse(arguments: impl Iterator<Item = OsString>) -> Result<Self, ()> {
        let mut arguments = arguments;
        let mut values = BTreeMap::new();
        while let Some(key) = arguments.next() {
            let key = key.into_string().map_err(|_| ())?;
            if !key.starts_with("--") || values.contains_key(&key) {
                return Err(());
            }
            let value = arguments.next().ok_or(())?;
            values.insert(key, value);
        }
        Ok(Self { values })
    }

    fn take(&mut self, key: &str) -> Result<String, ()> {
        self.values
            .remove(key)
            .ok_or(())?
            .into_string()
            .map_err(|_| ())
    }

    fn take_path(&mut self, key: &str) -> Result<PathBuf, ()> {
        self.values.remove(key).map(PathBuf::from).ok_or(())
    }

    fn take_optional(&mut self, key: &str) -> Result<Option<String>, ()> {
        self.values
            .remove(key)
            .map(|value| value.into_string().map_err(|_| ()))
            .transpose()
    }

    fn finish(&self) -> Result<(), ()> {
        if self.values.is_empty() {
            Ok(())
        } else {
            Err(())
        }
    }
}
