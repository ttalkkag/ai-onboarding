#![cfg(feature = "m0-test-profile")]

use crate::m0::{
    EvaluationMetadata, FallbackFailure, M0ActionRequest, M0CoreInput, M0CoreOutput,
    validate_core_output,
};
use crate::strict_json::{canonical_bytes, from_slice};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

const MAX_CHILD_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreFault {
    None,
    Timeout,
    Nonzero,
    SchemaInvalid,
    OversizedStdout,
}

impl CoreFault {
    fn argument(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Timeout => "timeout",
            Self::Nonzero => "nonzero",
            Self::SchemaInvalid => "schema-invalid",
            Self::OversizedStdout => "oversized-stdout",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreChild {
    pub executable: PathBuf,
    pub working_directory: PathBuf,
    pub timeout: Duration,
    pub fault: CoreFault,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum CoreChildError {
    #[error("core child could not be spawned")]
    Spawn,
    #[error("core child timed out")]
    Timeout,
    #[error("core child exited nonzero")]
    Nonzero,
    #[error("core child output was not a valid correlated M0 response")]
    SchemaInvalid,
    #[error("core child I/O failed")]
    Io,
}

impl CoreChildError {
    pub fn fallback_failure(&self) -> Option<FallbackFailure> {
        match self {
            Self::Timeout => Some(FallbackFailure::CoreTimeout),
            Self::Nonzero => Some(FallbackFailure::CoreNonzero),
            Self::SchemaInvalid => Some(FallbackFailure::CoreSchemaInvalid),
            Self::Spawn | Self::Io => None,
        }
    }
}

pub fn run_core_child(
    core: &CoreChild,
    request: &M0ActionRequest,
    metadata: &EvaluationMetadata,
) -> Result<M0CoreOutput, CoreChildError> {
    let input = M0CoreInput {
        schema_version: "m0-core-input/v1".into(),
        request: request.clone(),
        metadata: metadata.clone(),
    };
    let mut input_bytes = canonical_bytes(&input).map_err(|_| CoreChildError::Io)?;
    input_bytes.push(b'\n');

    let mut command = Command::new(&core.executable);
    command
        .arg("--fault")
        .arg(core.fault.argument())
        .current_dir(&core.working_directory)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|_| CoreChildError::Spawn)?;
    let child_process_group = child.id();

    let mut stdin = child.stdin.take().ok_or(CoreChildError::Io)?;
    let stdout = child.stdout.take().ok_or(CoreChildError::Io)?;
    let stderr = child.stderr.take().ok_or(CoreChildError::Io)?;
    let deadline = Instant::now() + core.timeout;
    let stdin_writer = thread::spawn(move || stdin.write_all(&input_bytes));
    let stdout_reader = bounded_reader(stdout);
    let stderr_reader = bounded_reader(stderr);

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                terminate_process_group(child_process_group);
                break status;
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            Ok(None) => {
                terminate_child_tree(&mut child);
                let _ = stdin_writer.join();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(CoreChildError::Timeout);
            }
            Err(_) => {
                terminate_child_tree(&mut child);
                let _ = stdin_writer.join();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(CoreChildError::Io);
            }
        }
    };
    let stdin_result = stdin_writer.join().map_err(|_| CoreChildError::Io)?;
    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| CoreChildError::Io)?
        .map_err(|_| CoreChildError::Io)?;
    let (_, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| CoreChildError::Io)?
        .map_err(|_| CoreChildError::Io)?;

    if !status.success() {
        return Err(CoreChildError::Nonzero);
    }
    if stdout_truncated || stderr_truncated {
        return Err(CoreChildError::SchemaInvalid);
    }
    if stdin_result.is_err() {
        return Err(CoreChildError::SchemaInvalid);
    }
    let output: M0CoreOutput = from_slice(&stdout).map_err(|_| CoreChildError::SchemaInvalid)?;
    validate_core_output(request, metadata, &output).map_err(|_| CoreChildError::SchemaInvalid)?;
    Ok(output)
}

fn terminate_child_tree(child: &mut Child) {
    terminate_process_group(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn terminate_process_group(process_group: u32) {
    let Ok(process_group) = libc::pid_t::try_from(process_group) else {
        return;
    };
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn terminate_process_group(_: u32) {}

fn bounded_reader(
    mut file: impl Read + Send + 'static,
) -> thread::JoinHandle<std::io::Result<(Vec<u8>, bool)>> {
    thread::spawn(move || {
        let mut captured = Vec::new();
        let mut truncated = false;
        let mut buffer = [0_u8; 8192];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            let remaining = MAX_CHILD_OUTPUT_BYTES.saturating_sub(captured.len());
            let kept = remaining.min(count);
            captured.extend_from_slice(&buffer[..kept]);
            truncated |= kept < count;
        }
        Ok((captured, truncated))
    })
}
