#![cfg(feature = "m0-test-profile")]

use secure_onboard::m0::{M0CoreInput, evaluate};
use secure_onboard::strict_json::{canonical_bytes, from_slice};
use std::io::{Read, Write};
use std::process::ExitCode;
use std::time::Duration;

const MAX_INPUT_BYTES: u64 = 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn run() -> Result<(), u8> {
    let fault = fault_argument()?;
    match fault.as_str() {
        "timeout" => {
            std::thread::sleep(Duration::from_secs(30));
            return Ok(());
        }
        "nonzero" => return Err(70),
        "schema-invalid" => {
            std::io::stdout().write_all(b"{\n").map_err(|_| 74)?;
            return Ok(());
        }
        "oversized-stdout" => {
            let bytes = vec![b'x'; (MAX_INPUT_BYTES as usize) + 1];
            std::io::stdout().write_all(&bytes).map_err(|_| 74)?;
            return Ok(());
        }
        "none" => {}
        _ => return Err(64),
    }

    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| 74)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(65);
    }
    let input: M0CoreInput = from_slice(&bytes).map_err(|_| 65)?;
    if input.schema_version != "m0-core-input/v1" {
        return Err(65);
    }
    let output = evaluate(input.request, input.metadata).map_err(|_| 65)?;
    let mut output_bytes = canonical_bytes(&output).map_err(|_| 65)?;
    output_bytes.push(b'\n');
    std::io::stdout().write_all(&output_bytes).map_err(|_| 74)?;
    Ok(())
}

fn fault_argument() -> Result<String, u8> {
    let mut arguments = std::env::args();
    let _program = arguments.next();
    if arguments.next().as_deref() != Some("--fault") {
        return Err(64);
    }
    let fault = arguments.next().ok_or(64)?;
    if arguments.next().is_some() {
        return Err(64);
    }
    Ok(fault)
}
