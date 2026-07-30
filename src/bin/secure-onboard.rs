use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn run() -> Result<(), u8> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    match arguments.next().and_then(|value| value.into_string().ok()) {
        Some(command) if command == "probe-profile" => {
            let profile = arguments.next().ok_or(64)?;
            if profile.is_empty() || arguments.next().is_some() {
                return Err(64);
            }
            write_stdout(b"{\"profile\":\"not_supported\"}\n")
        }
        Some(command) if command == "components" => {
            if arguments.next().is_some() {
                return Err(64);
            }
            write_stdout(
                b"{\"schema_version\":\"secure-onboard-build-components/v1\",\"components\":[\"production_profile_rejection\"]}\n",
            )
        }
        _ => Err(64),
    }
}

fn write_stdout(bytes: &[u8]) -> Result<(), u8> {
    std::io::stdout().write_all(bytes).map_err(|_| 74)
}
