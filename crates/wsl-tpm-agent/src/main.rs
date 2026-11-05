//! `wsl-tpm-agent.exe`: `keygen` creates an ECDSA P-256 key in the Windows TPM and prints it in
//! OpenSSH format; `agent` serves the ssh-agent protocol for one connection on stdin/stdout and
//! signs with that key. Started from WSL through interop, one process per connection.
//!
//! A console-subsystem executable, so stderr (the log) reaches the journal through the unit.

mod cli;
#[cfg(windows)]
mod ncrypt;

use std::io;
use std::process::ExitCode;

use cli::Command;
use wta_protocol::{error, warn};

fn main() -> ExitCode {
    let command = match cli::parse(std::env::args_os().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("wsl-tpm-agent: {e}\n\n{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };
    let result = match command {
        Command::Help => {
            println!("{}", cli::USAGE);
            Ok(())
        }
        Command::Version => {
            println!("wsl-tpm-agent {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Keygen { name } => {
            if !name.starts_with(cli::PREFIX) {
                warn!(
                    "{name} does not start with {}: `agent` lists it only with --name {name}",
                    cli::PREFIX
                );
            }
            keygen(&name)
        }
        Command::Agent { name } => agent(name),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
fn keygen(name: &str) -> io::Result<()> {
    use std::io::Write as _;
    use wta_protocol::ecdsa;

    let point = ncrypt::Provider::open()?.create_key(name)?;
    let mut out = io::stdout().lock();
    writeln!(out, "{}", ecdsa::openssh_line(&point, name))?;
    out.flush()
}

#[cfg(windows)]
fn agent(name: Option<String>) -> io::Result<()> {
    let mut tpm = ncrypt::Tpm::open(name)?;
    wta_protocol::agent::serve(&mut io::stdin().lock(), &mut io::stdout().lock(), &mut tpm)
}

// Built on Linux only for the tests and clippy.
#[cfg(not(windows))]
fn keygen(_: &str) -> io::Result<()> {
    Err(only_windows())
}

#[cfg(not(windows))]
fn agent(_: Option<String>) -> io::Result<()> {
    Err(only_windows())
}

#[cfg(not(windows))]
fn only_windows() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "this executable only runs on Windows",
    )
}
