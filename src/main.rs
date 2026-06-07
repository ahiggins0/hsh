//! hsh — hardened shell.
//!
//! Keeps environment variables in an age-encrypted file and injects them into
//! individual commands rather than into the interactive shell.

mod agent;
mod cli;
mod client;
mod commands;
mod config;
mod crypto;
mod envfile;
mod forget;
mod hygiene;
mod profiles;
mod prompt;
mod protocol;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    let result = match cli.command {
        cli::Command::Init => commands::init::run(),
        cli::Command::Agent => agent::run(),
        cli::Command::Status => commands::status::run(),
        cli::Command::Lock => commands::lock::run(),
        cli::Command::Run(args) => commands::run::run(args),
    };
    if let Err(err) = result {
        eprintln!("hsh: {err:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
