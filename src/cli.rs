//! Command-line interface definition.

use clap::{Args, Parser, Subcommand};

/// hardened shell — age-encrypted env vars injected per-command.
#[derive(Parser)]
#[command(name = "hsh", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create the encrypted secrets file interactively.
    Init,
    /// Run the secrets agent (normally started automatically).
    Agent,
    /// Show whether the agent is running and unlocked.
    Status,
    /// Forget the cached secrets.
    Lock,
    /// Run a command with secrets injected into its environment.
    Run(RunArgs),
}

/// Arguments for `hsh run`.
#[derive(Args)]
pub struct RunArgs {
    /// Profile to use (default: the command's own name).
    #[arg(short, long)]
    pub profile: Option<String>,
    /// Inject every variable instead of a profile's subset.
    #[arg(long)]
    pub all: bool,
    /// The command to run, followed by its arguments.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}
