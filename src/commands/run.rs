//! `hsh run` — run a command with secrets injected into its environment.

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::cli::RunArgs;
use crate::client;
use crate::protocol::{Request, Response};
use crate::{commands, config, hygiene, profiles, prompt};

/// Run a command with profile-selected secrets injected into its environment.
pub fn run(args: RunArgs) -> Result<()> {
    // Protect this process while it briefly holds the fetched secrets.
    if let Err(err) = hygiene::disable_core_dumps() {
        eprintln!("hsh: warning: could not disable core dumps: {err}");
    }

    let (program, program_args) = args
        .command
        .split_first()
        .context("no command given to run")?;

    ensure_secrets_file()?;

    let vars = if args.all {
        fetch(&Request::GetAll)?
    } else {
        let profile = match &args.profile {
            Some(name) => name.clone(),
            None => default_profile_name(program),
        };
        let keys = profiles::load()?.keys_for(&profile)?;
        fetch(&Request::Get { keys })?
    };

    // `exec` replaces this process: the secrets enter only the child's
    // environment, never the interactive shell's.
    let error = Command::new(program).args(program_args).envs(vars).exec();
    Err(error).with_context(|| format!("could not execute '{program}'"))
}

/// The default profile name is the command's own basename.
fn default_profile_name(program: &str) -> String {
    Path::new(program)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.to_string())
}

/// Offer to create the secrets file interactively if it does not exist.
fn ensure_secrets_file() -> Result<()> {
    let path = config::secrets_path()?;
    if path.exists() {
        return Ok(());
    }
    eprintln!("hsh: no secrets file at {}", path.display());
    let answer = prompt::line("Create one now? [y/N]: ")?;
    if answer.trim().eq_ignore_ascii_case("y") {
        commands::init::run()
    } else {
        bail!("no secrets file — run `hsh init` first");
    }
}

/// Fetch secrets from the agent, unlocking it interactively if needed.
fn fetch(request: &Request) -> Result<BTreeMap<String, String>> {
    if let Some(vars) = try_fetch(request)? {
        return Ok(vars);
    }
    // The agent is locked — unlock it, then fetch once more.
    unlock_interactive()?;
    try_fetch(request)?.context("agent reported locked again after unlock")
}

/// One fetch attempt: `Ok(Some(vars))` on success, `Ok(None)` if locked.
fn try_fetch(request: &Request) -> Result<Option<BTreeMap<String, String>>> {
    match client::request(request)? {
        Response::Vars { vars } => Ok(Some(vars)),
        Response::Error { message } if message == "locked" => Ok(None),
        Response::Error { message } => bail!("agent error: {message}"),
        other => bail!("unexpected response from agent: {other:?}"),
    }
}

/// Prompt for the passphrase and unlock the agent, up to three attempts.
fn unlock_interactive() -> Result<()> {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let passphrase = prompt::secret("Passphrase: ")?;
        if passphrase.is_empty() {
            eprintln!("  passphrase must not be empty");
            continue;
        }
        match client::request(&Request::Unlock {
            passphrase: Zeroizing::new(passphrase),
        })? {
            Response::Ok => return Ok(()),
            Response::Error { message } => {
                let left = MAX_ATTEMPTS - attempt;
                if left > 0 {
                    eprintln!("  {message} — {left} attempt(s) left");
                } else {
                    eprintln!("  {message}");
                }
            }
            other => bail!("unexpected response from agent: {other:?}"),
        }
    }
    bail!("could not unlock the agent");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_is_the_basename() {
        assert_eq!(default_profile_name("/usr/bin/psql"), "psql");
        assert_eq!(default_profile_name("psql"), "psql");
    }
}
