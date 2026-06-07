//! `hsh init` — interactively create the encrypted secrets file.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use zeroize::Zeroize;

use crate::crypto::SecretString;
use crate::{config, crypto, envfile, hygiene, prompt};

/// Run the interactive creation flow.
pub fn run() -> Result<()> {
    // A crash while secrets are in memory must not leave them in a core file.
    if let Err(err) = hygiene::disable_core_dumps() {
        eprintln!("hsh: warning: could not disable core dumps: {err}");
    }

    let secrets_path = config::secrets_path()?;
    if secrets_path.exists() {
        bail!(
            "{} already exists — refusing to overwrite",
            secrets_path.display()
        );
    }

    println!(
        "Creating a new encrypted secrets file at {}",
        secrets_path.display()
    );
    println!("Enter your variables. Press Enter on an empty name to finish.\n");

    let mut vars = collect_vars()?;
    if vars.is_empty() {
        bail!("no variables entered — nothing to create");
    }
    let count = vars.len();

    println!("\nNow choose a passphrase to encrypt the file.");
    let passphrase = prompt_new_passphrase()?;

    // Serialise and encrypt, then scrub every plaintext copy we still hold.
    let mut plaintext = envfile::serialize(&vars);
    let ciphertext = crypto::encrypt(plaintext.as_bytes(), passphrase)?;
    plaintext.zeroize();
    for (_, value) in &mut vars {
        value.zeroize();
    }

    config::ensure_config_dir()?;
    write_private(&secrets_path, &ciphertext)?;
    println!(
        "\nEncrypted {count} variable(s) to {}",
        secrets_path.display()
    );

    write_starter_profiles(&vars)?;
    Ok(())
}

/// Prompt for variable names and values until an empty name is entered.
fn collect_vars() -> Result<Vec<(String, String)>> {
    let mut vars: Vec<(String, String)> = Vec::new();
    loop {
        let name = prompt::line("Variable name (blank to finish): ")?;
        let name = name.trim();
        if name.is_empty() {
            return Ok(vars);
        }
        if !envfile::is_valid_key(name) {
            eprintln!("  invalid name — must match [A-Za-z_][A-Za-z0-9_]*");
            continue;
        }
        if vars.iter().any(|(existing, _)| existing == name) {
            eprintln!("  '{name}' already entered — skipping");
            continue;
        }
        let value = prompt::secret(&format!("Value for {name} (hidden): "))?;
        vars.push((name.to_string(), value));
        println!("  added {name}");
    }
}

/// Below this length we warn but still accept: the at-rest secrecy of the whole
/// file rests on this passphrase plus scrypt.
const WEAK_PASSPHRASE_LEN: usize = 8;

/// Prompt for a passphrase twice and require the two entries to match.
fn prompt_new_passphrase() -> Result<SecretString> {
    const MAX_ATTEMPTS: u32 = 5;
    for _ in 0..MAX_ATTEMPTS {
        let mut first = prompt::secret("Passphrase (hidden): ")?;
        if first.is_empty() {
            eprintln!("  passphrase must not be empty");
            continue;
        }
        if first.chars().count() < WEAK_PASSPHRASE_LEN {
            eprintln!(
                "  warning: short passphrase (under {WEAK_PASSPHRASE_LEN} characters) — \
                 this is the only thing protecting the file at rest"
            );
        }
        let mut second = prompt::secret("Confirm passphrase: ")?;
        let matched = first == second;
        second.zeroize();
        if matched {
            return Ok(SecretString::from(first));
        }
        first.zeroize();
        eprintln!("  passphrases did not match — try again");
    }
    bail!("too many failed passphrase attempts");
}

/// Write `data` to `path`, creating it `0600` and failing if it already exists.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(data)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing {}", path.display()))?;
    Ok(())
}

/// Write a commented starter profile manifest, unless one already exists.
fn write_starter_profiles(vars: &[(String, String)]) -> Result<()> {
    let path = config::profiles_path()?;
    if path.exists() {
        return Ok(());
    }
    let mut body = String::from(
        "# hsh profile manifest — least-privilege map.\n\
         # Each profile lists exactly which variables a command may receive.\n\
         # `hsh run -- <cmd>` uses the profile named after <cmd> by default;\n\
         # `hsh run -p <name> -- <cmd>` selects one explicitly.\n\
         \n\
         idle_ttl_secs = 3600   # forget cached secrets after 1h idle\n\
         \n\
         # Variables in your secrets file:\n",
    );
    for (name, _) in vars {
        body.push_str("#   ");
        body.push_str(name);
        body.push('\n');
    }
    body.push_str(
        "\n# Example — uncomment and edit:\n\
         #\n\
         # [profiles.psql]\n\
         # vars = [\"DATABASE_URL\"]\n",
    );
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    println!("Wrote a starter profile manifest to {}", path.display());
    Ok(())
}
