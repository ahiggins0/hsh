//! Terminal prompting helpers.
//!
//! Prompts are written to stderr so they never pollute a command's stdout —
//! important for `hsh run`, whose stdout belongs to the executed command.
//! Secret input uses a no-echo terminal read when stdin is a TTY, and a plain
//! stdin read otherwise, so the flow stays scriptable and testable.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{Context, Result};

/// Print `prompt` to stderr and read one visible line from stdin.
pub fn line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush().context("writing prompt")?;
    read_stdin_line()
}

/// Print `prompt` to stderr and read one secret line.
///
/// Disables terminal echo when stdin is a TTY; otherwise reads a plain line.
pub fn secret(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush().context("writing prompt")?;
    if std::io::stdin().is_terminal() {
        let secret = rpassword::read_password().context("reading hidden input")?;
        // Echo-off swallowed the user's newline; move the cursor on.
        eprintln!();
        Ok(secret)
    } else {
        read_stdin_line()
    }
}

/// Read one line from the shared buffered stdin, trimming a trailing `\r?\n`.
fn read_stdin_line() -> Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .context("reading input")?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}
