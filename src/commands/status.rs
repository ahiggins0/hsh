//! `hsh status` — report whether the agent is running and unlocked.

use anyhow::{Result, bail};

use crate::client;
use crate::protocol::{Request, Response};

pub fn run() -> Result<()> {
    // `client::request` auto-spawns the agent, so it is running once we reply.
    match client::request(&Request::Status)? {
        Response::Status {
            unlocked: true,
            expires_in: Some(secs),
        } => println!("agent: running, unlocked ({secs}s until idle expiry)"),
        Response::Status {
            unlocked: true,
            expires_in: None,
        } => println!("agent: running, unlocked (no idle TTL configured)"),
        Response::Status {
            unlocked: false, ..
        } => println!("agent: running, locked"),
        Response::Error { message } => bail!("agent error: {message}"),
        other => bail!("unexpected response from agent: {other:?}"),
    }
    Ok(())
}
