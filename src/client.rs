//! Client side: connect to the agent, auto-spawning it when needed.

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::config;
use crate::protocol::{self, Request, Response};

/// Send one request to the agent and return its response, starting the agent
/// first if nothing is listening.
pub fn request(req: &Request) -> Result<Response> {
    let stream = connect_or_spawn()?;
    let mut reader = BufReader::new(stream.try_clone().context("cloning socket")?);
    let mut writer = stream;
    protocol::write_message(&mut writer, req)?;
    protocol::read_message(&mut reader)
}

/// Connect to the agent socket, spawning a fresh agent if nothing answers.
fn connect_or_spawn() -> Result<UnixStream> {
    let path = config::socket_path()?;
    if let Ok(stream) = UnixStream::connect(&path) {
        return Ok(stream);
    }
    spawn_agent()?;
    wait_for_agent(&path)
}

/// Start a detached agent process.
fn spawn_agent() -> Result<()> {
    let exe = std::env::current_exe().context("locating the hsh executable")?;
    let mut command = Command::new(exe);
    command
        .arg("agent")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid() is async-signal-safe; it detaches the agent into its
    // own session so it outlives this short-lived client.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    command.spawn().context("spawning hsh agent")?;
    Ok(())
}

/// Poll the socket until the freshly spawned agent accepts connections.
fn wait_for_agent(path: &Path) -> Result<UnixStream> {
    for _ in 0..100 {
        if let Ok(stream) = UnixStream::connect(path) {
            return Ok(stream);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    bail!(
        "hsh agent did not start within 2s — try running `hsh agent` directly to see why it failed (socket: {})",
        path.display()
    );
}

/// Convenience: send a request and require a plain [`Response::Ok`].
pub fn request_ok(req: &Request) -> Result<()> {
    match request(req)? {
        Response::Ok => Ok(()),
        Response::Error { message } => bail!("agent error: {message}"),
        other => bail!("unexpected response from agent: {other:?}"),
    }
}
