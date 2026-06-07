//! IPC wire protocol between the `hsh` client and the `hsh agent` daemon.
//!
//! One JSON object per message, newline-terminated, over a unix socket in the
//! per-user runtime directory.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufRead, Read, Write};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::{Zeroize, Zeroizing};

/// Hard cap on a single inbound message so a newline-less flood cannot grow an
/// unbounded buffer. Requests and responses are tiny; 1 MiB is generous.
const MAX_MESSAGE_BYTES: u64 = 1024 * 1024;

/// A request from a client to the daemon.
///
/// `Debug` is implemented by hand rather than derived so the passphrase in
/// [`Request::Unlock`] is never rendered into logs or error chains.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Report whether the cache is unlocked.
    Status,
    /// Decrypt the secrets file with this passphrase and cache it.
    ///
    /// Held in a [`Zeroizing`] buffer so the plaintext passphrase is wiped on
    /// drop on every path, client and daemon alike.
    Unlock { passphrase: Zeroizing<String> },
    /// Return the requested keys from the cache.
    Get { keys: Vec<String> },
    /// Return every key from the cache.
    GetAll,
    /// Forget the cached secrets.
    Lock,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Request::Status => f.write_str("Status"),
            Request::Unlock { .. } => f
                .debug_struct("Unlock")
                .field("passphrase", &"<redacted>")
                .finish(),
            Request::Get { keys } => f.debug_struct("Get").field("keys", keys).finish(),
            Request::GetAll => f.write_str("GetAll"),
            Request::Lock => f.write_str("Lock"),
        }
    }
}

/// A response from the daemon to a client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Result of [`Request::Status`].
    Status {
        unlocked: bool,
        /// Seconds remaining before the idle TTL forgets the cache.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_in: Option<u64>,
    },
    /// A successful [`Request::Unlock`] or [`Request::Lock`].
    Ok,
    /// Result of [`Request::Get`] / [`Request::GetAll`].
    Vars { vars: BTreeMap<String, String> },
    /// Any failure, with a human-readable message.
    Error { message: String },
}

impl Response {
    /// Wipe any secret values this response is still carrying. Call it after the
    /// response has been written to the wire so the daemon's heap copies of the
    /// plaintext do not linger un-zeroized.
    pub fn zeroize_secrets(&mut self) {
        if let Response::Vars { vars } = self {
            for value in vars.values_mut() {
                value.zeroize();
            }
        }
    }
}

/// Write `msg` as a single newline-terminated JSON line.
pub fn write_message<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> Result<()> {
    let mut line = serde_json::to_vec(msg).context("serialising message")?;
    line.push(b'\n');
    let result = writer.write_all(&line).context("writing message");
    // The line may have carried a passphrase; scrub the wire copy.
    line.zeroize();
    result?;
    writer.flush().context("flushing message")?;
    Ok(())
}

/// Read one newline-terminated JSON-line message.
pub fn read_message<R: BufRead, T: DeserializeOwned>(reader: &mut R) -> Result<T> {
    let mut line = String::new();
    // Cap the read so a peer that never sends a newline cannot grow `line`
    // without bound. A truncated line simply fails to parse below.
    let read = reader
        .take(MAX_MESSAGE_BYTES)
        .read_line(&mut line)
        .context("reading message")?;
    if read == 0 {
        bail!("connection closed before a message arrived");
    }
    let parsed = serde_json::from_str(&line).context("parsing message");
    // The line may have carried a passphrase; scrub it whatever the outcome.
    line.zeroize();
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let original = Request::Get {
            keys: vec!["A".into(), "B".into()],
        };
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#"{"op":"get","keys":["A","B"]}"#);
        let back: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Request::Get { keys } if keys == ["A", "B"]));

        assert_eq!(
            serde_json::to_string(&Request::GetAll).unwrap(),
            r#"{"op":"get_all"}"#
        );
    }

    #[test]
    fn response_round_trips() {
        assert_eq!(
            serde_json::to_string(&Response::Ok).unwrap(),
            r#"{"type":"ok"}"#
        );
        let back: Response = serde_json::from_str(r#"{"type":"ok"}"#).unwrap();
        assert!(matches!(back, Response::Ok));
    }

    #[test]
    fn framing_round_trips() {
        let mut buf = Vec::new();
        write_message(&mut buf, &Request::Status).unwrap();
        assert!(buf.ends_with(b"\n"));
        let mut reader = &buf[..];
        let back: Request = read_message(&mut reader).unwrap();
        assert!(matches!(back, Request::Status));
    }
}
