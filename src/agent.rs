//! The `hsh agent` daemon.
//!
//! Holds the decrypted secrets in `mlock`'d memory and serves them to `hsh`
//! clients over a unix socket. Background watchers (see [`crate::forget`])
//! drop the cache on screen lock, suspend, or idle timeout.

use std::collections::BTreeMap;
use std::io::{BufReader, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::SecretString;
use crate::hygiene::LockedSecret;
use crate::protocol::{Request, Response};
use crate::{config, crypto, envfile, forget, hygiene, profiles, protocol};

/// Mutable daemon state, shared between the request loop and the forget watchers.
pub struct AgentState {
    /// The decrypted secrets file, or `None` while locked.
    secrets: Option<LockedSecret>,
    /// When the cache was last touched by an unlock or a successful fetch.
    unlocked_at: Option<Instant>,
    /// Configured idle TTL, captured at unlock time from `profiles.toml`.
    idle_ttl: Option<Duration>,
}

impl AgentState {
    fn new() -> Self {
        Self {
            secrets: None,
            unlocked_at: None,
            idle_ttl: None,
        }
    }

    /// Install a freshly decrypted cache and capture the active idle TTL.
    fn unlock_with(&mut self, secrets: LockedSecret, idle_ttl: Option<Duration>) {
        self.secrets = Some(secrets);
        self.unlocked_at = Some(Instant::now());
        self.idle_ttl = idle_ttl;
    }

    /// Drop the cache. Called by the request loop and by the forget watchers.
    pub fn forget(&mut self) {
        // Dropping the LockedSecret zeroizes and munlocks it.
        self.secrets = None;
        self.unlocked_at = None;
        self.idle_ttl = None;
    }

    /// Reset the idle clock — a successful fetch counts as user activity.
    fn touch(&mut self) {
        if self.secrets.is_some() {
            self.unlocked_at = Some(Instant::now());
        }
    }

    /// Drop the cache if the idle TTL has elapsed since the last activity.
    pub fn expire_if_idle(&mut self) {
        if let (Some(ttl), Some(at)) = (self.idle_ttl, self.unlocked_at)
            && at.elapsed() >= ttl
        {
            self.forget();
        }
    }

    fn expires_in(&self) -> Option<u64> {
        let (ttl, at) = (self.idle_ttl?, self.unlocked_at?);
        let elapsed = at.elapsed();
        Some(ttl.saturating_sub(elapsed).as_secs())
    }

    /// Re-read the configured idle TTL from `profiles.toml`, so a shortened TTL
    /// takes effect within the current session rather than only at next unlock.
    /// A missing or unparsable manifest leaves the captured value untouched.
    fn refresh_idle_ttl(&mut self) {
        if self.secrets.is_none() {
            return;
        }
        if let Ok(manifest) = profiles::load() {
            self.idle_ttl = manifest.idle_ttl_secs.map(Duration::from_secs);
        }
    }
}

/// Lock the shared state, recovering rather than propagating a poisoned mutex.
///
/// If a request handler ever panics while holding the lock, propagating the
/// poison would take down the idle/lock watchers too and strand the secrets
/// cached forever — a fail-*open* outcome. Recovering keeps the forget paths
/// alive (fail-closed).
pub fn lock_state(state: &Mutex<AgentState>) -> MutexGuard<'_, AgentState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Run the daemon: bind the socket and serve requests until killed.
pub fn run() -> Result<()> {
    if let Err(err) = hygiene::disable_core_dumps() {
        eprintln!("hsh agent: warning: could not disable core dumps: {err}");
    }
    // No process-wide mlockall here: MCL_FUTURE would force every later
    // allocation into locked RAM, and the memory-hard scrypt KDF that decrypts
    // the secrets file allocates far past RLIMIT_MEMLOCK. Each cached secret is
    // locked individually via `LockedSecret` instead.

    let socket_path = config::socket_path()?;
    let listener = bind_socket(&socket_path)?;
    write_pidfile()?;
    println!("hsh agent: listening on {}", socket_path.display());

    let state = Arc::new(Mutex::new(AgentState::new()));
    forget::spawn_watchers(state.clone());

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                // Serve each connection on its own thread so a slow or stalled
                // client cannot block the accept loop (the read/write timeouts
                // in `handle_connection` bound each one).
                let state = state.clone();
                thread::spawn(move || {
                    if let Err(err) = handle_connection(stream, &state) {
                        eprintln!("hsh agent: connection error: {err:#}");
                    }
                });
            }
            Err(err) => eprintln!("hsh agent: accept error: {err}"),
        }
    }
    Ok(())
}

/// Bind the control socket, clearing a stale socket file if no daemon answers.
fn bind_socket(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        // Tighten the directory holding the socket to owner-only. On Linux the
        // runtime dir is already 0700; on macOS we may have just created an
        // `hsh/` subdir under the per-user temp dir, so make it private too.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("securing {}", parent.display()))?;
    }
    // Bind under a tight umask so the socket is never even briefly group/other
    // accessible in the window before the explicit chmod below.
    // SAFETY: umask only reads/sets this process's file-mode mask.
    let prev_umask = unsafe { libc::umask(0o077) };
    let bound = UnixListener::bind(path);
    // SAFETY: restore the caller's umask regardless of the bind result.
    unsafe { libc::umask(prev_umask) };
    let listener = match bound {
        Ok(listener) => listener,
        Err(err) if err.kind() == ErrorKind::AddrInUse => {
            if UnixStream::connect(path).is_ok() {
                bail!("an hsh agent is already running at {}", path.display());
            }
            // Stale socket left by a dead daemon — remove it and retry.
            std::fs::remove_file(path)
                .with_context(|| format!("removing stale socket {}", path.display()))?;
            UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?
        }
        Err(err) => return Err(err).with_context(|| format!("binding {}", path.display())),
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("securing {}", path.display()))?;
    Ok(listener)
}

/// Record this daemon's PID. Liveness is actually checked by connecting to the
/// socket; the pidfile is a convenience for tearing the daemon down (e.g. tests
/// and `kill $(cat hsh.pid)`).
fn write_pidfile() -> Result<()> {
    let path = config::pid_path()?;
    std::fs::write(&path, format!("{}\n", std::process::id()))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Read one request from `stream`, handle it, and write back one response.
fn handle_connection(stream: UnixStream, state: &Mutex<AgentState>) -> Result<()> {
    // Defence in depth on top of the 0600 socket: only serve our own uid, so a
    // mislabelled or race-exposed socket can't be used by another local user.
    let peer = peer_uid(&stream).context("reading socket peer credentials")?;
    // SAFETY: getuid() always succeeds and touches no memory.
    let me = unsafe { libc::getuid() };
    if peer != me {
        bail!("refusing connection from uid {peer} (agent runs as {me})");
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .context("setting socket read timeout")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .context("setting socket write timeout")?;
    let mut reader = BufReader::new(stream.try_clone().context("cloning socket")?);
    let mut writer = stream;
    let request: Request = protocol::read_message(&mut reader)?;
    let mut response = dispatch(request, state);
    let result = protocol::write_message(&mut writer, &response);
    // The response may have carried plaintext secrets; wipe our heap copy now
    // that it is on the wire, whether or not the write succeeded.
    response.zeroize_secrets();
    result
}

/// The uid of the process on the other end of `stream`, via `SO_PEERCRED`.
///
/// Linux-only: `SO_PEERCRED` / `struct ucred` are not portable. The macOS
/// counterpart below uses `getpeereid(3)` for the same same-uid check.
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred`/`len` are valid for the duration of the call; the fd is a
    // live connected socket owned by `stream`.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("getsockopt(SO_PEERCRED)");
    }
    Ok(cred.uid)
}

/// The uid of the process on the other end of `stream`, via `getpeereid(3)`.
///
/// Used on macOS/BSD, where the libc crate exposes `getpeereid` but not the
/// Linux `SO_PEERCRED` socket option.
#[cfg(not(target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `uid`/`gid` are valid out-params for the duration of the call; the
    // fd is a live connected socket owned by `stream`.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("getpeereid");
    }
    Ok(uid)
}

/// Apply a request to the daemon state and produce a response.
fn dispatch(request: Request, state: &Mutex<AgentState>) -> Response {
    match request {
        Request::Status => {
            let mut st = lock_state(state);
            st.expire_if_idle();
            Response::Status {
                unlocked: st.secrets.is_some(),
                expires_in: st.expires_in(),
            }
        }
        Request::Lock => {
            lock_state(state).forget();
            Response::Ok
        }
        Request::Unlock { passphrase } => match unlock(passphrase) {
            Ok(secrets) => {
                let ttl = profiles::load()
                    .ok()
                    .and_then(|m| m.idle_ttl_secs)
                    .map(Duration::from_secs);
                lock_state(state).unlock_with(secrets, ttl);
                Response::Ok
            }
            Err(err) => Response::Error {
                message: format!("{err:#}"),
            },
        },
        Request::Get { keys } => respond_with_vars(state, Some(&keys)),
        Request::GetAll => respond_with_vars(state, None),
    }
}

/// Build a [`Response::Vars`] for a key subset (`Some`) or every key (`None`).
fn respond_with_vars(state: &Mutex<AgentState>, keys: Option<&[String]>) -> Response {
    let mut st = lock_state(state);
    st.expire_if_idle();
    let response = match &st.secrets {
        None => Response::Error {
            message: "locked".into(),
        },
        Some(secrets) => match lookup(secrets, keys) {
            Ok(vars) => Response::Vars { vars },
            Err(err) => Response::Error {
                message: format!("{err:#}"),
            },
        },
    };
    if matches!(response, Response::Vars { .. }) {
        // A successful fetch is user activity: reset the idle clock and pick up
        // any change the user made to `idle_ttl_secs` since the last unlock.
        st.refresh_idle_ttl();
        st.touch();
    }
    response
}

/// Read and decrypt the secrets file, returning a locked plaintext buffer.
fn unlock(passphrase: Zeroizing<String>) -> Result<LockedSecret> {
    let path = config::secrets_path()?;
    let ciphertext = std::fs::read(&path)
        .with_context(|| format!("reading {} (run `hsh init` first?)", path.display()))?;
    let plaintext = crypto::decrypt(&ciphertext, SecretString::from(passphrase.to_string()))?;
    let secret = LockedSecret::new(plaintext);
    if !secret.is_locked() {
        // mlock(2) failed — usually RLIMIT_MEMLOCK is too low. Secrets stay
        // zeroize-on-drop but could be swapped to disk before then.
        eprintln!(
            "hsh agent: warning: could not mlock the cached secrets — \
             RLIMIT_MEMLOCK may be too low, allowing the kernel to swap them"
        );
    }
    Ok(secret)
}

/// Extract cached vars: a `keys` subset, or every var when `keys` is `None`.
fn lookup(secrets: &LockedSecret, keys: Option<&[String]>) -> Result<BTreeMap<String, String>> {
    let text =
        std::str::from_utf8(secrets.as_bytes()).context("cached secrets are not valid UTF-8")?;
    let mut all = envfile::parse(text)?;
    let out: BTreeMap<String, String> = match keys {
        None => all.iter().cloned().collect(),
        Some(keys) => keys
            .iter()
            .filter_map(|key| {
                all.iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, value)| (key.clone(), value.clone()))
            })
            .collect(),
    };
    // Scrub the transient full-file parse; only `out` should survive.
    for (key, value) in &mut all {
        key.zeroize();
        value.zeroize();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expires_in_counts_down() {
        let mut st = AgentState::new();
        assert_eq!(st.expires_in(), None);
        st.unlock_with(
            LockedSecret::new(b"x".to_vec()),
            Some(Duration::from_secs(10)),
        );
        let left = st.expires_in().unwrap();
        assert!((9..=10).contains(&left));
    }

    #[test]
    fn expire_if_idle_forgets_after_ttl() {
        let mut st = AgentState::new();
        st.unlock_with(
            LockedSecret::new(b"x".to_vec()),
            Some(Duration::from_millis(1)),
        );
        std::thread::sleep(Duration::from_millis(20));
        st.expire_if_idle();
        assert!(st.secrets.is_none());
    }

    #[test]
    fn touch_resets_the_idle_clock() {
        let mut st = AgentState::new();
        st.unlock_with(
            LockedSecret::new(b"x".to_vec()),
            Some(Duration::from_millis(50)),
        );
        std::thread::sleep(Duration::from_millis(30));
        st.touch();
        std::thread::sleep(Duration::from_millis(30));
        st.expire_if_idle();
        assert!(
            st.secrets.is_some(),
            "touch should have reset the idle window"
        );
    }
}
