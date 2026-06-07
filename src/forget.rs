//! Forget-on-lock: drop the cached secrets when the user goes away.
//!
//! Two watchers can run alongside the request loop:
//!
//! - **Idle timer** — wakes every [`IDLE_POLL_INTERVAL`] and drops the cache if
//!   the configured `idle_ttl_secs` has elapsed since the last activity. Always
//!   runs, on every platform, even without a system bus.
//! - **logind listener** (Linux only) — subscribes to the session `Lock` signal
//!   and the manager's `PrepareForSleep(true)` signal; drops the cache on
//!   either. Fails softly when the bus is unreachable (containers, CI). macOS
//!   has no logind, so there the idle timer is the only watcher.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::agent::{AgentState, lock_state};

#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use zbus::blocking::Connection;
#[cfg(target_os = "linux")]
use zbus::proxy;
#[cfg(target_os = "linux")]
use zbus::zvariant::OwnedObjectPath;

/// How often the idle watcher checks the TTL. Sub-second so a one-second TTL
/// expires near its declared instant rather than potentially a full tick late.
const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Spawn the background watchers that share `state` with the request loop.
pub fn spawn_watchers(state: Arc<Mutex<AgentState>>) {
    let idle = state.clone();
    thread::Builder::new()
        .name("hsh-idle".into())
        .spawn(move || idle_loop(idle))
        .expect("spawning idle-timeout thread");

    #[cfg(target_os = "linux")]
    spawn_logind_watcher(state);
    // Off Linux the idle timer is the only watcher; `state` is otherwise unused.
    #[cfg(not(target_os = "linux"))]
    let _ = state;
}

fn idle_loop(state: Arc<Mutex<AgentState>>) -> ! {
    loop {
        thread::sleep(IDLE_POLL_INTERVAL);
        lock_state(&state).expire_if_idle();
    }
}

#[cfg(target_os = "linux")]
#[proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1"
)]
trait Logind {
    fn get_session(&self, session_id: &str) -> zbus::Result<OwnedObjectPath>;
    fn get_session_by_pid(&self, pid: u32) -> zbus::Result<OwnedObjectPath>;

    #[zbus(signal)]
    fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;
}

#[cfg(target_os = "linux")]
#[proxy(
    interface = "org.freedesktop.login1.Session",
    default_service = "org.freedesktop.login1"
)]
trait Session {
    #[zbus(signal)]
    fn lock(&self) -> zbus::Result<()>;
}

/// Spawn the logind listener thread, reporting (once) if the bus is unreachable.
#[cfg(target_os = "linux")]
fn spawn_logind_watcher(state: Arc<Mutex<AgentState>>) {
    thread::Builder::new()
        .name("hsh-logind".into())
        .spawn(move || {
            if let Err(err) = logind_loop(state) {
                eprintln!("hsh agent: forget-on-lock unavailable: {err:#}");
            }
        })
        .expect("spawning logind thread");
}

#[cfg(target_os = "linux")]
fn logind_loop(state: Arc<Mutex<AgentState>>) -> Result<()> {
    let conn = Connection::system().context("connecting to the system bus")?;
    let manager = LogindProxyBlocking::new(&conn).context("creating logind proxy")?;

    // The blocking signal iterators each park their own thread, so we cannot
    // multiplex them on this one. Hand PrepareForSleep off to a sibling and
    // keep Lock here.
    let sleep_state = state.clone();
    let sleep_manager = manager.clone();
    thread::Builder::new()
        .name("hsh-sleep".into())
        .spawn(move || sleep_loop(sleep_manager, sleep_state))
        .expect("spawning sleep-signal thread");

    let session_path = discover_session_path(&manager).context("locating our logind session")?;
    let session = SessionProxyBlocking::builder(&conn)
        .path(session_path)
        .context("setting session path")?
        .build()
        .context("building session proxy")?;

    for _signal in session
        .receive_lock()
        .context("subscribing to session Lock signal")?
    {
        lock_state(&state).forget();
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sleep_loop(manager: LogindProxyBlocking<'_>, state: Arc<Mutex<AgentState>>) {
    let iter = match manager.receive_prepare_for_sleep() {
        Ok(it) => it,
        Err(err) => {
            eprintln!("hsh agent: PrepareForSleep subscribe failed: {err}");
            return;
        }
    };
    for signal in iter {
        // `start = true` fires just before the system suspends.
        if let Ok(args) = signal.args()
            && args.start
        {
            lock_state(&state).forget();
        }
    }
}

#[cfg(target_os = "linux")]
fn discover_session_path(manager: &LogindProxyBlocking) -> Result<OwnedObjectPath> {
    if let Ok(id) = std::env::var("XDG_SESSION_ID")
        && !id.is_empty()
        && let Ok(path) = manager.get_session(&id)
    {
        return Ok(path);
    }
    manager
        .get_session_by_pid(std::process::id())
        .context("get_session_by_pid")
}
