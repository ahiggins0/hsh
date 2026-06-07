//! Filesystem locations used by hsh.

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Encrypted secrets file, inside the config directory.
pub const SECRETS_FILE: &str = "secrets.age";
/// Least-privilege profile manifest, inside the config directory.
pub const PROFILES_FILE: &str = "profiles.toml";
/// Daemon control socket, inside the runtime directory.
pub const SOCKET_FILE: &str = "hsh.sock";
/// Daemon PID file, inside the runtime directory.
pub const PID_FILE: &str = "hsh.pid";

/// `$XDG_CONFIG_HOME/hsh`, falling back to `~/.config/hsh`.
pub fn config_dir() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return Ok(PathBuf::from(xdg).join("hsh"));
    }
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config").join("hsh"))
}

/// Path to the encrypted secrets file.
pub fn secrets_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(SECRETS_FILE))
}

/// Path to the profile manifest.
pub fn profiles_path() -> Result<PathBuf> {
    Ok(config_dir()?.join(PROFILES_FILE))
}

/// Path to the daemon control socket, in a per-user runtime directory.
pub fn socket_path() -> Result<PathBuf> {
    // Honored first on every OS so it can be overridden explicitly.
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR")
        && !rt.is_empty()
    {
        return Ok(PathBuf::from(rt).join(SOCKET_FILE));
    }
    runtime_fallback()
}

/// Per-OS fallback for the runtime directory when `XDG_RUNTIME_DIR` is unset.
#[cfg(target_os = "linux")]
fn runtime_fallback() -> Result<PathBuf> {
    // SAFETY: getuid() is always successful and touches no memory.
    let uid = unsafe { libc::getuid() };
    let dir = PathBuf::from(format!("/run/user/{uid}"));
    if dir.is_dir() {
        return Ok(dir.join(SOCKET_FILE));
    }
    anyhow::bail!("XDG_RUNTIME_DIR is unset and /run/user/{uid} does not exist");
}

/// On macOS there is no `/run/user`; use the per-user secure temp dir
/// (`_CS_DARWIN_USER_TEMP_DIR`, a 0700 path under `/var/folders/...`), falling
/// back to `$TMPDIR`. The socket lives in an `hsh/` subdir we tighten to 0700.
#[cfg(target_os = "macos")]
fn runtime_fallback() -> Result<PathBuf> {
    let base = darwin_user_temp_dir()
        .or_else(|| std::env::var_os("TMPDIR").map(PathBuf::from))
        .context("no per-user temp dir found (set XDG_RUNTIME_DIR)")?;
    Ok(base.join("hsh").join(SOCKET_FILE))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn runtime_fallback() -> Result<PathBuf> {
    anyhow::bail!("XDG_RUNTIME_DIR is unset and no runtime-dir fallback exists for this OS");
}

/// Query `confstr(_CS_DARWIN_USER_TEMP_DIR)` for the caller's private temp dir.
#[cfg(target_os = "macos")]
fn darwin_user_temp_dir() -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    // SAFETY: confstr writes up to `len` bytes into `buf` and returns the
    // required size (including the NUL); a zero return means unavailable.
    let len = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    let written =
        unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr().cast(), len) };
    if written == 0 || written > len {
        return None;
    }
    // Drop the trailing NUL that confstr includes in the count.
    buf.truncate(written - 1);
    Some(PathBuf::from(OsString::from_vec(buf)))
}

/// Path to the daemon PID file, alongside the control socket.
pub fn pid_path() -> Result<PathBuf> {
    Ok(socket_path()?.with_file_name(PID_FILE))
}

/// Create the config directory if needed and tighten it to `0700`.
pub fn ensure_config_dir() -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let dir = config_dir()?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting permissions on {}", dir.display()))?;
    Ok(dir)
}
