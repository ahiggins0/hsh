//! Memory-hygiene primitives: keep secrets out of swap and core dumps.

use libc::{RLIMIT_CORE, c_void, mlock, munlock, rlimit, setrlimit};
use zeroize::Zeroize;

/// A heap buffer of sensitive bytes.
///
/// On construction the buffer's pages are `mlock`'d so the kernel cannot swap
/// them to disk. On drop the bytes are zeroized and the pages unlocked. The
/// buffer never grows, so it cannot reallocate and strand a plaintext copy.
///
/// Locking is per-buffer on purpose: a process-wide `mlockall(MCL_FUTURE)`
/// would force the memory-hard scrypt KDF's large allocations into locked RAM
/// and blow past `RLIMIT_MEMLOCK`.
pub struct LockedSecret {
    buf: Vec<u8>,
    locked: bool,
}

impl LockedSecret {
    /// Take ownership of `data` and lock its pages into RAM.
    ///
    /// `mlock` may fail (e.g. `RLIMIT_MEMLOCK` too low); [`Self::is_locked`]
    /// reports whether it succeeded. The bytes are zeroized on drop regardless.
    pub fn new(data: Vec<u8>) -> Self {
        let locked = if data.capacity() == 0 {
            false
        } else {
            // SAFETY: pointer and length describe this Vec's live allocation.
            unsafe { mlock(data.as_ptr() as *const c_void, data.capacity()) == 0 }
        };
        Self { buf: data, locked }
    }

    /// The protected bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Whether `mlock` succeeded for this buffer.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for LockedSecret {
    fn drop(&mut self) {
        let capacity = self.buf.capacity();
        self.buf.zeroize();
        if self.locked {
            // SAFETY: same allocation locked in `new`; the capacity is
            // unchanged because the buffer is never mutated after construction.
            unsafe {
                munlock(self.buf.as_ptr() as *const c_void, capacity);
            }
        }
    }
}

/// Prevent this process from writing a core dump, which would contain secrets.
///
/// Sets `RLIMIT_CORE` to zero and, on Linux, clears the process "dumpable" flag.
/// The flag is the reliable suppressor there: when `kernel.core_pattern` is a
/// pipe (systemd-coredump, apport), a zero `RLIMIT_CORE` alone does not stop the
/// dump. macOS has no `prctl(PR_SET_DUMPABLE)`; `RLIMIT_CORE` is the mechanism.
pub fn disable_core_dumps() -> std::io::Result<()> {
    let limit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, initialised rlimit for the duration of the call.
    if unsafe { setrlimit(RLIMIT_CORE, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    set_undumpable()
}

/// Clear the process "dumpable" flag so core-pattern pipes cannot capture a dump.
#[cfg(target_os = "linux")]
fn set_undumpable() -> std::io::Result<()> {
    // SAFETY: PR_SET_DUMPABLE takes one value argument; unused args are zero.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// No portable `prctl(PR_SET_DUMPABLE)` off Linux; `RLIMIT_CORE = 0` set above is
/// the suppressor (macOS does not pipe core dumps to a capturing handler).
#[cfg(not(target_os = "linux"))]
fn set_undumpable() -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_secret_exposes_bytes() {
        let secret = LockedSecret::new(b"hunter2".to_vec());
        assert_eq!(secret.as_bytes(), b"hunter2");
    }

    #[test]
    fn empty_secret_is_safe() {
        let secret = LockedSecret::new(Vec::new());
        assert_eq!(secret.as_bytes(), b"");
        assert!(!secret.is_locked());
    }

    #[test]
    fn disabling_core_dumps_succeeds() {
        disable_core_dumps().unwrap();
    }
}
