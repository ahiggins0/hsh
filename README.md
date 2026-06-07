> [!DISCLAIMER]
> This is a disclaimer. This is a vibe coded tool. Use at your own discretion.

# `hsh` — hardened shell

A small Rust CLI that keeps your environment-variable secrets in an
age-encrypted file and injects them into individual commands rather than
into your interactive shell.

Inspired by [`sops exec-env`](https://github.com/getsops/sops), reduced to one
job and one user.

## Why

A secret in your shell's environment is inherited by every child process and
readable by anything running as the same user — via `/proc/<pid>/environ` on
Linux, or `ps -E` / process inspection on macOS. `hsh` shrinks both axes of
that exposure:

- **At rest**: secrets live in an age-encrypted file. Plaintext never touches
  disk: the daemon holds the decrypted file in a small `mlock`'d buffer, and
  each `hsh run` only ever holds the subset it injects, transiently, before
  `exec`. (That client copy lives on the normal heap, not the `mlock`'d buffer —
  see *Memory hygiene*.)
- **Live**: each command gets only the variables its profile lists, injected
  into *its* environment via `exec`. The calling shell never sees them. The
  daemon forgets the cache on screen-lock, suspend, or after an idle TTL.

It does **not** defend against a live attacker already running as the same
user — they can reach the socket and the daemon's memory. That boundary needs
a separate user, VM, or hardware token, which is out of scope.

## Install

```sh
cargo install --path .
```

## Platform support

| | Linux | macOS |
|---|---|---|
| At-rest encryption (age) | ✅ | ✅ |
| Per-command injection (`exec`) | ✅ | ✅ |
| `mlock`'d cache, zeroize-on-drop | ✅ | ✅ |
| Core-dump suppression | `RLIMIT_CORE` + `PR_SET_DUMPABLE` | `RLIMIT_CORE` |
| Forget after idle TTL | ✅ | ✅ |
| Forget on screen-lock / suspend | ✅ (logind) | ❌ not yet |

macOS builds and runs with everything except the screen-lock/suspend hook —
that relies on systemd-logind, which macOS lacks, so the idle TTL is the only
"user went away" trigger there. A CoreGraphics-based lock backend is a possible
follow-up (see `PLAN.md`). On macOS the control socket lives under the per-user
secure temp dir (`/var/folders/.../hsh/hsh.sock`) instead of `$XDG_RUNTIME_DIR`;
set `XDG_RUNTIME_DIR` to override the location on either OS.

## Quickstart

```sh
# 1. Create the encrypted secrets file. Enter your variables one at a
#    time; press Enter on an empty name to finish, then pick a passphrase.
hsh init

# 2. Edit ~/.config/hsh/profiles.toml — the starter file lists your
#    variable names as comments so you can copy them into profiles.

# 3. Run anything with its secrets injected.
hsh run -- psql                       # uses the `psql` profile by default
hsh run -p aws -- terraform apply     # explicit profile
hsh run --all -- ./deploy.sh          # inject every variable

# 4. Drop the cache manually when you're done.
hsh lock
```

The first `hsh run` after boot prompts for the passphrase once. Later runs
reuse the unlocked cache until the idle TTL expires, you suspend, your
screen locks, or you call `hsh lock`.

## File formats

### `~/.config/hsh/secrets.age` (encrypted)

The decrypted contents are a tiny dotenv-style file:

```sh
# hsh secrets — one KEY=VALUE per line.
# '#' as the first non-blank char is a comment. Blank lines ignored.
# The value is the literal rest of the line: no shell expansion, no $VAR.

DATABASE_URL=postgres://appuser:s3cr3t@localhost:5432/app
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_1a2b3c4d5e6f

# Wrap a value in double quotes only if it has leading/trailing spaces:
GREETING="  hello world  "
```

Keys match `[A-Za-z_][A-Za-z0-9_]*`. The value is everything after the first
`=`, so `#` and `=` inside values are fine. No escaping, no variable
expansion. To edit, decrypt, change, re-encrypt — there is no `hsh edit` yet.

### `~/.config/hsh/profiles.toml` (cleartext)

The least-privilege map — which variables each command may see:

```toml
idle_ttl_secs = 3600          # forget cached secrets after 1h idle

[profiles.psql]
vars = ["DATABASE_URL"]

[profiles.aws]
vars = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]

[profiles.gh]
vars = ["GITHUB_TOKEN"]
```

`terraform` will never see the `GITHUB_TOKEN`; `psql` will never see the AWS
keys. The default profile for `hsh run -- foo` is the one named `foo`. Use
`--all` as an escape hatch when you genuinely need everything.

## Commands

| Command | Purpose |
|---|---|
| `hsh init` | Create the encrypted file interactively. |
| `hsh run -- <cmd> [args...]` | Run `cmd` with the `cmd` profile's vars injected. |
| `hsh run -p <name> -- <cmd>` | Use a specific profile. |
| `hsh run --all -- <cmd>` | Inject every variable. |
| `hsh status` | Daemon state and time until idle expiry. |
| `hsh lock` | Forget the cached secrets now. |
| `hsh agent` | Run the daemon in the foreground (normally auto-spawned). |

## How it works

Three pieces:

```
hsh                            short-lived CLI you invoke
hsh agent                      per-user daemon (decrypted vars in mlock'd RAM)
~/.config/hsh/                 secrets.age + profiles.toml
$XDG_RUNTIME_DIR/hsh.sock      0600 control socket (per-user temp dir on macOS)
```

The agent is the *only* long-lived process and the *only* one that ever holds
plaintext. It listens on a per-user unix socket (mode 0600 in tmpfs), holds
the decrypted file in a single fixed-capacity `mlock`'d buffer, and zeroizes
it on drop. Two background threads watch for "user went away":

- A 250 ms idle ticker drops the cache when `idle_ttl_secs` elapses since the
  last `hsh run` activity.
- On Linux, a zbus listener subscribes to logind's session `Lock` and
  `PrepareForSleep(true)` signals. If the system bus is unreachable
  (containers, CI), this thread exits quietly and the idle TTL carries on.
  macOS has no logind, so only the idle ticker runs there.

`hsh run` resolves the profile, asks the agent for that subset of keys, then
`exec`s the target command with those vars in its environment. Because `exec`
*replaces* the current process, the secrets never enter `hsh run`'s own
`/proc/<pid>/environ` — only the child's.

## Memory hygiene

- **`LockedSecret`**: heap buffer locked with `mlock` on construction (so the
  kernel cannot swap it to disk) and `zeroize`d + `munlock`ed on drop. It
  never grows, so no realloc strands a plaintext copy.
- **No `mlockall`**: the agent does *not* call `mlockall(MCL_FUTURE)`. The
  memory-hard scrypt KDF that decrypts the file allocates well past
  `RLIMIT_MEMLOCK` and would abort the process. Per-buffer locking is the
  right granularity.
- **No core dumps**: both the agent and `hsh run` call `setrlimit(RLIMIT_CORE,
  0)`, and on Linux also `prctl(PR_SET_DUMPABLE, 0)` — the latter is the one
  that actually works when `kernel.core_pattern` is a pipe to systemd-coredump
  or apport. macOS has no `prctl`, so `RLIMIT_CORE` is the suppressor there.
- **Passphrases & plaintext**: held in `secrecy::SecretString` /
  zeroize-on-drop buffers throughout — the passphrase rides the wire in a
  `Zeroizing` buffer and never appears in a `Debug` rendering. The IPC line is
  zeroized after every message, and the daemon wipes its copy of a `vars`
  response once it is written. The one copy that is *not* `mlock`'d is the
  subset `hsh run` injects: it sits on the client's normal heap for the moment
  between fetch and `exec`. Core dumps are disabled there too, so it cannot
  leak that way, but the kernel could in principle swap it.
- **Socket**: per-user, mode 0600, in a 0700 parent directory —
  `$XDG_RUNTIME_DIR` (tmpfs) on Linux, the per-user secure temp dir on macOS.

If the agent's `mlock` fails (usually `RLIMIT_MEMLOCK` too low —
`ulimit -l`), it logs a warning at unlock time. Secrets are still
zeroize-on-drop, but the kernel may swap them before then.

## Threat model

`hsh` defends **at-rest** (encrypted file, plaintext only ever in RAM) and
**shrinks the live window** (per-command injection, forget-on-lock). It does
**not** defend against a live attacker already running as the same user —
they can connect to the socket, prompt the daemon for vars, or read the
daemon's memory (e.g. `/proc/<pid>/mem` on Linux). That boundary needs a
separate user, VM, or hardware token, which is explicitly out of scope.

## Layout

```
src/
  main.rs        CLI dispatch
  cli.rs         clap definitions
  config.rs      XDG paths
  envfile.rs     parse/serialize KEY=VALUE
  crypto.rs      age encrypt/decrypt
  hygiene.rs     LockedSecret, disable_core_dumps()
  protocol.rs    IPC request/response (newline-delimited JSON)
  agent.rs       daemon: socket server + locked cache + state
  forget.rs      idle-TTL ticker + logind listener
  client.rs      connect to daemon, auto-spawn it
  prompt.rs      TTY-aware passphrase / line prompts (to stderr)
  profiles.rs    load profiles.toml
  commands/
    init.rs      interactive creation
    run.rs       exec-wrapper
    status.rs    daemon state
    lock.rs      forget now
```

See `PLAN.md` for the design rationale.
