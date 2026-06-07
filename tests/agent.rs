//! End-to-end test for the `hsh agent` daemon and its IPC protocol.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Create a clean, uniquely-named temp tree: (root, config_home, runtime).
fn temp_tree(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("hsh-it-{tag}"));
    let _ = std::fs::remove_dir_all(&root);
    let config_home = root.join("config");
    let runtime = root.join("run");
    std::fs::create_dir_all(&config_home).unwrap();
    std::fs::create_dir_all(&runtime).unwrap();
    (root, config_home, runtime)
}

/// Run `hsh init` non-interactively to create a secrets file.
fn init_secrets(hsh: &str, config_home: &Path, runtime: &Path, input: &[u8]) {
    let mut child = Command::new(hsh)
        .arg("init")
        .env("XDG_CONFIG_HOME", config_home)
        .env("XDG_RUNTIME_DIR", runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    assert!(child.wait().unwrap().success(), "hsh init failed");
}

fn wait_for_socket(path: &Path) -> bool {
    for _ in 0..100 {
        if UnixStream::connect(path).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Send one JSON request line and return the JSON response line.
fn rpc(socket: &Path, request: &str) -> String {
    let mut stream = UnixStream::connect(socket).expect("connect to agent");
    stream.write_all(request.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response).unwrap();
    response
}

#[test]
fn agent_serves_the_protocol() {
    let hsh = env!("CARGO_BIN_EXE_hsh");
    let (root, config_home, runtime) = temp_tree("agent-proto");
    init_secrets(
        hsh,
        &config_home,
        &runtime,
        b"DATABASE_URL\npostgres://localhost/db\n\nhunter2\nhunter2\n",
    );

    let mut agent = Command::new(hsh)
        .arg("agent")
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_RUNTIME_DIR", &runtime)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let socket = runtime.join("hsh.sock");
    assert!(wait_for_socket(&socket), "agent socket never appeared");

    // Starts locked.
    assert!(rpc(&socket, r#"{"op":"status"}"#).contains("\"unlocked\":false"));
    // Get while locked is rejected.
    assert!(rpc(&socket, r#"{"op":"get","keys":["DATABASE_URL"]}"#).contains("locked"));
    // Unlock with the right passphrase.
    assert!(rpc(&socket, r#"{"op":"unlock","passphrase":"hunter2"}"#).contains("\"ok\""));
    // Now unlocked.
    assert!(rpc(&socket, r#"{"op":"status"}"#).contains("\"unlocked\":true"));
    // Get returns the value.
    let got = rpc(&socket, r#"{"op":"get","keys":["DATABASE_URL"]}"#);
    assert!(got.contains("postgres://localhost/db"), "got: {got}");
    // Unknown keys are simply absent from the result.
    let missing = rpc(&socket, r#"{"op":"get","keys":["NOPE"]}"#);
    assert!(
        missing.contains("\"vars\"") && !missing.contains("NOPE"),
        "got: {missing}"
    );
    // Lock forgets the secrets.
    assert!(rpc(&socket, r#"{"op":"lock"}"#).contains("\"ok\""));
    assert!(rpc(&socket, r#"{"op":"status"}"#).contains("\"unlocked\":false"));
    // Wrong passphrase fails.
    assert!(rpc(&socket, r#"{"op":"unlock","passphrase":"wrong"}"#).contains("error"));

    agent.kill().unwrap();
    agent.wait().unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn idle_ttl_forgets_the_cache() {
    let hsh = env!("CARGO_BIN_EXE_hsh");
    let (root, config_home, runtime) = temp_tree("agent-idle");
    init_secrets(
        hsh,
        &config_home,
        &runtime,
        b"FOO\nbar\n\nhunter2\nhunter2\n",
    );

    // Overwrite the starter profiles file with a tiny TTL we can wait out.
    std::fs::write(
        config_home.join("hsh").join("profiles.toml"),
        "idle_ttl_secs = 1\n",
    )
    .unwrap();

    let mut agent = Command::new(hsh)
        .arg("agent")
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_RUNTIME_DIR", &runtime)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let socket = runtime.join("hsh.sock");
    assert!(wait_for_socket(&socket), "agent socket never appeared");

    assert!(rpc(&socket, r#"{"op":"unlock","passphrase":"hunter2"}"#).contains("\"ok\""));
    let status = rpc(&socket, r#"{"op":"status"}"#);
    assert!(
        status.contains("\"unlocked\":true") && status.contains("\"expires_in\""),
        "expected unlocked status with expires_in: {status}"
    );

    // The TTL is 1s and the idle watcher polls every 250ms; 2s is generous.
    std::thread::sleep(Duration::from_millis(2000));

    assert!(
        rpc(&socket, r#"{"op":"status"}"#).contains("\"unlocked\":false"),
        "agent did not forget after the idle TTL elapsed"
    );

    agent.kill().unwrap();
    agent.wait().unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn client_auto_spawns_the_agent() {
    let hsh = env!("CARGO_BIN_EXE_hsh");
    let (root, config_home, runtime) = temp_tree("agent-spawn");

    // No agent running and no secrets file — `status` must still succeed by
    // auto-spawning the daemon.
    let output = Command::new(hsh)
        .arg("status")
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_RUNTIME_DIR", &runtime)
        .output()
        .unwrap();
    assert!(output.status.success(), "hsh status failed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("locked"), "unexpected output: {stdout}");

    // Clean up the detached agent via its pidfile.
    if let Ok(pid) = std::fs::read_to_string(runtime.join("hsh.pid")) {
        let _ = Command::new("kill").arg("-9").arg(pid.trim()).status();
    }
    let _ = std::fs::remove_dir_all(&root);
}
