//! End-to-end test for `hsh run`: profile resolution, injection, and `--all`.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn temp_tree(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("hsh-it-{tag}"));
    let _ = std::fs::remove_dir_all(&root);
    let config_home = root.join("config");
    let runtime = root.join("run");
    std::fs::create_dir_all(&config_home).unwrap();
    std::fs::create_dir_all(&runtime).unwrap();
    (root, config_home, runtime)
}

#[test]
fn run_injects_profile_secrets() {
    let hsh = env!("CARGO_BIN_EXE_hsh");
    let (root, config_home, runtime) = temp_tree("run");

    // 1. Create the secrets file with two variables.
    let mut init = Command::new(hsh)
        .arg("init")
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_RUNTIME_DIR", &runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    init.stdin
        .take()
        .unwrap()
        .write_all(b"HSH_TEST_DB\npg://localhost/db\nHSH_TEST_TOKEN\ntok_secret\n\npw\npw\n")
        .unwrap();
    assert!(init.wait().unwrap().success(), "init failed");

    // 2. Profiles `db` and `printenv` expose only HSH_TEST_DB.
    std::fs::write(
        config_home.join("hsh").join("profiles.toml"),
        "[profiles.db]\nvars = [\"HSH_TEST_DB\"]\n\
         [profiles.printenv]\nvars = [\"HSH_TEST_DB\"]\n",
    )
    .unwrap();

    // Helper: run `hsh run ...` with no stdin (agent already unlocked).
    let run = |args: &[&str]| -> Output {
        Command::new(hsh)
            .arg("run")
            .args(args)
            .env("XDG_CONFIG_HOME", &config_home)
            .env("XDG_RUNTIME_DIR", &runtime)
            .output()
            .unwrap()
    };

    // 3. First run: agent is locked, so supply the passphrase on stdin.
    let mut first = Command::new(hsh)
        .args(["run", "-p", "db", "--", "printenv", "HSH_TEST_DB"])
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_RUNTIME_DIR", &runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    first.stdin.take().unwrap().write_all(b"pw\n").unwrap();
    let first_out = first.wait_with_output().unwrap();
    assert!(first_out.status.success(), "first run failed");
    assert_eq!(
        String::from_utf8_lossy(&first_out.stdout).trim(),
        "pg://localhost/db"
    );

    // 4. Default profile = command basename ("printenv"); agent now unlocked.
    let out = run(&["--", "printenv", "HSH_TEST_DB"]);
    assert!(out.status.success(), "default-profile run failed");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "pg://localhost/db"
    );

    // 5. Least privilege: profile `db` must not expose HSH_TEST_TOKEN.
    let out = run(&["-p", "db", "--", "printenv", "HSH_TEST_TOKEN"]);
    assert!(!out.status.success(), "token leaked into the `db` profile");
    assert!(String::from_utf8_lossy(&out.stdout).trim().is_empty());

    // 6. `--all` injects every variable.
    let out = run(&["--all", "--", "printenv", "HSH_TEST_TOKEN"]);
    assert!(out.status.success(), "--all run failed");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "tok_secret");

    // Cleanup: kill the detached agent.
    if let Ok(pid) = std::fs::read_to_string(runtime.join("hsh.pid")) {
        let _ = Command::new("kill").arg("-9").arg(pid.trim()).status();
    }
    let _ = std::fs::remove_dir_all(&root);
}
