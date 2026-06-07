//! End-to-end test for `hsh init`: it must produce a real, decryptable file.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

#[test]
fn init_creates_a_decryptable_file() {
    let root = std::env::temp_dir().join(format!("hsh-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let config_home = root.join("config");
    std::fs::create_dir_all(&config_home).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_hsh"))
        .arg("init")
        .env("XDG_CONFIG_HOME", &config_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn hsh");

    // name, value, blank line (finish), passphrase, confirmation.
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"DATABASE_URL\npostgres://localhost/db\n\nhunter2\nhunter2\n")
        .unwrap();

    assert!(child.wait().unwrap().success(), "hsh init should succeed");

    let secrets = config_home.join("hsh").join("secrets.age");
    let profiles = config_home.join("hsh").join("profiles.toml");
    assert!(secrets.exists(), "secrets.age should be created");
    assert!(profiles.exists(), "profiles.toml should be created");

    // The file must be real age ciphertext, decryptable with the passphrase.
    let ciphertext = std::fs::read(&secrets).unwrap();
    let identity =
        age::scrypt::Identity::new(age::secrecy::SecretString::from("hunter2".to_string()));
    let decryptor = age::Decryptor::new(&ciphertext[..]).expect("valid age header");
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .expect("decrypt with correct passphrase");
    let mut plaintext = String::new();
    reader.read_to_string(&mut plaintext).unwrap();
    assert_eq!(plaintext, "DATABASE_URL=postgres://localhost/db\n");

    let _ = std::fs::remove_dir_all(&root);
}
