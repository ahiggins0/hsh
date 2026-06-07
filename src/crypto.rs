//! Passphrase-based encryption of the secrets file, backed by `age` (scrypt).

use anyhow::{Context, Result};
use std::io::{Read, Write};

/// Re-exported so the rest of the crate has one canonical `SecretString` type,
/// matching the version `age` expects.
pub use age::secrecy::SecretString;

/// Encrypt `plaintext` under `passphrase`, returning binary age ciphertext.
pub fn encrypt(plaintext: &[u8], passphrase: SecretString) -> Result<Vec<u8>> {
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .context("initialising age encryptor")?;
    writer
        .write_all(plaintext)
        .context("encrypting plaintext")?;
    writer.finish().context("finalising age ciphertext")?;
    Ok(ciphertext)
}

/// Decrypt binary age `ciphertext` under `passphrase`.
///
/// Returns an error on a wrong passphrase or a corrupt file.
pub fn decrypt(ciphertext: &[u8], passphrase: SecretString) -> Result<Vec<u8>> {
    let identity = age::scrypt::Identity::new(passphrase);
    let decryptor = age::Decryptor::new(ciphertext).context("reading age ciphertext header")?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .context("decryption failed — wrong passphrase or corrupt file")?;
    // Plaintext is always smaller than ciphertext; pre-sizing the buffer means
    // it never reallocates and never strands a stale plaintext copy in freed
    // heap memory.
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    reader
        .read_to_end(&mut plaintext)
        .context("reading decrypted plaintext")?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    #[test]
    fn round_trips() {
        let plaintext = b"DATABASE_URL=postgres://localhost/db\n";
        let ciphertext = encrypt(plaintext, pass("correct horse battery")).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext.as_slice());

        let decrypted = decrypt(&ciphertext, pass("correct horse battery")).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let ciphertext = encrypt(b"GITHUB_TOKEN=ghp_secret", pass("right")).unwrap();
        assert!(decrypt(&ciphertext, pass("wrong")).is_err());
    }
}
