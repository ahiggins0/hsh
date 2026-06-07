//! Loading the least-privilege profile manifest (`profiles.toml`).

use std::collections::BTreeMap;
use std::io::ErrorKind;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::config;

/// The parsed `profiles.toml`.
#[derive(Debug, Default, Deserialize)]
pub struct Manifest {
    /// Idle timeout before the agent forgets its cache (used in phase 5).
    #[serde(default)]
    pub idle_ttl_secs: Option<u64>,
    /// Named profiles, each listing the variables a command may receive.
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

/// One named profile: the set of variables it exposes.
#[derive(Debug, Deserialize)]
pub struct Profile {
    pub vars: Vec<String>,
}

impl Manifest {
    /// The variables allowed for `name`, or an error if it is not defined.
    pub fn keys_for(&self, name: &str) -> Result<Vec<String>> {
        match self.profiles.get(name) {
            Some(profile) => Ok(profile.vars.clone()),
            None => bail!(
                "no profile '{name}' defined in profiles.toml — add one, or use `hsh run --all`"
            ),
        }
    }
}

/// Load the manifest, returning an empty one if the file does not exist.
pub fn load() -> Result<Manifest> {
    let path = config::profiles_path()?;
    match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("parsing {}", path.display())),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(Manifest::default()),
        Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_profiles() {
        let manifest: Manifest =
            toml::from_str("idle_ttl_secs = 60\n[profiles.db]\nvars = [\"A\", \"B\"]\n").unwrap();
        assert_eq!(manifest.idle_ttl_secs, Some(60));
        assert_eq!(manifest.keys_for("db").unwrap(), vec!["A", "B"]);
        assert!(manifest.keys_for("missing").is_err());
    }

    #[test]
    fn empty_text_is_an_empty_manifest() {
        let manifest: Manifest = toml::from_str("").unwrap();
        assert!(manifest.profiles.is_empty());
        assert!(manifest.idle_ttl_secs.is_none());
    }
}
