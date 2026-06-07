//! Parsing and serialisation of the `KEY=VALUE` secrets format.
//!
//! Rules (deliberately minimal):
//! - One `KEY=VALUE` per line; the value is everything after the first `=`.
//! - A `#` as the first non-blank character starts a comment; blank lines are
//!   ignored. `#` and `=` inside a value are literal.
//! - A value may be wrapped in double quotes to preserve leading/trailing
//!   whitespace. There is no escaping and no variable expansion.

use anyhow::{Result, bail};

/// Is `key` a valid environment variable name: `[A-Za-z_][A-Za-z0-9_]*`?
pub fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parse env-file text into ordered `(key, value)` pairs.
pub fn parse(input: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (idx, raw) in input.lines().enumerate() {
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(eq) = line.find('=') else {
            bail!("line {}: expected KEY=VALUE, found {:?}", idx + 1, raw);
        };
        let key = line[..eq].trim_end();
        if !is_valid_key(key) {
            bail!("line {}: invalid key name {:?}", idx + 1, key);
        }
        out.push((key.to_string(), unquote(&line[eq + 1..])));
    }
    Ok(out)
}

/// Serialise `(key, value)` pairs into env-file text (one newline-terminated
/// line each).
pub fn serialize(vars: &[(String, String)]) -> String {
    // Pre-size so `out` never reallocates and strands a stale secret copy, and
    // build it with `push` rather than `format!` so no secret-bearing
    // temporary strings are allocated and dropped un-zeroized.
    let capacity: usize = vars.iter().map(|(k, v)| k.len() + v.len() + 4).sum();
    let mut out = String::with_capacity(capacity);
    for (key, value) in vars {
        out.push_str(key);
        out.push('=');
        if needs_quoting(value) {
            out.push('"');
            out.push_str(value);
            out.push('"');
        } else {
            out.push_str(value);
        }
        out.push('\n');
    }
    out
}

/// Strip one layer of surrounding double quotes; otherwise trim whitespace.
fn unquote(raw: &str) -> String {
    let trimmed = raw.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

/// A value needs quoting if it has edge whitespace, or would otherwise be
/// misread as already-quoted on the next parse.
fn needs_quoting(value: &str) -> bool {
    value != value.trim() || (value.len() >= 2 && value.starts_with('"') && value.ends_with('"'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_validation() {
        assert!(is_valid_key("FOO_BAR9"));
        assert!(is_valid_key("_x"));
        assert!(!is_valid_key("9x"));
        assert!(!is_valid_key(""));
        assert!(!is_valid_key("a-b"));
    }

    #[test]
    fn parses_basic() {
        let vars = parse("FOO=bar\n# comment\n\n  BAZ=qux\n").unwrap();
        assert_eq!(
            vars,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("BAZ".to_string(), "qux".to_string()),
            ]
        );
    }

    #[test]
    fn value_keeps_special_chars() {
        let vars = parse("URL=postgres://u:p@h/db?x=1#frag\n").unwrap();
        assert_eq!(vars[0].1, "postgres://u:p@h/db?x=1#frag");
    }

    #[test]
    fn quoted_value_preserves_whitespace() {
        let vars = parse("PAD=\"  hello world  \"\n").unwrap();
        assert_eq!(vars[0].1, "  hello world  ");
    }

    #[test]
    fn rejects_invalid_input() {
        assert!(parse("1BAD=x\n").is_err());
        assert!(parse("no equals here\n").is_err());
    }

    #[test]
    fn round_trips() {
        let original = vec![
            ("A".to_string(), "simple".to_string()),
            ("B".to_string(), "  padded  ".to_string()),
            ("C".to_string(), "with=equals#hash".to_string()),
            ("D".to_string(), "\"quoted\"".to_string()),
            ("E".to_string(), String::new()),
        ];
        let parsed = parse(&serialize(&original)).unwrap();
        assert_eq!(parsed, original);
    }
}
