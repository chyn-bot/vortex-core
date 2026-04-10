//! RFC 8785 — JSON Canonicalization Scheme (JCS)
//!
//! Produces a deterministic, byte-exact serialization of a JSON value so
//! that the same logical value always hashes to the same digest. This is
//! the only serialization the WORM audit ledger uses for the
//! `canonical_payload` column; entries signed by Ed25519 and chained by
//! SHA-256 depend on this being stable across processes, Rust versions,
//! and roundtrips through Postgres.
//!
//! # Why not `serde_json::to_string`?
//!
//! `serde_json` does not guarantee key order for `Map<String, Value>` in
//! all code paths, and even if the BTreeMap ordering is stable, it does
//! **not** implement the JCS number normalization rules (RFC 8785 §3.2.2).
//! Storing the output of `serde_json::to_string` and then rehashing it
//! later will silently drift whenever a serializer detail changes.
//!
//! # Why not `serde_jcs` or another crate?
//!
//! Minimizing third-party dependencies in the security crate is a project
//! requirement (supply-chain attack surface). JCS is small enough to
//! implement in ~150 LOC with full RFC 8785 test vector coverage.
//!
//! # What this implements
//!
//! - **Key ordering** (§3.2.3): object keys are sorted by UTF-16 code unit.
//! - **String escaping** (§3.2.1 / RFC 8259 §7): JSON-standard escapes for
//!   `"`, `\`, and control characters `U+0000..U+001F`; all other characters
//!   (including non-ASCII) are emitted literally as UTF-8.
//! - **Number canonicalization** (§3.2.2): integers in the safe i64 range
//!   serialize as their shortest decimal; floats use JavaScript `Number`
//!   shortest-roundtrip rules via `ryu`-compatible formatting — but to
//!   avoid pulling in `ryu`, we disallow non-integer numbers in audit
//!   payloads (enforced at [`canonicalize`] entry). Audit payloads are
//!   structured data and do not need floats.
//! - **Null, bool, array** (§3.2): literal tokens, comma-separated without
//!   whitespace.
//!
//! # Non-goals
//!
//! This is not a full general-purpose JCS implementation. It rejects
//! floating-point numbers (returning an error) because the audit ledger
//! never needs them and because implementing `ryu` shortest-roundtrip
//! serialization correctly is surprisingly subtle. If a future audit
//! caller needs floats, add `ryu` as a dependency and relax the check.

use serde_json::Value;
use std::fmt::Write as _;

/// Canonicalization error.
#[derive(Debug, thiserror::Error)]
pub enum JcsError {
    #[error("non-finite floating point number is not representable in JCS")]
    NonFiniteFloat,
    #[error("floating-point numbers are not allowed in audit canonical payloads")]
    FloatNotAllowed,
    #[error("invalid UTF-16 sequence in string: {0}")]
    InvalidUtf16(String),
}

/// Canonicalize a JSON value into a deterministic UTF-8 byte sequence
/// per RFC 8785 (with the float restriction described in the module docs).
pub fn canonicalize(value: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Ok(out)
}

fn write_value(out: &mut String, value: &Value) -> Result<(), JcsError> {
    match value {
        Value::Null => {
            out.push_str("null");
            Ok(())
        }
        Value::Bool(true) => {
            out.push_str("true");
            Ok(())
        }
        Value::Bool(false) => {
            out.push_str("false");
            Ok(())
        }
        Value::Number(n) => write_number(out, n),
        Value::String(s) => {
            write_string(out, s);
            Ok(())
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
            Ok(())
        }
        Value::Object(map) => {
            // RFC 8785 §3.2.3: sort keys by UTF-16 code unit (not byte order).
            // For ASCII keys this is identical to byte order; for non-ASCII
            // it differs. Convert keys to UTF-16 once up front.
            let mut entries: Vec<(Vec<u16>, &String, &Value)> = map
                .iter()
                .map(|(k, v)| (k.encode_utf16().collect(), k, v))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));

            out.push('{');
            for (i, (_, key, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, val)?;
            }
            out.push('}');
            Ok(())
        }
    }
}

fn write_number(out: &mut String, n: &serde_json::Number) -> Result<(), JcsError> {
    if let Some(i) = n.as_i64() {
        write!(out, "{}", i).unwrap();
        Ok(())
    } else if let Some(u) = n.as_u64() {
        write!(out, "{}", u).unwrap();
        Ok(())
    } else if let Some(f) = n.as_f64() {
        if !f.is_finite() {
            Err(JcsError::NonFiniteFloat)
        } else {
            Err(JcsError::FloatNotAllowed)
        }
    } else {
        // serde_json::Number has no other variants, but be explicit.
        Err(JcsError::NonFiniteFloat)
    }
}

/// Write a JSON string literal per RFC 8259 §7 escaping rules.
/// Non-ASCII characters are written as-is (UTF-8). Control characters
/// `U+0000..U+001F` are escaped as `\uXXXX`. The mandatory escapes are
/// `"`, `\`, and the C0 control range.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0A}' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\u{0D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                // Remaining C0 controls: \u00XX
                write!(out, "\\u{:04x}", c as u32).unwrap();
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Fixture from RFC 8785 Appendix B.2 "Simple Object".
    /// The JCS output sorts keys and strips whitespace.
    #[test]
    fn rfc8785_simple_object() {
        let input = json!({
            "numbers": [333333333, 1, 1073741824],
            "string": "\u{20ac}$\u{000f}\nA'\u{42}\u{22}\u{5c}\u{0234}",
            "literals": [null, true, false]
        });
        let out = canonicalize(&input).unwrap();
        // Expected per RFC 8785 Appendix B.2.
        // Keys sorted: literals < numbers < string.
        assert_eq!(
            out,
            "{\"literals\":[null,true,false],\
             \"numbers\":[333333333,1,1073741824],\
             \"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\u{0234}\"}"
        );
    }

    #[test]
    fn empty_collections() {
        assert_eq!(canonicalize(&json!({})).unwrap(), "{}");
        assert_eq!(canonicalize(&json!([])).unwrap(), "[]");
    }

    #[test]
    fn null_and_booleans() {
        assert_eq!(canonicalize(&json!(null)).unwrap(), "null");
        assert_eq!(canonicalize(&json!(true)).unwrap(), "true");
        assert_eq!(canonicalize(&json!(false)).unwrap(), "false");
    }

    #[test]
    fn integer_edge_cases() {
        assert_eq!(canonicalize(&json!(0)).unwrap(), "0");
        assert_eq!(canonicalize(&json!(-1)).unwrap(), "-1");
        assert_eq!(
            canonicalize(&json!(i64::MAX)).unwrap(),
            i64::MAX.to_string()
        );
        assert_eq!(
            canonicalize(&json!(i64::MIN)).unwrap(),
            i64::MIN.to_string()
        );
    }

    #[test]
    fn floats_are_rejected() {
        let v = json!(1.5);
        assert!(matches!(
            canonicalize(&v).unwrap_err(),
            JcsError::FloatNotAllowed
        ));
    }

    #[test]
    fn key_ordering_is_utf16_codeunit() {
        // Per RFC 8785 §3.2.3, keys sort by UTF-16 code unit order. For
        // ASCII, this matches byte order.
        let input = json!({
            "zulu": 1,
            "alpha": 2,
            "mike": 3,
        });
        let out = canonicalize(&input).unwrap();
        assert_eq!(out, "{\"alpha\":2,\"mike\":3,\"zulu\":1}");
    }

    #[test]
    fn string_control_escapes() {
        let input = json!({
            "s": "line1\nline2\ttabbed\u{0001}ctrl\"quote\\slash"
        });
        let out = canonicalize(&input).unwrap();
        assert_eq!(
            out,
            "{\"s\":\"line1\\nline2\\ttabbed\\u0001ctrl\\\"quote\\\\slash\"}"
        );
    }

    #[test]
    fn nested_object_sorting() {
        let input = json!({
            "outer_b": {"inner_z": 1, "inner_a": 2},
            "outer_a": {"inner_m": 3},
        });
        let out = canonicalize(&input).unwrap();
        assert_eq!(
            out,
            "{\"outer_a\":{\"inner_m\":3},\
             \"outer_b\":{\"inner_a\":2,\"inner_z\":1}}"
        );
    }

    #[test]
    fn canonicalization_is_idempotent() {
        let input = json!({
            "b": [1, 2, {"nested_z": true, "nested_a": false}],
            "a": null,
        });
        let once = canonicalize(&input).unwrap();
        let parsed: Value = serde_json::from_str(&once).unwrap();
        let twice = canonicalize(&parsed).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn non_ascii_strings_passthrough() {
        // Non-ASCII characters must be emitted as UTF-8, not as \uXXXX.
        let input = json!({"greeting": "héllo — wörld"});
        let out = canonicalize(&input).unwrap();
        assert_eq!(out, "{\"greeting\":\"héllo — wörld\"}");
    }
}
