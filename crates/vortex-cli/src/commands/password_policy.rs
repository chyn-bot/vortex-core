//! Centralized password-policy enforcement (CSRA / ICT-P11).
//!
//! Single source of truth for the account-lockout threshold, the password
//! expiry window, and the complexity rules. Shared by the web login / reset
//! paths (`server.rs`) and the `vortex user reset-password` CLI (`user.rs`)
//! so the policy can never drift between surfaces.
//!
//! These are generic, industry-neutral authentication controls (they name no
//! regulator or geography), so they live in core — a vertical compliance
//! profile maps them onto its own control references.

/// Lock the account after this many consecutive failed login attempts.
/// CSRA ICT-P11 mandates lock-out after 5.
pub const MAX_FAILED_ATTEMPTS: i32 = 5;

/// Passwords older than this must be changed before login proceeds
/// (≈3 months). CSRA ICT-P11 password-expiry control.
pub const PASSWORD_MAX_AGE_DAYS: i64 = 90;

/// Minimum password length.
pub const MIN_LENGTH: usize = 8;

/// How many previous passwords are remembered and refused on change. The
/// current password counts as one of them, so a depth of 5 means a user must
/// cycle through five distinct passwords before an old one becomes available
/// again.
pub const HISTORY_DEPTH: i64 = 5;

/// Message shown when a proposed password matches one in the remembered
/// history.
pub const HISTORY_HINT: &str = "New password must not match any of your last 5 passwords.";

/// Human-readable statement of the complexity policy, for form hints and
/// CLI messages. Keep in sync with [`validate`].
pub const POLICY_HINT: &str =
    "At least 8 characters, including an uppercase letter, a lowercase letter, a digit, and a symbol.";

/// Validate a plaintext password against the complexity policy.
///
/// Returns `Err(reason)` with a user-facing message on the first rule that
/// fails, `Ok(())` when the password satisfies every rule.
pub fn validate(password: &str) -> Result<(), String> {
    // Count Unicode scalar values, not bytes: a password of accented
    // characters shouldn't clear the length bar on byte-count alone.
    if password.chars().count() < MIN_LENGTH {
        return Err(format!("Password must be at least {MIN_LENGTH} characters."));
    }
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    // "Symbol" = anything that isn't a letter or a digit (punctuation,
    // whitespace, currency marks, …). This deliberately accepts a broad set.
    let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

    if !(has_lower && has_upper && has_digit && has_symbol) {
        return Err(
            "Password must include an uppercase letter, a lowercase letter, a digit, and a symbol."
                .to_string(),
        );
    }
    Ok(())
}

/// True when a password set at `changed_at` has passed the expiry window and
/// must be rotated before the account may be used again.
pub fn is_expired(changed_at: chrono::DateTime<chrono::Utc>) -> bool {
    chrono::Utc::now() - changed_at > chrono::Duration::days(PASSWORD_MAX_AGE_DAYS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short() {
        assert!(validate("Aa1!").is_err());
    }

    #[test]
    fn rejects_missing_class() {
        assert!(validate("alllowercase1!").is_err()); // no uppercase
        assert!(validate("ALLUPPERCASE1!").is_err()); // no lowercase
        assert!(validate("NoDigitsHere!!").is_err()); // no digit
        assert!(validate("NoSymbolHere12").is_err()); // no symbol
    }

    #[test]
    fn accepts_compliant() {
        assert!(validate("Admin@123!").is_ok());
        assert!(validate("Str0ng-Pass").is_ok());
    }

    #[test]
    fn expiry_window() {
        let fresh = chrono::Utc::now() - chrono::Duration::days(PASSWORD_MAX_AGE_DAYS - 1);
        let stale = chrono::Utc::now() - chrono::Duration::days(PASSWORD_MAX_AGE_DAYS + 1);
        assert!(!is_expired(fresh));
        assert!(is_expired(stale));
    }
}
