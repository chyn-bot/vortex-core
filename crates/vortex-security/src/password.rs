//! Password hashing and policy enforcement - enterprise password policy
//!
//! Implements secure password handling with configurable policies.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher as ArgonHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use vortex_common::{VortexError, VortexResult};

/// Password policy configuration for an enterprise password policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    /// Minimum password length
    pub min_length: usize,
    /// Maximum password length
    pub max_length: usize,
    /// Require uppercase letters
    pub require_uppercase: bool,
    /// Require lowercase letters
    pub require_lowercase: bool,
    /// Require numbers
    pub require_numbers: bool,
    /// Require special characters
    pub require_special: bool,
    /// Minimum number of character classes
    pub min_character_classes: usize,
    /// Password history count (prevent reuse)
    pub history_count: usize,
    /// Password expiry in days (0 = never)
    pub expiry_days: u32,
    /// Minimum age in days before change allowed
    pub min_age_days: u32,
    /// Maximum failed attempts before lockout
    pub max_failed_attempts: u32,
    /// Lockout duration in minutes
    pub lockout_duration_minutes: u32,
    /// List of forbidden passwords
    pub forbidden_passwords: Vec<String>,
}

impl Default for PasswordPolicy {
    /// Hardened enterprise defaults
    fn default() -> Self {
        Self {
            min_length: 8,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
            min_character_classes: 3,
            history_count: 24,          // 2 years of monthly changes
            expiry_days: 365,           // rotate at least annually
            min_age_days: 1,
            max_failed_attempts: 5,
            lockout_duration_minutes: 30,
            forbidden_passwords: vec![
                "password".to_string(),
                "123456".to_string(),
                "password123".to_string(),
                "admin".to_string(),
                "letmein".to_string(),
            ],
        }
    }
}

impl PasswordPolicy {
    /// Validate a password against the policy
    pub fn validate(&self, password: &str) -> VortexResult<()> {
        // Length checks
        if password.len() < self.min_length {
            return Err(VortexError::ValidationFailed(format!(
                "Password must be at least {} characters",
                self.min_length
            )));
        }
        if password.len() > self.max_length {
            return Err(VortexError::ValidationFailed(format!(
                "Password must be at most {} characters",
                self.max_length
            )));
        }

        // Character class checks
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_numbers = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        if self.require_uppercase && !has_uppercase {
            return Err(VortexError::ValidationFailed(
                "Password must contain uppercase letters".to_string(),
            ));
        }
        if self.require_lowercase && !has_lowercase {
            return Err(VortexError::ValidationFailed(
                "Password must contain lowercase letters".to_string(),
            ));
        }
        if self.require_numbers && !has_numbers {
            return Err(VortexError::ValidationFailed(
                "Password must contain numbers".to_string(),
            ));
        }
        if self.require_special && !has_special {
            return Err(VortexError::ValidationFailed(
                "Password must contain special characters".to_string(),
            ));
        }

        // Count character classes
        let class_count = [has_uppercase, has_lowercase, has_numbers, has_special]
            .iter()
            .filter(|&&x| x)
            .count();

        if class_count < self.min_character_classes {
            return Err(VortexError::ValidationFailed(format!(
                "Password must use at least {} different character types",
                self.min_character_classes
            )));
        }

        // Check forbidden passwords
        let lower = password.to_lowercase();
        if self.forbidden_passwords.iter().any(|f| lower.contains(f)) {
            return Err(VortexError::ValidationFailed(
                "Password contains a forbidden word or pattern".to_string(),
            ));
        }

        Ok(())
    }

    /// Check if password is in history
    pub fn check_history(&self, password_hash: &str, history: &[String]) -> VortexResult<()> {
        let hasher = PasswordHasher::new();

        for historical in history.iter().take(self.history_count) {
            if hasher.verify(password_hash, historical).is_ok() {
                return Err(VortexError::ValidationFailed(
                    "Password was used recently and cannot be reused".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Password hasher using Argon2id
pub struct PasswordHasher {
    argon2: Argon2<'static>,
}

impl PasswordHasher {
    /// Create a new password hasher with secure defaults
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    /// Hash a password
    pub fn hash(&self, password: &str) -> VortexResult<String> {
        let salt = SaltString::generate(&mut OsRng);

        self.argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| VortexError::Internal(format!("Password hashing failed: {}", e)))
    }

    /// Verify a password against a hash
    pub fn verify(&self, password: &str, hash: &str) -> VortexResult<()> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|_| VortexError::AuthenticationFailed {
                username: "unknown".to_string(),
            })?;

        self.argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| VortexError::AuthenticationFailed {
                username: "unknown".to_string(),
            })
    }

    /// Check if a hash needs to be upgraded (algorithm change)
    pub fn needs_upgrade(&self, hash: &str) -> bool {
        // Check if hash uses current algorithm version
        !hash.starts_with("$argon2id$v=19$")
    }
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Password strength estimator
pub struct PasswordStrength {
    pub score: u8,          // 0-100
    pub level: StrengthLevel,
    pub feedback: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrengthLevel {
    VeryWeak,
    Weak,
    Fair,
    Strong,
    VeryStrong,
}

impl PasswordStrength {
    /// Estimate password strength
    pub fn estimate(password: &str) -> Self {
        let mut score: u8 = 0;
        let mut feedback = Vec::new();

        // Length scoring
        let len = password.len();
        score += match len {
            0..=7 => 0,
            8..=11 => 10,
            12..=15 => 20,
            16..=19 => 30,
            _ => 40,
        };

        if len < 12 {
            feedback.push("Consider using a longer password".to_string());
        }

        // Character variety
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        if has_upper { score += 10; }
        if has_lower { score += 10; }
        if has_digit { score += 10; }
        if has_special { score += 15; }

        if !has_upper { feedback.push("Add uppercase letters".to_string()); }
        if !has_lower { feedback.push("Add lowercase letters".to_string()); }
        if !has_digit { feedback.push("Add numbers".to_string()); }
        if !has_special { feedback.push("Add special characters".to_string()); }

        // Pattern detection (reduce score)
        if password.chars().collect::<Vec<_>>().windows(3).any(|w| {
            w[0] as u32 + 1 == w[1] as u32 && w[1] as u32 + 1 == w[2] as u32
        }) {
            score = score.saturating_sub(10);
            feedback.push("Avoid sequential characters".to_string());
        }

        // Repeated characters
        let unique_chars: std::collections::HashSet<_> = password.chars().collect();
        let uniqueness = unique_chars.len() as f32 / len as f32;
        if uniqueness < 0.5 {
            score = score.saturating_sub(15);
            feedback.push("Use more varied characters".to_string());
        }

        // Common patterns
        let lower = password.to_lowercase();
        let common_patterns = ["password", "123456", "qwerty", "admin", "letmein"];
        if common_patterns.iter().any(|p| lower.contains(p)) {
            score = score.saturating_sub(20);
            feedback.push("Avoid common passwords and patterns".to_string());
        }

        let level = match score {
            0..=20 => StrengthLevel::VeryWeak,
            21..=40 => StrengthLevel::Weak,
            41..=60 => StrengthLevel::Fair,
            61..=80 => StrengthLevel::Strong,
            _ => StrengthLevel::VeryStrong,
        };

        Self {
            score: score.min(100),
            level,
            feedback,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let hasher = PasswordHasher::new();
        let password = "SecureP@ssw0rd!";

        let hash = hasher.hash(password).unwrap();
        assert!(hash.starts_with("$argon2"));

        assert!(hasher.verify(password, &hash).is_ok());
        assert!(hasher.verify("wrong", &hash).is_err());
    }

    #[test]
    fn test_password_policy() {
        let policy = PasswordPolicy::default();

        // Too short
        assert!(policy.validate("Short1!").is_err());

        // Missing uppercase
        assert!(policy.validate("lowercase1!").is_err());

        // Missing special
        assert!(policy.validate("Uppercase1").is_err());

        // Valid password
        assert!(policy.validate("ValidP@ssw0rd!").is_ok());
    }
}
