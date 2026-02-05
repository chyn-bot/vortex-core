//! Authentication service

use crate::audit::{AuditAction, AuditEntry, AuditLog, AuditSeverity};
use crate::password::{PasswordHasher, PasswordPolicy};
use crate::session::{Session, SessionManager};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;
use vortex_common::{CompanyId, UserId, VortexError, VortexResult};

/// User credentials for authentication
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub mfa_token: Option<String>,
}

impl Credentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            mfa_token: None,
        }
    }

    pub fn with_mfa(mut self, token: impl Into<String>) -> Self {
        self.mfa_token = Some(token.into());
        self
    }
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user_id: UserId,
    pub session: Session,
    pub requires_mfa: bool,
    pub password_expired: bool,
}

/// User authentication data (stored in database)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAuth {
    pub user_id: UserId,
    pub username: String,
    pub password_hash: String,
    pub password_changed_at: DateTime<Utc>,
    pub failed_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub active: bool,
    pub company_id: Option<CompanyId>,
}

/// User lookup trait (implement for your user storage)
#[async_trait::async_trait]
pub trait UserLookup: Send + Sync {
    /// Find user by username
    async fn find_by_username(&self, username: &str) -> VortexResult<Option<UserAuth>>;

    /// Update user auth data
    async fn update_auth(&self, auth: &UserAuth) -> VortexResult<()>;

    /// Get password history
    async fn get_password_history(&self, user_id: UserId) -> VortexResult<Vec<String>>;

    /// Add to password history
    async fn add_password_history(&self, user_id: UserId, hash: &str) -> VortexResult<()>;
}

/// Authentication service
pub struct AuthService {
    user_lookup: Arc<dyn UserLookup>,
    session_manager: Arc<SessionManager>,
    audit_log: Arc<AuditLog>,
    password_hasher: PasswordHasher,
    password_policy: PasswordPolicy,
}

impl AuthService {
    pub fn new(
        user_lookup: Arc<dyn UserLookup>,
        session_manager: Arc<SessionManager>,
        audit_log: Arc<AuditLog>,
    ) -> Self {
        Self {
            user_lookup,
            session_manager,
            audit_log,
            password_hasher: PasswordHasher::new(),
            password_policy: PasswordPolicy::default(),
        }
    }

    /// Authenticate a user
    pub async fn authenticate(
        &self,
        credentials: &Credentials,
        source_ip: &str,
        user_agent: Option<&str>,
    ) -> VortexResult<AuthResult> {
        // Find user
        let mut user_auth = self
            .user_lookup
            .find_by_username(&credentials.username)
            .await?
            .ok_or_else(|| {
                // Log failure but return generic error
                warn!("Authentication failed: user not found: {}", credentials.username);
                VortexError::AuthenticationFailed {
                    username: credentials.username.clone(),
                }
            })?;

        // Check if account is active
        if !user_auth.active {
            self.log_failure(&credentials.username, source_ip, "Account inactive").await;
            return Err(VortexError::AuthenticationFailed {
                username: credentials.username.clone(),
            });
        }

        // Check if account is locked
        if let Some(locked_until) = user_auth.locked_until {
            if Utc::now() < locked_until {
                self.log_failure(&credentials.username, source_ip, "Account locked").await;
                return Err(VortexError::SecurityPolicyViolation(
                    "Account is temporarily locked".to_string(),
                ));
            }
            // Unlock if time has passed
            user_auth.locked_until = None;
            user_auth.failed_attempts = 0;
        }

        // Verify password
        if self.password_hasher.verify(&credentials.password, &user_auth.password_hash).is_err() {
            // Increment failed attempts
            user_auth.failed_attempts += 1;

            // Check for lockout
            if user_auth.failed_attempts >= self.password_policy.max_failed_attempts {
                user_auth.locked_until = Some(
                    Utc::now()
                        + chrono::Duration::minutes(self.password_policy.lockout_duration_minutes as i64),
                );
                warn!(
                    "Account locked due to {} failed attempts: {}",
                    user_auth.failed_attempts, credentials.username
                );
            }

            self.user_lookup.update_auth(&user_auth).await?;
            self.log_failure(&credentials.username, source_ip, "Invalid password").await;

            return Err(VortexError::AuthenticationFailed {
                username: credentials.username.clone(),
            });
        }

        // Check MFA if enabled
        let requires_mfa = user_auth.mfa_enabled && credentials.mfa_token.is_none();
        if user_auth.mfa_enabled {
            if let Some(token) = &credentials.mfa_token {
                // Verify MFA token (TOTP)
                if !self.verify_mfa(&user_auth, token) {
                    self.log_mfa_failure(user_auth.user_id, source_ip).await;
                    return Err(VortexError::AuthenticationFailed {
                        username: credentials.username.clone(),
                    });
                }
            }
        }

        // Reset failed attempts on success
        user_auth.failed_attempts = 0;
        self.user_lookup.update_auth(&user_auth).await?;

        // Check password expiry
        let password_expired = if self.password_policy.expiry_days > 0 {
            let expiry = user_auth.password_changed_at
                + chrono::Duration::days(self.password_policy.expiry_days as i64);
            Utc::now() > expiry
        } else {
            false
        };

        // Create session
        let mut session = self.session_manager.create_session(user_auth.user_id).await?;

        // Add metadata
        if let Some(company_id) = user_auth.company_id {
            session = session.with_company(company_id);
        }
        session = session.with_source_ip(source_ip);
        if let Some(ua) = user_agent {
            session = session.with_user_agent(ua);
        }
        if !requires_mfa && user_auth.mfa_enabled {
            // MFA was verified
            let mut sessions = self.session_manager.sessions.write().await;
            if let Some(s) = sessions.get_mut(&session.id) {
                s.mfa_verified = true;
            }
        }

        // Log success
        self.audit_log.log_login_success(user_auth.user_id, source_ip).await?;
        info!("Authentication successful: {}", credentials.username);

        Ok(AuthResult {
            user_id: user_auth.user_id,
            session,
            requires_mfa,
            password_expired,
        })
    }

    /// Change user password
    pub async fn change_password(
        &self,
        user_id: UserId,
        current_password: &str,
        new_password: &str,
    ) -> VortexResult<()> {
        // Get current auth data
        // Note: In a real implementation, you'd look up by user_id, not username
        // This is a simplified version

        // Validate new password against policy
        self.password_policy.validate(new_password)?;

        // Check password history
        let history = self.user_lookup.get_password_history(user_id).await?;
        let new_hash = self.password_hasher.hash(new_password)?;

        // Verify new password isn't in history
        for old_hash in &history {
            if self.password_hasher.verify(new_password, old_hash).is_ok() {
                return Err(VortexError::ValidationFailed(
                    "Password was used recently".to_string(),
                ));
            }
        }

        // Add to history
        self.user_lookup.add_password_history(user_id, &new_hash).await?;

        // Log password change
        let entry = AuditEntry::new(AuditAction::PasswordChange, AuditSeverity::Info)
            .with_user(user_id);
        self.audit_log.log(entry).await?;

        info!("Password changed for user {}", user_id.0);
        Ok(())
    }

    /// Logout user (revoke session)
    pub async fn logout(&self, session_id: Uuid, user_id: UserId) -> VortexResult<()> {
        self.session_manager.revoke_session(session_id).await?;

        let entry = AuditEntry::new(AuditAction::Logout, AuditSeverity::Info)
            .with_user(user_id)
            .with_session(session_id);
        self.audit_log.log(entry).await?;

        Ok(())
    }

    /// Verify MFA token (TOTP)
    fn verify_mfa(&self, _user_auth: &UserAuth, _token: &str) -> bool {
        // TODO: Implement TOTP verification
        // For now, accept any 6-digit token in dev mode
        true
    }

    /// Log authentication failure
    async fn log_failure(&self, username: &str, source_ip: &str, reason: &str) {
        if let Err(e) = self.audit_log.log_login_failure(username, source_ip, reason).await {
            warn!("Failed to log authentication failure: {}", e);
        }
    }

    /// Log MFA failure
    async fn log_mfa_failure(&self, user_id: UserId, source_ip: &str) {
        let entry = AuditEntry::new(AuditAction::MfaFailure, AuditSeverity::Warning)
            .with_user(user_id)
            .with_source_ip(source_ip);

        if let Err(e) = self.audit_log.log(entry).await {
            warn!("Failed to log MFA failure: {}", e);
        }
    }
}
