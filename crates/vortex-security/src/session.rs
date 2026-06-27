//! Session management - enterprise session security
//!
//! Secure session handling with timeouts and tracking.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;
use vortex_common::{CompanyId, UserId, VortexError, VortexResult};

/// Session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Session timeout (idle)
    pub idle_timeout_minutes: u32,
    /// Absolute session timeout
    pub absolute_timeout_hours: u32,
    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: u32,
    /// Require re-auth for sensitive operations
    pub sensitive_operation_timeout_minutes: u32,
    /// Enable session binding to IP
    pub bind_to_ip: bool,
    /// Enable session binding to user agent
    pub bind_to_user_agent: bool,
}

impl Default for SessionConfig {
    /// Hardened enterprise defaults
    fn default() -> Self {
        Self {
            idle_timeout_minutes: 30,       // idle sessions expire within 30 minutes
            absolute_timeout_hours: 24,
            max_concurrent_sessions: 3,
            sensitive_operation_timeout_minutes: 5,
            bind_to_ip: true,
            bind_to_user_agent: true,
        }
    }
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    Active,
    Expired,
    Revoked,
    Locked,
}

/// Session data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID
    pub id: Uuid,
    /// User this session belongs to
    pub user_id: UserId,
    /// Company context
    pub company_id: Option<CompanyId>,
    /// When the session was created
    pub created_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
    /// When the session expires
    pub expires_at: DateTime<Utc>,
    /// Session state
    pub state: SessionState,
    /// Source IP address
    pub source_ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Additional session data
    pub data: HashMap<String, serde_json::Value>,
    /// Last sensitive operation timestamp (for re-auth)
    pub last_sensitive_op: Option<DateTime<Utc>>,
    /// MFA verified
    pub mfa_verified: bool,
}

impl Session {
    /// Create a new session
    pub fn new(user_id: UserId, config: &SessionConfig) -> Self {
        let now = Utc::now();
        let expires_at = now + Duration::hours(config.absolute_timeout_hours as i64);

        Self {
            id: Uuid::now_v7(),
            user_id,
            company_id: None,
            created_at: now,
            last_activity: now,
            expires_at,
            state: SessionState::Active,
            source_ip: None,
            user_agent: None,
            data: HashMap::new(),
            last_sensitive_op: None,
            mfa_verified: false,
        }
    }

    /// Check if session is valid
    pub fn is_valid(&self, config: &SessionConfig) -> bool {
        if self.state != SessionState::Active {
            return false;
        }

        let now = Utc::now();

        // Check absolute expiry
        if now > self.expires_at {
            return false;
        }

        // Check idle timeout
        let idle_timeout = Duration::minutes(config.idle_timeout_minutes as i64);
        if now > self.last_activity + idle_timeout {
            return false;
        }

        true
    }

    /// Check if re-authentication is required for sensitive operations
    pub fn requires_reauth(&self, config: &SessionConfig) -> bool {
        let timeout = Duration::minutes(config.sensitive_operation_timeout_minutes as i64);

        match self.last_sensitive_op {
            Some(last) => Utc::now() > last + timeout,
            None => true,
        }
    }

    /// Touch the session (update last activity)
    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    /// Mark sensitive operation performed
    pub fn mark_sensitive_op(&mut self) {
        self.last_sensitive_op = Some(Utc::now());
    }

    /// Set company context
    pub fn with_company(mut self, company_id: CompanyId) -> Self {
        self.company_id = Some(company_id);
        self
    }

    /// Set source IP
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    /// Set user agent
    pub fn with_user_agent(mut self, agent: impl Into<String>) -> Self {
        self.user_agent = Some(agent.into());
        self
    }

    /// Store custom data
    pub fn set_data(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.data.insert(key.into(), value);
    }

    /// Get custom data
    pub fn get_data(&self, key: &str) -> Option<&serde_json::Value> {
        self.data.get(key)
    }
}

/// Session manager
pub struct SessionManager {
    pub(crate) sessions: RwLock<HashMap<Uuid, Session>>,
    user_sessions: RwLock<HashMap<UserId, Vec<Uuid>>>,
    config: SessionConfig,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            user_sessions: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Create a new session for a user
    pub async fn create_session(&self, user_id: UserId) -> VortexResult<Session> {
        // Check concurrent session limit
        {
            let user_sessions = self.user_sessions.read().await;
            if let Some(sessions) = user_sessions.get(&user_id) {
                if sessions.len() >= self.config.max_concurrent_sessions as usize {
                    // Revoke oldest session
                    if let Some(oldest) = sessions.first() {
                        self.revoke_session(*oldest).await?;
                    }
                }
            }
        }

        let session = Session::new(user_id, &self.config);
        let session_id = session.id;

        // Store session
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(session_id, session.clone());
        }

        // Track user's sessions
        {
            let mut user_sessions = self.user_sessions.write().await;
            user_sessions.entry(user_id).or_default().push(session_id);
        }

        info!("Session created: {} for user {}", session_id, user_id.0);
        Ok(session)
    }

    /// Get a session by ID
    pub async fn get_session(&self, session_id: Uuid) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(&session_id).cloned()
    }

    /// Validate and touch a session
    pub async fn validate_session(&self, session_id: Uuid) -> VortexResult<Session> {
        let mut sessions = self.sessions.write().await;

        let session = sessions
            .get_mut(&session_id)
            .ok_or(VortexError::SessionInvalid)?;

        if !session.is_valid(&self.config) {
            session.state = SessionState::Expired;
            return Err(VortexError::SessionInvalid);
        }

        session.touch();
        Ok(session.clone())
    }

    /// Validate session with IP/UA binding check
    pub async fn validate_session_strict(
        &self,
        session_id: Uuid,
        source_ip: Option<&str>,
        user_agent: Option<&str>,
    ) -> VortexResult<Session> {
        let session = self.validate_session(session_id).await?;

        // IP binding check
        if self.config.bind_to_ip {
            if let (Some(session_ip), Some(request_ip)) = (&session.source_ip, source_ip) {
                if session_ip != request_ip {
                    warn!(
                        "Session {} IP mismatch: {} vs {}",
                        session_id, session_ip, request_ip
                    );
                    return Err(VortexError::SessionInvalid);
                }
            }
        }

        // User agent binding check
        if self.config.bind_to_user_agent {
            if let (Some(session_ua), Some(request_ua)) = (&session.user_agent, user_agent) {
                if session_ua != request_ua {
                    warn!("Session {} user agent mismatch", session_id);
                    return Err(VortexError::SessionInvalid);
                }
            }
        }

        Ok(session)
    }

    /// Revoke a session
    pub async fn revoke_session(&self, session_id: Uuid) -> VortexResult<()> {
        let mut sessions = self.sessions.write().await;

        if let Some(session) = sessions.get_mut(&session_id) {
            session.state = SessionState::Revoked;
            info!("Session revoked: {}", session_id);
        }

        Ok(())
    }

    /// Revoke all sessions for a user
    pub async fn revoke_user_sessions(&self, user_id: UserId) -> VortexResult<()> {
        let session_ids = {
            let user_sessions = self.user_sessions.read().await;
            user_sessions.get(&user_id).cloned().unwrap_or_default()
        };

        for session_id in session_ids {
            self.revoke_session(session_id).await?;
        }

        info!("All sessions revoked for user {}", user_id.0);
        Ok(())
    }

    /// Get all active sessions for a user
    pub async fn get_user_sessions(&self, user_id: UserId) -> Vec<Session> {
        let user_sessions = self.user_sessions.read().await;
        let session_ids = match user_sessions.get(&user_id) {
            Some(ids) => ids.clone(),
            None => return Vec::new(),
        };
        drop(user_sessions);

        let sessions = self.sessions.read().await;
        session_ids
            .iter()
            .filter_map(|id| sessions.get(id))
            .filter(|s| s.is_valid(&self.config))
            .cloned()
            .collect()
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired(&self) {
        let mut sessions = self.sessions.write().await;
        let mut user_sessions = self.user_sessions.write().await;

        let expired: Vec<Uuid> = sessions
            .iter()
            .filter(|(_, s)| !s.is_valid(&self.config))
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            if let Some(session) = sessions.remove(id) {
                if let Some(user_list) = user_sessions.get_mut(&session.user_id) {
                    user_list.retain(|s| s != id);
                }
            }
        }

        if !expired.is_empty() {
            debug!("Cleaned up {} expired sessions", expired.len());
        }
    }

    /// Get session count
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.values().filter(|s| s.is_valid(&self.config)).count()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(SessionConfig::default())
    }
}
