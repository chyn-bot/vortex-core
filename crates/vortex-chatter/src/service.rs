//! Main ChatterService API

use crate::audit_bridge::{AuditBridge, ChatterAuditEntry};
use crate::mention_parser::MentionParser;
use crate::models::*;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;
use vortex_common::{error::RecordId, Context, VortexError, VortexResult};
use vortex_orm::ConnectionPool;
use vortex_security::{audit::AuditSeverity, AuditAction, AuditEntry, AuditLog};

fn map_db_err(e: sqlx::Error) -> VortexError {
    VortexError::QueryExecution(e.to_string())
}

/// Main service for chatter operations.
pub struct ChatterService {
    pool: Arc<ConnectionPool>,
    audit: Arc<AuditLog>,
    audit_bridge: AuditBridge,
    mention_parser: MentionParser,
}

impl ChatterService {
    pub fn new(pool: Arc<ConnectionPool>, audit: Arc<AuditLog>) -> Self {
        Self {
            pool: pool.clone(),
            audit: audit.clone(),
            audit_bridge: AuditBridge::new(pool.clone(), audit.clone()),
            mention_parser: MentionParser::new(),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Message Operations
    // ─────────────────────────────────────────────────────────────────────────

    /// Post a new message/note on a record.
    pub async fn post_message(
        &self,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        body: &str,
        message_type: MessageType,
        is_internal: bool,
    ) -> VortexResult<ChatterMessage> {
        let user_id = ctx.require_user()?;
        let company_id = ctx.require_company()?;

        // Parse mentions from body
        let mentioned_users = self.mention_parser.extract_mentions(body)?;

        // Create message
        let message = ChatterMessage::create(
            &self.pool,
            ctx,
            res_model,
            res_id,
            body,
            message_type.as_str(),
            is_internal,
        )
        .await?;

        // Create mention records
        for mention_user_id in &mentioned_users {
            let _ = ChatterMention::create(&self.pool, message.id, *mention_user_id).await;
        }

        // Notify followers (unless internal)
        if !is_internal {
            self.notify_followers(ctx, res_model, res_id, &message)
                .await?;
        }

        // Notify mentioned users
        self.notify_mentions(ctx, &message, &mentioned_users).await?;

        // Audit log
        self.audit
            .log(
                AuditEntry::new(AuditAction::RecordCreated, AuditSeverity::Info)
                    .with_user(user_id)
                    .with_company(company_id)
                    .with_resource("ChatterMessage", &message.id.to_string()),
            )
            .await?;

        Ok(message)
    }

    /// Get timeline for a record (messages + optional audit entries).
    pub async fn get_timeline(
        &self,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        include_audit: bool,
        include_internal: bool,
        limit: u64,
        offset: u64,
    ) -> VortexResult<Vec<ChatterTimelineItem>> {
        let mut timeline = Vec::new();

        // Get user messages
        let messages = ChatterMessage::find_for_record(
            &self.pool,
            ctx,
            res_model,
            res_id,
            include_internal,
            limit,
            offset,
        )
        .await?;

        for msg in messages {
            timeline.push(ChatterTimelineItem::Message(msg));
        }

        // Optionally include audit entries
        if include_audit {
            let audit_entries = self
                .audit_bridge
                .get_audit_for_record(ctx, res_model, res_id, limit, offset)
                .await?;

            for entry in audit_entries {
                timeline.push(ChatterTimelineItem::AuditEntry(entry));
            }
        }

        // Sort by timestamp descending
        timeline.sort_by(|a, b| b.timestamp().cmp(&a.timestamp()));

        // Truncate to limit after merging
        timeline.truncate(limit as usize);

        Ok(timeline)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Activity Operations
    // ─────────────────────────────────────────────────────────────────────────

    /// Schedule a new activity on a record.
    pub async fn schedule_activity(
        &self,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        activity_type_id: Uuid,
        summary: Option<&str>,
        note: Option<&str>,
        due_date: NaiveDate,
        assigned_to_id: Uuid,
    ) -> VortexResult<ChatterActivity> {
        let user_id = ctx.require_user()?;
        let company_id = ctx.require_company()?;

        let activity = ChatterActivity::create(
            &self.pool,
            ctx,
            res_model,
            res_id,
            activity_type_id,
            summary,
            note,
            due_date,
            assigned_to_id,
        )
        .await?;

        // Notify assignee (if not self-assigned)
        if assigned_to_id != user_id.0 {
            ChatterNotification::create(
                &self.pool,
                assigned_to_id,
                "activity",
                None,
                Some(activity.id),
                res_model,
                res_id,
                &format!("New activity assigned: {}", summary.unwrap_or("Task")),
                note,
                company_id.0,
            )
            .await?;
        }

        Ok(activity)
    }

    /// Complete an activity.
    pub async fn complete_activity(
        &self,
        ctx: &Context,
        activity_id: Uuid,
        feedback: Option<&str>,
    ) -> VortexResult<ChatterActivity> {
        let mut activity = ChatterActivity::find(&self.pool, ctx, activity_id)
            .await?
            .ok_or_else(|| VortexError::RecordNotFound {
                model: "ChatterActivity".to_string(),
                id: RecordId::Uuid(activity_id),
            })?;

        activity.complete(&self.pool, ctx, feedback).await?;

        // Post a completion message
        self.post_message(
            ctx,
            &activity.res_model,
            activity.res_id,
            &format!(
                "Completed activity: {}",
                activity.summary.as_deref().unwrap_or("Task")
            ),
            MessageType::System,
            false,
        )
        .await?;

        Ok(activity)
    }

    /// Get activities for a record.
    pub async fn get_activities(
        &self,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        include_completed: bool,
    ) -> VortexResult<Vec<ChatterActivity>> {
        ChatterActivity::find_for_record(&self.pool, ctx, res_model, res_id, include_completed)
            .await
    }

    /// Get activities assigned to current user.
    pub async fn get_my_activities(
        &self,
        ctx: &Context,
        include_completed: bool,
    ) -> VortexResult<Vec<ChatterActivity>> {
        let user_id = ctx.require_user()?;
        ChatterActivity::find_for_user(&self.pool, ctx, user_id.0, include_completed).await
    }

    /// Get all activity types.
    pub async fn get_activity_types(&self) -> VortexResult<Vec<ChatterActivityType>> {
        ChatterActivityType::all(&self.pool).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Follower Operations
    // ─────────────────────────────────────────────────────────────────────────

    /// Add a follower to a record.
    pub async fn add_follower(
        &self,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        user_id: Uuid,
        reason: Option<&str>,
    ) -> VortexResult<ChatterFollower> {
        ChatterFollower::add(&self.pool, ctx, res_model, res_id, user_id, reason).await
    }

    /// Remove a follower from a record.
    pub async fn remove_follower(
        &self,
        _ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        user_id: Uuid,
    ) -> VortexResult<()> {
        ChatterFollower::remove(&self.pool, res_model, res_id, user_id).await
    }

    /// Toggle follow status for current user.
    pub async fn toggle_follow(
        &self,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
    ) -> VortexResult<bool> {
        let user_id = ctx.require_user()?;
        let is_following = ChatterFollower::exists(&self.pool, res_model, res_id, user_id.0).await?;

        if is_following {
            ChatterFollower::remove(&self.pool, res_model, res_id, user_id.0).await?;
            Ok(false)
        } else {
            ChatterFollower::add(&self.pool, ctx, res_model, res_id, user_id.0, Some("manual"))
                .await?;
            Ok(true)
        }
    }

    /// Get followers for a record.
    pub async fn get_followers(
        &self,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
    ) -> VortexResult<Vec<ChatterFollower>> {
        ChatterFollower::find_for_record(&self.pool, ctx, res_model, res_id).await
    }

    /// Check if current user follows a record.
    pub async fn is_following(&self, ctx: &Context, res_model: &str, res_id: Uuid) -> VortexResult<bool> {
        let user_id = ctx.require_user()?;
        ChatterFollower::exists(&self.pool, res_model, res_id, user_id.0).await
    }

    /// Count followers for a record.
    pub async fn follower_count(&self, res_model: &str, res_id: Uuid) -> VortexResult<i64> {
        ChatterFollower::count_for_record(&self.pool, res_model, res_id).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Attachment Operations
    // ─────────────────────────────────────────────────────────────────────────

    /// Attach a file to a message.
    pub async fn attach_to_message(
        &self,
        ctx: &Context,
        message_id: Uuid,
        file_name: &str,
        file_path: &str,
        file_size: i64,
        mime_type: Option<&str>,
    ) -> VortexResult<ChatterAttachment> {
        ChatterAttachment::create_for_message(
            &self.pool, ctx, message_id, file_name, file_path, file_size, mime_type,
        )
        .await
    }

    /// Attach a file directly to a record.
    pub async fn attach_to_record(
        &self,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        file_name: &str,
        file_path: &str,
        file_size: i64,
        mime_type: Option<&str>,
    ) -> VortexResult<ChatterAttachment> {
        ChatterAttachment::create_for_record(
            &self.pool, ctx, res_model, res_id, file_name, file_path, file_size, mime_type,
        )
        .await
    }

    /// Get attachments for a record.
    pub async fn get_attachments(
        &self,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
    ) -> VortexResult<Vec<ChatterAttachment>> {
        ChatterAttachment::find_for_record(&self.pool, ctx, res_model, res_id).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Notification Operations
    // ─────────────────────────────────────────────────────────────────────────

    /// Get unread notifications for current user.
    pub async fn get_unread_notifications(
        &self,
        ctx: &Context,
        limit: u64,
    ) -> VortexResult<Vec<ChatterNotification>> {
        let user_id = ctx.require_user()?;
        ChatterNotification::find_unread(&self.pool, user_id.0, limit).await
    }

    /// Get notification count for badge display.
    pub async fn get_unread_count(&self, ctx: &Context) -> VortexResult<i64> {
        let user_id = ctx.require_user()?;
        ChatterNotification::count_unread(&self.pool, user_id.0).await
    }

    /// Mark notifications as read.
    pub async fn mark_notifications_read(&self, notification_ids: &[Uuid]) -> VortexResult<()> {
        ChatterNotification::mark_read(&self.pool, notification_ids).await
    }

    /// Mark all notifications as read.
    pub async fn mark_all_read(&self, ctx: &Context) -> VortexResult<()> {
        let user_id = ctx.require_user()?;
        ChatterNotification::mark_all_read(&self.pool, user_id.0).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Field Change Tracking
    // ─────────────────────────────────────────────────────────────────────────

    /// Record field changes as a chatter message.
    pub async fn record_field_changes(
        &self,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        changes: Vec<FieldChange>,
    ) -> VortexResult<Option<ChatterMessage>> {
        if changes.is_empty() {
            return Ok(None);
        }

        let body = self.format_changes_as_html(&changes);

        let message = self
            .post_message(ctx, res_model, res_id, &body, MessageType::System, false)
            .await?;

        Ok(Some(message))
    }

    fn format_changes_as_html(&self, changes: &[FieldChange]) -> String {
        let mut lines = vec!["<ul class=\"list-disc ml-4 text-sm\">".to_string()];

        for change in changes {
            lines.push(format!(
                "<li><strong>{}</strong>: {} → {}</li>",
                change.field_label,
                change.old_value.as_deref().unwrap_or("(empty)"),
                change.new_value.as_deref().unwrap_or("(empty)")
            ));
        }

        lines.push("</ul>".to_string());
        lines.join("\n")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal Helpers
    // ─────────────────────────────────────────────────────────────────────────

    async fn notify_followers(
        &self,
        ctx: &Context,
        res_model: &str,
        res_id: Uuid,
        message: &ChatterMessage,
    ) -> VortexResult<()> {
        let followers = self.get_followers(ctx, res_model, res_id).await?;
        let author_id = message.author_id;
        let company_id = ctx.require_company()?;

        for follower in followers {
            // Don't notify the author
            if follower.user_id == author_id {
                continue;
            }

            ChatterNotification::create(
                &self.pool,
                follower.user_id,
                "message",
                Some(message.id),
                None,
                res_model,
                res_id,
                "New message",
                Some(&message.body),
                company_id.0,
            )
            .await?;
        }

        Ok(())
    }

    async fn notify_mentions(
        &self,
        ctx: &Context,
        message: &ChatterMessage,
        mentioned_user_ids: &[Uuid],
    ) -> VortexResult<()> {
        let company_id = ctx.require_company()?;

        for user_id in mentioned_user_ids {
            // Don't notify the author if they mention themselves
            if *user_id == message.author_id {
                continue;
            }

            ChatterNotification::create(
                &self.pool,
                *user_id,
                "mention",
                Some(message.id),
                None,
                &message.res_model,
                message.res_id,
                "You were mentioned",
                Some(&message.body),
                company_id.0,
            )
            .await?;
        }

        Ok(())
    }
}

/// Field change record for tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldChange {
    pub field_name: String,
    pub field_label: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Timeline item (either message or audit entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ChatterTimelineItem {
    Message(ChatterMessage),
    AuditEntry(ChatterAuditEntry),
}

impl ChatterTimelineItem {
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            Self::Message(m) => m.created_at,
            Self::AuditEntry(e) => e.timestamp,
        }
    }
}

/// Message type enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Comment,
    Note,
    Notification,
    System,
}

impl MessageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Comment => "comment",
            Self::Note => "note",
            Self::Notification => "notification",
            Self::System => "system",
        }
    }
}

/// Notification type enum.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NotificationType {
    Message,
    Mention,
    Activity,
    Follow,
}

impl NotificationType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Mention => "mention",
            Self::Activity => "activity",
            Self::Follow => "follow",
        }
    }
}
