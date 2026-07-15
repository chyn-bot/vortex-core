//! Status / stage bar — Vortex's analogue of Odoo's `widget="statusbar"`,
//! backed by **user-managed stages** (Odoo's `stage_id` / pipeline model).
//!
//! Stages are rows in the core `record_stages` table, keyed by `(model,
//! code)`. A record stores the stage `code` in its own status column (e.g.
//! `contacts.record_state`). Load the bar for a model with
//! [`StatusBar::from_db`], render it, and apply transitions — admins add,
//! reorder, recolour and hide stages from Settings ▸ Stages without any
//! code change.
//!
//! Odoo attribute mapping:
//! - **statusbar_visible** → each stage's `always_visible` (false = shows
//!   only while it is the current value, e.g. a `Cancelled` stage).
//! - **statusbar_colors** → each stage's `color` ([`StageColor`]).
//! - **clickable** → [`StatusBar::clickable`] (on by default for DB-loaded
//!   bars); each non-current stage becomes a POST transition.
//!
//! ```ignore
//! let bar = StatusBar::from_db(&db, "contacts", "contacts", "record_state").await;
//! let html = bar.render(&record_state, &format!("/contacts/{id}/status"));
//! // POST /contacts/{id}/status/{state}:
//! bar.apply(&db, &state.audit, &db_ctx.db_name,
//!           user.id, &user.username, "contact", id, &name, &new_state).await?;
//! ```

use sqlx::{PgPool, Row};
use uuid::Uuid;
use vortex_common::UserId;
use vortex_security::{AuditAction, AuditEntry, AuditLog, AuditSeverity};

use crate::ui::html_escape;

/// DaisyUI semantic colour for a stage when it is the active one.
#[derive(Clone, Copy, PartialEq)]
pub enum StageColor {
    Neutral,
    Primary,
    Info,
    Success,
    Warning,
    Error,
}

impl StageColor {
    /// The DaisyUI suffix (`btn-info`, `badge-success`, …).
    pub fn suffix(self) -> &'static str {
        match self {
            StageColor::Neutral => "neutral",
            StageColor::Primary => "primary",
            StageColor::Info => "info",
            StageColor::Success => "success",
            StageColor::Warning => "warning",
            StageColor::Error => "error",
        }
    }

    /// Parse a stored colour string; unknown values fall back to neutral.
    pub fn parse(s: &str) -> Self {
        match s {
            "primary" => StageColor::Primary,
            "info" => StageColor::Info,
            "success" => StageColor::Success,
            "warning" => StageColor::Warning,
            "error" => StageColor::Error,
            _ => StageColor::Neutral,
        }
    }

    /// The full set, for settings-UI colour pickers.
    pub const ALL: [StageColor; 6] = [
        StageColor::Neutral,
        StageColor::Primary,
        StageColor::Info,
        StageColor::Success,
        StageColor::Warning,
        StageColor::Error,
    ];
}

/// One stage in the bar.
pub struct Stage {
    pub value: String,
    pub label: String,
    pub color: StageColor,
    /// `true` => always rendered; `false` => only while it is the current
    /// value (Odoo `statusbar_visible` exclusion).
    pub always_visible: bool,
    /// When the record is in this stage, its fields are read-only. Multiple
    /// stages may be locked (e.g. pending + completed).
    pub locked: bool,
}

/// Restrict a colour string to known DaisyUI button colours so it can be
/// safely interpolated into a class name.
fn sanitize_color(c: &str) -> &str {
    match c {
        "neutral" | "primary" | "secondary" | "accent" | "info" | "success" | "warning"
        | "error" | "ghost" => c,
        _ => "primary",
    }
}

/// A role-gated transition button (Odoo `<button states= groups=>`). Moves a
/// record from `from_stage` (None = any) to `target_stage`, shown only to
/// users holding `required_role` (None = anyone).
pub struct StageAction {
    pub id: Option<Uuid>,
    pub label: String,
    pub target_stage: String,
    pub from_stage: Option<String>,
    pub required_role: Option<String>,
    pub color: String,
}

/// The transition buttons declared for a model.
pub struct StageActions {
    actions: Vec<StageAction>,
}

impl StageActions {
    /// Load a model's active transition buttons, ordered by sequence.
    pub async fn from_db(db: &PgPool, model: &str) -> Self {
        let rows = sqlx::query(
            "SELECT id, label, target_stage, from_stage, required_role, color \
             FROM record_stage_actions WHERE model = $1 AND active = true \
             ORDER BY sequence, label",
        )
        .bind(model)
        .fetch_all(db)
        .await
        .unwrap_or_default();
        let mut actions = Vec::new();
        for r in &rows {
            actions.push(StageAction {
                id: r.try_get("id").ok(),
                label: r.get("label"),
                target_stage: r.get("target_stage"),
                from_stage: r
                    .try_get::<Option<String>, _>("from_stage")
                    .ok()
                    .flatten()
                    .filter(|s| !s.is_empty()),
                required_role: r
                    .try_get::<Option<String>, _>("required_role")
                    .ok()
                    .flatten()
                    .filter(|s| !s.is_empty()),
                color: r.get("color"),
            });
        }
        Self { actions }
    }

    fn visible(&self, current: &str, user_roles: &[String]) -> Vec<&StageAction> {
        self.actions
            .iter()
            .filter(|a| {
                a.from_stage.as_deref().map_or(true, |f| f == current)
                    && a.target_stage != current
                    && a
                        .required_role
                        .as_deref()
                        .map_or(true, |role| user_roles.iter().any(|ur| ur == role))
            })
            .collect()
    }

    /// Server-side gate: may this user move `current` → `target`? Mirrors
    /// exactly what [`StageActions::render`] would show, so a hand-crafted
    /// POST can't bypass the buttons.
    pub fn can_transition(&self, current: &str, target: &str, user_roles: &[String]) -> bool {
        self.visible(current, user_roles)
            .iter()
            .any(|a| a.target_stage == target)
    }

    /// The specific button a user would press to move `current` → `target`
    /// (the one [`StageActions::render`] shows). `None` if they can't, which
    /// makes this both the lookup for an action's approval rules *and* the
    /// gate — callers that get `Some` are authorized.
    pub fn action_for(&self, current: &str, target: &str, user_roles: &[String]) -> Option<&StageAction> {
        self.visible(current, user_roles)
            .into_iter()
            .find(|a| a.target_stage == target)
    }

    /// Render the buttons this user may use from `current`. Each is a POST to
    /// `{change_base}/{target}`. Empty string if none apply.
    pub fn render(&self, current: &str, user_roles: &[String], change_base: &str) -> String {
        let btns: Vec<String> = self
            .visible(current, user_roles)
            .iter()
            .map(|a| {
                format!(
                    r#"<form method="POST" action="{base}/{target}" class="inline"><button type="submit" class="btn btn-sm btn-{color}">{label}</button></form>"#,
                    base = change_base,
                    target = html_escape(&a.target_stage),
                    color = sanitize_color(&a.color),
                    label = html_escape(&a.label),
                )
            })
            .collect();
        if btns.is_empty() {
            return String::new();
        }
        format!(r#"<div class="flex flex-wrap items-center gap-2">{}</div>"#, btns.join(""))
    }
}

/// A model's status bar — its stages plus where the value is stored.
pub struct StatusBar {
    table: String,
    column: String,
    stages: Vec<Stage>,
    clickable: bool,
}

fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl StatusBar {
    /// Empty bar writing to `table.column`. Prefer [`StatusBar::from_db`].
    pub fn new(table: &str, column: &str) -> Self {
        Self { table: table.to_string(), column: column.to_string(), stages: Vec::new(), clickable: false }
    }

    /// Load the active stages for `model` from `record_stages`, ordered by
    /// sequence. `table`/`column` say where the value is persisted. The bar
    /// is display-only (transitions go through [`StageActions`] buttons).
    pub async fn from_db(db: &PgPool, model: &str, table: &str, column: &str) -> Self {
        let mut bar = Self::new(table, column);
        let rows = sqlx::query(
            "SELECT code, label, color, always_visible, locked \
             FROM record_stages WHERE model = $1 AND active = true \
             ORDER BY sequence, label",
        )
        .bind(model)
        .fetch_all(db)
        .await
        .unwrap_or_default();
        for r in &rows {
            bar.stages.push(Stage {
                value: r.get::<String, _>("code"),
                label: r.get::<String, _>("label"),
                color: StageColor::parse(&r.get::<String, _>("color")),
                always_visible: r.get::<bool, _>("always_visible"),
                locked: r.get::<bool, _>("locked"),
            });
        }
        bar
    }

    /// Add an always-visible stage (mainly for code-defined/test bars).
    pub fn stage(mut self, value: &str, label: &str, color: StageColor) -> Self {
        self.stages.push(Stage {
            value: value.into(),
            label: label.into(),
            color,
            always_visible: true,
            locked: false,
        });
        self
    }

    /// Is the given current value a locked stage (fields read-only)?
    pub fn is_locked(&self, current: &str) -> bool {
        self.stages.iter().any(|s| s.value == current && s.locked)
    }

    /// Allow users to click a stage to transition to it.
    pub fn clickable(mut self) -> Self {
        self.clickable = true;
        self
    }

    /// Is `value` one of the loaded stages?
    pub fn is_valid(&self, value: &str) -> bool {
        self.stages.iter().any(|s| s.value == value)
    }

    /// Does this model have any stages defined? Lets a caller skip rendering an
    /// empty bar for a model that hasn't configured a workflow.
    pub fn has_stages(&self) -> bool {
        !self.stages.is_empty()
    }

    fn label_of(&self, value: &str) -> String {
        self.stages
            .iter()
            .find(|s| s.value == value)
            .map(|s| s.label.clone())
            .unwrap_or_else(|| value.to_string())
    }

    /// Render the bar for `current`. Clickable stages POST to
    /// `{change_base}/{value}`. Server-rendered, no inline scripts.
    pub fn render(&self, current: &str, change_base: &str) -> String {
        let mut segments: Vec<String> = Vec::new();
        let mut current_shown = false;
        for s in &self.stages {
            let is_current = s.value == current;
            if is_current {
                current_shown = true;
            }
            if !s.always_visible && !is_current {
                continue; // statusbar_visible exclusion
            }
            let label = html_escape(&s.label);
            if is_current {
                segments.push(format!(
                    r#"<span class="btn btn-sm btn-{color} no-animation cursor-default">{label}</span>"#,
                    color = s.color.suffix(),
                    label = label,
                ));
            } else if self.clickable {
                segments.push(format!(
                    r#"<form method="POST" action="{base}/{value}" class="inline"><button type="submit" class="btn btn-sm btn-ghost border border-base-300 hover:btn-{color}">{label}</button></form>"#,
                    base = change_base,
                    value = html_escape(&s.value),
                    color = s.color.suffix(),
                    label = label,
                ));
            } else {
                segments.push(format!(
                    r#"<span class="btn btn-sm btn-ghost no-animation opacity-60">{label}</span>"#,
                    label = label,
                ));
            }
        }
        // If the record's current value isn't among the (active) stages —
        // e.g. the stage was archived — still surface it so the bar reflects
        // reality rather than silently dropping the state.
        if !current_shown && !current.is_empty() {
            segments.insert(
                0,
                format!(
                    r#"<span class="btn btn-sm btn-ghost no-animation border border-warning text-warning cursor-default">{}</span>"#,
                    html_escape(current)
                ),
            );
        }
        if segments.is_empty() {
            return String::new();
        }
        let joined = segments.join(r#"<span class="text-base-content/30 mx-0.5">›</span>"#);
        format!(r#"<div class="flex flex-wrap items-center gap-1 mb-4">{joined}</div>"#)
    }

    /// Validate and apply a transition: update the status column and post a
    /// tenant-scoped audit entry rendered as a `Status` change in the
    /// per-record history trail. `Err` for an unknown target stage.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply(
        &self,
        db: &PgPool,
        audit: &AuditLog,
        db_name: &str,
        user_id: Uuid,
        username: &str,
        resource_type: &str,
        resource_id: Uuid,
        resource_name: &str,
        new_state: &str,
    ) -> Result<(), String> {
        if !self.is_valid(new_state) {
            return Err(format!("Unknown status '{new_state}'"));
        }
        if !is_ident(&self.table) || !is_ident(&self.column) {
            return Err("Invalid status configuration".to_string());
        }

        let read_sql = format!("SELECT {} FROM {} WHERE id = $1", self.column, self.table);
        let old_state: String = sqlx::query_scalar(&read_sql)
            .bind(resource_id)
            .fetch_optional(db)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        if old_state == new_state {
            return Ok(()); // no-op
        }

        let upd_sql = format!("UPDATE {} SET {} = $1 WHERE id = $2", self.table, self.column);
        sqlx::query(&upd_sql)
            .bind(new_state)
            .bind(resource_id)
            .execute(db)
            .await
            .map_err(|e| format!("Could not change status: {e}"))?;

        let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
            .with_user(UserId(user_id))
            .with_username(username)
            .with_database(db_name)
            .with_resource(resource_type, resource_id.to_string())
            .with_resource_name(resource_name)
            .with_details(serde_json::json!({
                "changes": [{
                    "field": "Status",
                    "from": self.label_of(&old_state),
                    "to": self.label_of(new_state),
                }]
            }));
        if let Err(e) = audit.log(entry).await {
            tracing::error!(error = %e, "status-change audit write failed");
        }
        Ok(())
    }
}
