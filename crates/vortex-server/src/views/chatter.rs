//! Chatter view handlers

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use chrono::NaiveDate;
use serde::Deserialize;
use uuid::Uuid;
use vortex_chatter::{ChatterTimelineItem, MessageType};
use vortex_common::Context;

use crate::state::AppState;

/// Build chatter API routes
pub fn chatter_routes() -> Router<AppState> {
    Router::new()
        // Timeline
        .route("/:model/:id/timeline", get(get_timeline))
        // Messages
        .route("/:model/:id/messages", post(post_message))
        // Activities
        .route("/:model/:id/activities", get(get_activities))
        .route("/:model/:id/activities", post(create_activity))
        .route("/activities/:id/complete", post(complete_activity))
        // Followers
        .route("/:model/:id/followers", get(get_followers))
        .route("/:model/:id/follow", post(toggle_follow))
        // Notifications
        .route("/notifications", get(get_notifications))
        .route("/notifications/count", get(get_notification_count))
        .route("/notifications/read", post(mark_notifications_read))
}

/// Build chatter HTMX partial routes
pub fn chatter_partials() -> Router<AppState> {
    Router::new()
        .route("/:model/:id", get(chatter_component))
        .route("/:model/:id/timeline", get(timeline_partial))
        .route("/:model/:id/activities", get(activities_partial))
}

// Request/Response types

#[derive(Deserialize)]
pub struct PostMessageRequest {
    pub body: String,
    #[serde(default)]
    pub is_internal: bool,
}

#[derive(Deserialize)]
pub struct CreateActivityRequest {
    pub activity_type_id: Uuid,
    pub summary: Option<String>,
    pub note: Option<String>,
    pub due_date: String,
    pub assigned_to_id: Uuid,
}

#[derive(Deserialize)]
pub struct TimelineQuery {
    #[serde(default = "default_true")]
    pub include_audit: bool,
    #[serde(default)]
    pub include_internal: bool,
    #[serde(default = "default_limit")]
    pub limit: u64,
    #[serde(default)]
    pub offset: u64,
}

#[derive(Deserialize)]
pub struct MarkReadRequest {
    pub ids: Vec<Uuid>,
}

fn default_true() -> bool {
    true
}
fn default_limit() -> u64 {
    50
}

// API Handlers

pub async fn get_timeline(
    State(state): State<AppState>,
    Extension(ctx): Extension<Context>,
    Path((model, id)): Path<(String, Uuid)>,
    Query(query): Query<TimelineQuery>,
) -> Response {
    match state
        .chatter
        .get_timeline(
            &ctx,
            &model,
            id,
            query.include_audit,
            query.include_internal,
            query.limit,
            query.offset,
        )
        .await
    {
        Ok(items) => Json(items).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn post_message(
    State(state): State<AppState>,
    Extension(ctx): Extension<Context>,
    Path((model, id)): Path<(String, Uuid)>,
    Json(req): Json<PostMessageRequest>,
) -> Response {
    let message_type = if req.is_internal {
        MessageType::Note
    } else {
        MessageType::Comment
    };

    match state
        .chatter
        .post_message(&ctx, &model, id, &req.body, message_type, req.is_internal)
        .await
    {
        Ok(message) => Json(message).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn get_activities(
    State(state): State<AppState>,
    Extension(ctx): Extension<Context>,
    Path((model, id)): Path<(String, Uuid)>,
) -> Response {
    match state.chatter.get_activities(&ctx, &model, id, false).await {
        Ok(activities) => Json(activities).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn create_activity(
    State(state): State<AppState>,
    Extension(ctx): Extension<Context>,
    Path((model, id)): Path<(String, Uuid)>,
    Json(req): Json<CreateActivityRequest>,
) -> Response {
    let due_date = match NaiveDate::parse_from_str(&req.due_date, "%Y-%m-%d") {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid date format. Use YYYY-MM-DD"})),
            )
                .into_response()
        }
    };

    match state
        .chatter
        .schedule_activity(
            &ctx,
            &model,
            id,
            req.activity_type_id,
            req.summary.as_deref(),
            req.note.as_deref(),
            due_date,
            req.assigned_to_id,
        )
        .await
    {
        Ok(activity) => Json(activity).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn complete_activity(
    State(state): State<AppState>,
    Extension(ctx): Extension<Context>,
    Path(id): Path<Uuid>,
) -> Response {
    match state.chatter.complete_activity(&ctx, id, None).await {
        Ok(activity) => Json(activity).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn get_followers(
    State(state): State<AppState>,
    Extension(ctx): Extension<Context>,
    Path((model, id)): Path<(String, Uuid)>,
) -> Response {
    match state.chatter.get_followers(&ctx, &model, id).await {
        Ok(followers) => Json(followers).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn toggle_follow(
    State(state): State<AppState>,
    Extension(ctx): Extension<Context>,
    Path((model, id)): Path<(String, Uuid)>,
) -> Response {
    match state.chatter.toggle_follow(&ctx, &model, id).await {
        Ok(is_following) => Json(serde_json::json!({"following": is_following})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn get_notifications(
    State(state): State<AppState>,
    Extension(ctx): Extension<Context>,
) -> Response {
    match state.chatter.get_unread_notifications(&ctx, 50).await {
        Ok(notifications) => Json(notifications).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn get_notification_count(
    State(state): State<AppState>,
    Extension(ctx): Extension<Context>,
) -> Response {
    match state.chatter.get_unread_count(&ctx).await {
        Ok(count) => Json(serde_json::json!({"count": count})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn mark_notifications_read(
    State(state): State<AppState>,
    Extension(_ctx): Extension<Context>,
    Json(req): Json<MarkReadRequest>,
) -> Response {
    match state.chatter.mark_notifications_read(&req.ids).await {
        Ok(()) => Json(serde_json::json!({"success": true})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// HTMX Partial Handlers

pub async fn chatter_component(
    State(state): State<AppState>,
    Extension(ctx): Extension<Context>,
    Path((model, id)): Path<(String, Uuid)>,
) -> Response {
    let pending_activities = state
        .chatter
        .get_activities(&ctx, &model, id, false)
        .await
        .map(|a| a.len())
        .unwrap_or(0);

    let is_following = state
        .chatter
        .is_following(&ctx, &model, id)
        .await
        .unwrap_or(false);

    let follow_icon = if is_following {
        "<svg class=\"w-4 h-4 fill-current\" viewBox=\"0 0 20 20\"><path d=\"M3.172 5.172a4 4 0 015.656 0L10 6.343l1.172-1.171a4 4 0 115.656 5.656L10 17.657l-6.828-6.829a4 4 0 010-5.656z\"/></svg>"
    } else {
        "<svg class=\"w-4 h-4\" fill=\"none\" stroke=\"currentColor\" viewBox=\"0 0 24 24\"><path stroke-linecap=\"round\" stroke-linejoin=\"round\" stroke-width=\"2\" d=\"M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z\"/></svg>"
    };

    let activity_badge = if pending_activities > 0 {
        format!("<span class=\"badge badge-primary badge-sm ml-1\">{}</span>", pending_activities)
    } else {
        String::new()
    };

    let html = format!(
        concat!(
            "<div id=\"chatter-container\" class=\"card bg-base-100 shadow\" data-model=\"{model}\" data-id=\"{id}\">",
            "<div class=\"card-body p-4\">",
            "<div class=\"flex justify-between items-center mb-4\">",
            "<h3 class=\"card-title text-base\">Chatter</h3>",
            "<button class=\"btn btn-ghost btn-sm\" hx-post=\"/api/chatter/{model}/{id}/follow\" hx-swap=\"none\">",
            "{follow_icon}",
            "</button>",
            "</div>",
            "<div class=\"tabs tabs-boxed tabs-sm mb-4\">",
            "<a class=\"tab tab-active\" hx-get=\"/partials/chatter/{model}/{id}/timeline\" hx-target=\"#chatter-content\">Messages</a>",
            "<a class=\"tab\" hx-get=\"/partials/chatter/{model}/{id}/activities\" hx-target=\"#chatter-content\">Activities{activity_badge}</a>",
            "</div>",
            "<div id=\"chatter-content\" hx-get=\"/partials/chatter/{model}/{id}/timeline\" hx-trigger=\"load\">",
            "<div class=\"flex justify-center py-4\"><span class=\"loading loading-spinner\"></span></div>",
            "</div>",
            "</div>",
            "</div>"
        ),
        model = model,
        id = id,
        follow_icon = follow_icon,
        activity_badge = activity_badge
    );

    Html(html).into_response()
}

pub async fn timeline_partial(
    State(state): State<AppState>,
    Extension(ctx): Extension<Context>,
    Path((model, id)): Path<(String, Uuid)>,
) -> Response {
    let timeline = state
        .chatter
        .get_timeline(&ctx, &model, id, true, false, 50, 0)
        .await
        .unwrap_or_default();

    let mut html = String::new();

    // Message input form
    html.push_str(&format!(
        concat!(
            "<form hx-post=\"/api/chatter/{model}/{id}/messages\" hx-target=\"#timeline-items\" hx-swap=\"afterbegin\" class=\"mb-4\">",
            "<textarea name=\"body\" class=\"textarea textarea-bordered w-full text-sm\" placeholder=\"Write a message...\" rows=\"2\" required></textarea>",
            "<div class=\"flex justify-between items-center mt-2\">",
            "<label class=\"label cursor-pointer gap-2 p-0\">",
            "<input type=\"checkbox\" name=\"is_internal\" class=\"checkbox checkbox-xs\">",
            "<span class=\"label-text text-xs\">Internal note</span>",
            "</label>",
            "<button type=\"submit\" class=\"btn btn-primary btn-sm\">Send</button>",
            "</div>",
            "</form>",
            "<div id=\"timeline-items\" class=\"space-y-3\">"
        ),
        model = model,
        id = id
    ));

    // Render timeline items
    for item in &timeline {
        match item {
            ChatterTimelineItem::Message(msg) => {
                let author_initials: String = msg.author_id.to_string().chars().take(2).collect();
                let time_ago = format_time_ago(msg.created_at);
                let internal_badge = if msg.is_internal {
                    "<span class=\"badge badge-ghost badge-xs\">Internal</span>"
                } else {
                    ""
                };

                html.push_str(&format!(
                    concat!(
                        "<div class=\"flex gap-2\">",
                        "<div class=\"avatar placeholder\">",
                        "<div class=\"bg-primary text-primary-content rounded-full w-8 h-8\">",
                        "<span class=\"text-xs\">{initials}</span>",
                        "</div>",
                        "</div>",
                        "<div class=\"flex-1\">",
                        "<div class=\"text-xs text-base-content/60 mb-1\">",
                        "<span class=\"font-medium\">User</span> · {time_ago} {internal_badge}",
                        "</div>",
                        "<div class=\"text-sm bg-base-200 rounded-lg p-2\">{body}</div>",
                        "</div>",
                        "</div>"
                    ),
                    initials = author_initials.to_uppercase(),
                    time_ago = time_ago,
                    internal_badge = internal_badge,
                    body = msg.body
                ));
            }
            ChatterTimelineItem::AuditEntry(entry) => {
                let time_ago = format_time_ago(entry.timestamp);
                if !entry.changes.is_empty() {
                    html.push_str(&format!(
                        concat!(
                            "<div class=\"flex gap-2 opacity-70\">",
                            "<div class=\"avatar placeholder\">",
                            "<div class=\"bg-base-300 rounded-full w-8 h-8\">",
                            "<span class=\"text-xs\">SYS</span>",
                            "</div>",
                            "</div>",
                            "<div class=\"flex-1\">",
                            "<div class=\"text-xs text-base-content/60 mb-1\">",
                            "<span class=\"font-medium\">System</span> · {time_ago}",
                            "</div>",
                            "<div class=\"text-xs bg-base-200 rounded-lg p-2\">",
                            "<span class=\"font-medium\">{action}</span>",
                            "<ul class=\"list-disc ml-4 mt-1\">"
                        ),
                        time_ago = time_ago,
                        action = entry.action
                    ));

                    for change in &entry.changes {
                        html.push_str(&format!(
                            "<li><strong>{}</strong>: {} -> {}</li>",
                            change.field,
                            change.old_value.as_deref().unwrap_or("(empty)"),
                            change.new_value.as_deref().unwrap_or("(empty)")
                        ));
                    }

                    html.push_str("</ul></div></div></div>");
                }
            }
        }
    }

    if timeline.is_empty() {
        html.push_str("<div class=\"text-center py-4 text-base-content/60 text-sm\">No messages yet</div>");
    }

    html.push_str("</div>");

    Html(html).into_response()
}

pub async fn activities_partial(
    State(state): State<AppState>,
    Extension(ctx): Extension<Context>,
    Path((model, id)): Path<(String, Uuid)>,
) -> Response {
    let activities = state
        .chatter
        .get_activities(&ctx, &model, id, false)
        .await
        .unwrap_or_default();

    let activity_types = state.chatter.get_activity_types().await.unwrap_or_default();

    let mut html = String::new();

    // Schedule activity button
    html.push_str(&format!(
        "<button class=\"btn btn-sm btn-outline w-full mb-4\" onclick=\"document.getElementById('activity-modal-{id}').showModal()\">+ Schedule Activity</button>",
        id = id
    ));

    // Activity list
    html.push_str("<div class=\"space-y-2\">");

    for activity in &activities {
        let overdue = activity.state == "overdue";
        let badge_class = if overdue { "badge-error" } else { "badge-info" };

        html.push_str(&format!(
            concat!(
                "<div class=\"flex items-center gap-2 p-2 bg-base-200 rounded-lg\">",
                "<div class=\"flex-1\">",
                "<div class=\"text-sm font-medium\">{summary}</div>",
                "<div class=\"text-xs text-base-content/60\">Due: {due_date}</div>",
                "</div>",
                "<span class=\"badge {badge_class} badge-sm\">{state}</span>",
                "<button class=\"btn btn-ghost btn-xs\" hx-post=\"/api/chatter/activities/{activity_id}/complete\" hx-swap=\"outerHTML\">Done</button>",
                "</div>"
            ),
            summary = activity.summary.as_deref().unwrap_or("Task"),
            due_date = activity.due_date,
            badge_class = badge_class,
            state = activity.state,
            activity_id = activity.id
        ));
    }

    if activities.is_empty() {
        html.push_str("<div class=\"text-center py-4 text-base-content/60 text-sm\">No pending activities</div>");
    }

    html.push_str("</div>");

    // Activity modal
    html.push_str(&format!(
        concat!(
            "<dialog id=\"activity-modal-{id}\" class=\"modal\">",
            "<div class=\"modal-box\">",
            "<h3 class=\"font-bold text-lg mb-4\">Schedule Activity</h3>",
            "<form hx-post=\"/api/chatter/{model}/{id}/activities\" hx-swap=\"none\">",
            "<div class=\"form-control mb-3\">",
            "<label class=\"label py-1\"><span class=\"label-text text-sm\">Type</span></label>",
            "<select name=\"activity_type_id\" class=\"select select-bordered select-sm\">"
        ),
        id = id,
        model = model
    ));

    for atype in &activity_types {
        html.push_str(&format!(
            "<option value=\"{}\">{}</option>",
            atype.id, atype.name
        ));
    }

    html.push_str(&format!(
        concat!(
            "</select>",
            "</div>",
            "<div class=\"form-control mb-3\">",
            "<label class=\"label py-1\"><span class=\"label-text text-sm\">Summary</span></label>",
            "<input type=\"text\" name=\"summary\" class=\"input input-bordered input-sm\">",
            "</div>",
            "<div class=\"form-control mb-3\">",
            "<label class=\"label py-1\"><span class=\"label-text text-sm\">Due Date</span></label>",
            "<input type=\"date\" name=\"due_date\" class=\"input input-bordered input-sm\" required>",
            "</div>",
            "<div class=\"form-control mb-3\">",
            "<label class=\"label py-1\"><span class=\"label-text text-sm\">Assign To</span></label>",
            "<input type=\"text\" name=\"assigned_to_id\" class=\"input input-bordered input-sm\" placeholder=\"User ID\" required>",
            "</div>",
            "<div class=\"modal-action\">",
            "<button type=\"button\" class=\"btn btn-sm\" onclick=\"document.getElementById('activity-modal-{id}').close()\">Cancel</button>",
            "<button type=\"submit\" class=\"btn btn-primary btn-sm\">Schedule</button>",
            "</div>",
            "</form>",
            "</div>",
            "<form method=\"dialog\" class=\"modal-backdrop\"><button>close</button></form>",
            "</dialog>"
        ),
        id = id
    ));

    Html(html).into_response()
}

fn format_time_ago(dt: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(dt);

    if duration.num_minutes() < 1 {
        "just now".to_string()
    } else if duration.num_minutes() < 60 {
        format!("{}m ago", duration.num_minutes())
    } else if duration.num_hours() < 24 {
        format!("{}h ago", duration.num_hours())
    } else if duration.num_days() < 7 {
        format!("{}d ago", duration.num_days())
    } else {
        dt.format("%d/%m/%Y").to_string()
    }
}
