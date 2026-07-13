//! Saveable analytic views (Initiative #4 tail).
//!
//! The generic analytic views — pivot, graph, kanban, calendar — are driven
//! entirely by URL query params (`?rows=...&cols=...&measure=...&agg=...`). That
//! makes them powerful but ephemeral: an operator rebuilds the same breakdown by
//! hand every visit. A [`SavedView`] persists one such configuration as a **user
//! record** — owned by its author, optionally shared with the tenant, optionally
//! the shared *default* for that `(model, view_type)`.
//!
//! This is the same ownership shape as `user_reports` and `dashboards`, and it
//! replaces the `ir_ui_view` / `ir_ui_view_kanban` / `ir_ui_view_graph` tables
//! the kanban/graph handlers used to join — which no migration ever created, so
//! those joins silently returned nothing.
//!
//! ## Safety
//!
//! A config bag is a small map of query-param keys to values. On save, every key
//! is checked against a per-view-type allow-list, every value that names a field
//! is validated against the model registry (`ir_model_field`), and enum values
//! (`agg`, graph `type`) are checked against their own allow-lists. So a stored
//! view can only ever reconstruct a URL over real, registered columns — the view
//! handlers that consume it re-validate too, giving defence in depth.

use std::collections::BTreeMap;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::ui::html_escape;

/// The analytic view types a config can be saved for, as `(code, label)`.
pub const VIEW_TYPES: &[(&str, &str)] = &[
    ("pivot", "Pivot"),
    ("graph", "Graph"),
    ("kanban", "Kanban"),
    ("calendar", "Calendar"),
];

/// Graph shapes offered to a saved graph view, as `(code, label)`.
pub const GRAPH_TYPES: &[(&str, &str)] = &[
    ("bar", "Column"),
    ("hbar", "Bar"),
    ("line", "Line"),
    ("area", "Area"),
    ("pie", "Pie"),
    ("doughnut", "Donut"),
    ("stacked", "Stacked"),
    ("stackedarea", "Stacked area"),
];

/// Aggregate functions a pivot measure may use.
const AGGREGATES: &[&str] = &["count", "sum", "avg", "min", "max"];

/// A field-list config key holds one or more comma-separated field names.
/// A plain field key holds exactly one. Enum keys hold an allow-listed token.
enum KeyKind {
    /// Comma-separated list of field names (e.g. pivot `rows`).
    FieldList,
    /// A single field name (`measure` may also be the literal `id`).
    Field,
    /// One of a fixed set of tokens.
    Enum(&'static [&'static str]),
    /// Pivot `vals`: comma-separated `agg.field` measures. Each token's aggregate
    /// must be allow-listed and its field must be `id` or a registered column.
    Measures,
    /// Pivot `filters`: comma-separated `field.b64value` conditions. The field
    /// must be registered; the value is base64url-encoded opaque data (checked for
    /// charset and length only — it never reaches SQL unparameterised).
    Filters,
    /// Opaque persisted UI state (pivot `collapsed`): a bounded string over a
    /// URL-safe charset. Stored and re-emitted verbatim, never used in SQL.
    Opaque,
}

fn graph_type_codes() -> Vec<&'static str> {
    GRAPH_TYPES.iter().map(|(c, _)| *c).collect()
}

/// The keys a given view type may persist, and how each is validated.
fn allowed_keys(view_type: &str) -> Vec<(&'static str, KeyKind)> {
    static GRAPH_TYPE_CODES: &[&str] = &["bar", "hbar", "line", "area", "pie", "doughnut", "stacked", "stackedarea"];
    match view_type {
        "pivot" => vec![
            ("rows", KeyKind::FieldList),
            ("cols", KeyKind::FieldList),
            ("measure", KeyKind::Field),
            ("agg", KeyKind::Enum(AGGREGATES)),
            ("vals", KeyKind::Measures),
            // `mx` is the client-authoritative full measure list (aggregate +
            // calc-field + calculated measures + show-as), base64-JSON. The data
            // endpoint reads its SQL measures from `vals`; `mx` only needs to be
            // stored and replayed to the client verbatim.
            ("mx", KeyKind::Opaque),
            ("filters", KeyKind::Filters),
            ("collapsed", KeyKind::Opaque),
            // Display-only: reverse the column order (newest period first).
            ("coldesc", KeyKind::Enum(&["1"])),
        ],
        "graph" => vec![
            // X-axis dimension (accepts `field:gran` for date bucketing); single.
            ("group_by", KeyKind::FieldList),
            // Optional breakdown dimension → one series per distinct value.
            ("series", KeyKind::FieldList),
            ("vals", KeyKind::Measures),
            ("filters", KeyKind::Filters),
            ("type", KeyKind::Enum(GRAPH_TYPE_CODES)),
        ],
        "kanban" => vec![
            ("group_by", KeyKind::Field),
            // Fields to show on each card, in order.
            ("cards", KeyKind::FieldList),
            // Optional per-column total: aggregate of a numeric field.
            ("measure", KeyKind::Field),
            ("agg", KeyKind::Enum(AGGREGATES)),
            // Whether drag-to-change-stage is enabled ("1") or off ("0").
            ("drag", KeyKind::Enum(&["0", "1"])),
        ],
        "calendar" => vec![
            // The date/datetime field that positions an event (its start).
            ("date_field", KeyKind::Field),
            // Optional end date/datetime field → events span a range.
            ("end_field", KeyKind::Field),
            // Field used as the event label on each chip.
            ("title_field", KeyKind::Field),
            // Optional field whose distinct values color-code events + a legend.
            ("color_field", KeyKind::Field),
            // Display mode: month grid, week columns, or single-day agenda.
            ("mode", KeyKind::Enum(&["month", "week", "day"])),
        ],
        _ => vec![],
    }
}

fn valid_view_type(t: &str) -> bool {
    VIEW_TYPES.iter().any(|(c, _)| *c == t)
}

/// A SQL-identifier-shaped token: what a field name may look like.
fn ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A character allowed in a base64url payload (RFC 4648 §5, `=` padding kept).
fn is_base64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '='
}

#[derive(Debug, Clone)]
pub struct SavedView {
    pub id: Uuid,
    pub model_name: String,
    pub view_type: String,
    pub name: String,
    /// Ordered so a reconstructed query string is stable.
    pub config: BTreeMap<String, String>,
    pub owner_id: Option<Uuid>,
    pub is_shared: bool,
    pub is_default: bool,
}

impl SavedView {
    /// Owner, shared, or admin may see it.
    pub fn can_view(&self, user_id: Uuid, is_admin: bool) -> bool {
        self.is_shared || is_admin || self.owner_id == Some(user_id)
    }
    /// Owner or admin may edit/delete it.
    pub fn can_edit(&self, user_id: Uuid, is_admin: bool) -> bool {
        is_admin || self.owner_id == Some(user_id)
    }

    /// Reconstruct the `k=v&...` query string this view loads (percent-light:
    /// keys and values are field names / enums / csv, all URL-safe chars).
    pub fn query_string(&self) -> String {
        self.config
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    }
}

// ── Registry lookups ─────────────────────────────────────────────────────────

async fn model_exists(db: &PgPool, model: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM ir_model WHERE name = $1 AND is_active = true",
    )
    .bind(model)
    .fetch_one(db)
    .await
    .map(|n| n > 0)
    .unwrap_or(false)
}

/// The set of registered field names for a model.
async fn field_names(db: &PgPool, model: &str) -> std::collections::HashSet<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT f.name FROM ir_model_field f JOIN ir_model m ON m.id = f.model_id \
         WHERE m.name = $1",
    )
    .bind(model)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect()
}

// ── Validation ───────────────────────────────────────────────────────────────

/// Validate a raw config bag for `(model, view_type)` against the registry.
/// Returns the cleaned, ordered config (unknown/empty keys dropped) or an error
/// message suitable for showing the user.
pub async fn validate_config(
    db: &PgPool,
    model: &str,
    view_type: &str,
    raw: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    if !valid_view_type(view_type) {
        return Err(format!("Unknown view type {view_type:?}."));
    }
    if !model_exists(db, model).await {
        return Err(format!("Unknown model {model:?}."));
    }
    let fields = field_names(db, model).await;
    let is_field = |name: &str| ident(name) && fields.contains(name);

    let mut out = BTreeMap::new();
    for (key, kind) in allowed_keys(view_type) {
        let Some(val) = raw.get(key).map(|s| s.trim()).filter(|s| !s.is_empty()) else {
            continue;
        };
        match kind {
            KeyKind::FieldList => {
                // A token is a field name, or (for a pivot date dimension) a
                // field name plus a grouping granularity: `order_date:month`.
                for token in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let (name, gran) = token.split_once(':').unwrap_or((token, ""));
                    if !is_field(name) {
                        return Err(format!("{name:?} is not a field of {model}."));
                    }
                    if !gran.is_empty()
                        && !["day", "week", "month", "quarter", "year"].contains(&gran)
                    {
                        return Err(format!("Invalid date grouping {gran:?}."));
                    }
                }
            }
            KeyKind::Field => {
                // `measure` may be the literal `id` (count-of-rows sentinel).
                if val != "id" && !is_field(val) {
                    return Err(format!("{val:?} is not a field of {model}."));
                }
            }
            KeyKind::Enum(allowed) => {
                if !allowed.contains(&val) {
                    return Err(format!("Invalid value {val:?} for {key}."));
                }
            }
            KeyKind::Measures => {
                for token in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let (agg, field) = token.split_once('.').unwrap_or((token, "id"));
                    if !AGGREGATES.contains(&agg) {
                        return Err(format!("Invalid aggregate {agg:?} in {key}."));
                    }
                    // A calculated field is `agg.=<base64url(expression)>`; the
                    // expression is compiled/validated server-side at query time, so
                    // here we only shape-check the base64 payload.
                    if let Some(b64) = field.strip_prefix('=') {
                        if b64.is_empty() || b64.len() > 800 || !b64.chars().all(is_base64url) {
                            return Err(format!("Malformed calculated field in {key}."));
                        }
                    } else if field != "id" && !is_field(field) {
                        return Err(format!("{field:?} is not a field of {model}."));
                    }
                }
            }
            KeyKind::Filters => {
                if val.len() > 4000 {
                    return Err("Filter is too long.".into());
                }
                for token in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let Some((field, b64)) = token.split_once('.') else {
                        return Err(format!("Malformed filter {token:?}."));
                    };
                    if !is_field(field) {
                        return Err(format!("{field:?} is not a field of {model}."));
                    }
                    if b64.is_empty() || !b64.chars().all(is_base64url) {
                        return Err(format!("Malformed filter value for {field}."));
                    }
                }
            }
            KeyKind::Opaque => {
                if val.len() > 4000 {
                    return Err(format!("{key} state is too long."));
                }
                if !val.chars().all(|c| is_base64url(c) || c == ',') {
                    return Err(format!("Malformed {key} state."));
                }
            }
        }
        out.insert(key.to_string(), val.to_string());
    }
    Ok(out)
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

fn row_to_view(r: sqlx::postgres::PgRow) -> SavedView {
    let config: serde_json::Value = r.try_get("config").unwrap_or(serde_json::Value::Null);
    let config = config
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    SavedView {
        id: r.get("id"),
        model_name: r.get("model_name"),
        view_type: r.get("view_type"),
        name: r.get("name"),
        config,
        owner_id: r.try_get("owner_id").ok().flatten(),
        is_shared: r.get("is_shared"),
        is_default: r.get("is_default"),
    }
}

const SELECT_COLS: &str =
    "id, model_name, view_type, name, config, owner_id, is_shared, is_default";

/// Saved views for `(model, view_type)` a user may see: their own plus shared
/// (admins see all). Default first, then by name.
pub async fn list_for(
    db: &PgPool,
    model: &str,
    view_type: &str,
    user_id: Uuid,
    is_admin: bool,
) -> Vec<SavedView> {
    let sql = format!(
        "SELECT {SELECT_COLS} FROM saved_view \
         WHERE model_name = $1 AND view_type = $2 AND ($3 OR is_shared OR owner_id = $4) \
         ORDER BY is_default DESC, sequence, name"
    );
    sqlx::query(&sql)
        .bind(model)
        .bind(view_type)
        .bind(is_admin)
        .bind(user_id)
        .fetch_all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(row_to_view)
        .collect()
}

pub async fn load(db: &PgPool, id: Uuid) -> Option<SavedView> {
    let sql = format!("SELECT {SELECT_COLS} FROM saved_view WHERE id = $1");
    sqlx::query(&sql)
        .bind(id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(row_to_view)
}

/// The shared default config for `(model, view_type)`, if one is set. Used by the
/// view handlers to seed sensible defaults in place of the old `ir_ui_view` join.
pub async fn default_config_for(
    db: &PgPool,
    model: &str,
    view_type: &str,
) -> Option<BTreeMap<String, String>> {
    let sql = format!(
        "SELECT {SELECT_COLS} FROM saved_view \
         WHERE model_name = $1 AND view_type = $2 AND is_default = true LIMIT 1"
    );
    sqlx::query(&sql)
        .bind(model)
        .bind(view_type)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(row_to_view)
        .map(|v| v.config)
}

/// Validate and persist a saved view. `is_default` is honoured only when
/// `is_shared` (a private default makes no sense); setting it clears any prior
/// default for the same `(model, view_type)`.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    db: &PgPool,
    model: &str,
    view_type: &str,
    name: &str,
    raw_config: &BTreeMap<String, String>,
    owner_id: Uuid,
    is_shared: bool,
    is_default: bool,
) -> Result<Uuid, String> {
    if name.trim().is_empty() {
        return Err("A view needs a name.".into());
    }
    let config = validate_config(db, model, view_type, raw_config).await?;
    if config.is_empty() {
        return Err("Nothing to save — configure the view first.".into());
    }
    let is_default = is_default && is_shared;
    let config_json = serde_json::to_value(&config).unwrap_or(serde_json::json!({}));

    let mut tx = db.begin().await.map_err(|e| format!("save failed: {e}"))?;
    if is_default {
        // Enforce the single-default invariant defensively (the partial unique
        // index also guards it).
        sqlx::query(
            "UPDATE saved_view SET is_default = false \
             WHERE model_name = $1 AND view_type = $2 AND is_default = true",
        )
        .bind(model)
        .bind(view_type)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("save failed: {e}"))?;
    }
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO saved_view (model_name, view_type, name, config, owner_id, is_shared, is_default) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(model)
    .bind(view_type)
    .bind(name.trim())
    .bind(config_json)
    .bind(owner_id)
    .bind(is_shared)
    .bind(is_default)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("save failed: {e}"))?;
    tx.commit().await.map_err(|e| format!("save failed: {e}"))?;
    Ok(id)
}

pub async fn delete(db: &PgPool, id: Uuid) -> Result<(), String> {
    sqlx::query("DELETE FROM saved_view WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(|e| format!("delete failed: {e}"))?;
    Ok(())
}

// ── Rendering ────────────────────────────────────────────────────────────────

/// The base path a saved view of `view_type` loads against (`/pivot/{model}` …).
fn view_base(view_type: &str, model: &str) -> String {
    format!("/{view_type}/{model}")
}

/// Render the "Saved views ▾" toolbar control for a view: a dropdown of the
/// visible saved views (each loads its config), a delete affordance for editable
/// ones, and an inline "Save current view" form capturing `current_config`.
///
/// `current_config` is the *already-validated* set of query params in effect on
/// the page right now (so "Save" persists exactly what the user is looking at).
pub async fn render_view_bar(
    db: &PgPool,
    model: &str,
    view_type: &str,
    current_config: &BTreeMap<String, String>,
    user_id: Uuid,
    is_admin: bool,
) -> String {
    let views = list_for(db, model, view_type, user_id, is_admin).await;
    let base = view_base(view_type, model);

    // Saved-view links.
    let mut items = String::new();
    if views.is_empty() {
        items.push_str(r#"<li class="menu-title text-xs opacity-60">No saved views yet</li>"#);
    }
    for v in &views {
        let qs = v.query_string();
        let href = if qs.is_empty() { base.clone() } else { format!("{base}?{qs}") };
        let star = if v.is_default { "★ " } else { "" };
        let scope = if v.is_shared { "shared" } else { "mine" };
        let del = if v.can_edit(user_id, is_admin) {
            format!(
                r#"<form method="post" action="/views/{id}/delete" class="inline" onsubmit="return confirm('Delete this saved view?');">
<input type="hidden" name="redirect" value="{redir}"/>
<button class="btn btn-ghost btn-xs text-error" title="Delete">✕</button></form>"#,
                id = v.id,
                redir = html_escape(&base),
            )
        } else {
            String::new()
        };
        items.push_str(&format!(
            r#"<li><div class="flex items-center justify-between gap-2">
<a href="{href}" class="flex-1">{star}{name} <span class="opacity-50 text-xs">({scope})</span></a>{del}</div></li>"#,
            href = html_escape(&href),
            star = star,
            name = html_escape(&v.name),
            scope = scope,
            del = del,
        ));
    }

    // Hidden config inputs for the save form (persist what's on screen now).
    let mut cfg_inputs = String::new();
    for (k, val) in current_config {
        cfg_inputs.push_str(&format!(
            r#"<input type="hidden" name="cfg_{k}" value="{v}"/>"#,
            k = html_escape(k),
            v = html_escape(val),
        ));
    }
    let has_config = !current_config.is_empty();
    let save_form = if has_config {
        format!(
            r#"<li><div class="p-2">
<form method="post" action="/views/save" class="flex flex-col gap-2">
<input type="hidden" name="model" value="{model}"/>
<input type="hidden" name="view_type" value="{vt}"/>
<input type="hidden" name="redirect" value="{redir}"/>
{cfg}
<input name="name" required placeholder="Name this view" class="input input-bordered input-xs"/>
<label class="label cursor-pointer justify-start gap-2 py-0"><input type="checkbox" name="is_shared" value="1" class="checkbox checkbox-xs"/><span class="label-text text-xs">Share with team</span></label>
<label class="label cursor-pointer justify-start gap-2 py-0"><input type="checkbox" name="is_default" value="1" class="checkbox checkbox-xs"/><span class="label-text text-xs">Team default</span></label>
<button class="btn btn-primary btn-xs">Save current view</button>
</form></div></li>"#,
            model = html_escape(model),
            vt = html_escape(view_type),
            redir = html_escape(&view_base(view_type, model)),
            cfg = cfg_inputs,
        )
    } else {
        r#"<li class="menu-title text-xs opacity-60">Configure the view, then save it</li>"#
            .to_string()
    };

    format!(
        r#"<div class="dropdown dropdown-end">
<button tabindex="0" class="btn btn-sm gap-1" title="Saved views">
<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 5a2 2 0 012-2h10a2 2 0 012 2v16l-7-3.5L5 21V5z"/></svg>
Saved views</button>
<ul tabindex="0" class="dropdown-content menu z-[60] p-2 shadow bg-base-100 rounded-box w-72 border border-base-300">
{items}
<div class="divider my-1"></div>
{save_form}
</ul></div>"#,
        items = items,
        save_form = save_form,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn allowlists_and_view_types() {
        assert!(valid_view_type("pivot"));
        assert!(valid_view_type("calendar"));
        assert!(!valid_view_type("spreadsheet"));
        assert!(ident("contact_type"));
        assert!(!ident("a; DROP TABLE x"));
        assert!(!ident(""));
        assert_eq!(graph_type_codes(), vec!["bar", "hbar", "line", "area", "pie", "doughnut", "stacked", "stackedarea"]);
    }

    #[test]
    fn query_string_is_stable_and_ordered() {
        let v = SavedView {
            id: Uuid::new_v4(),
            model_name: "contacts".into(),
            view_type: "pivot".into(),
            name: "By type".into(),
            // BTreeMap keeps keys sorted → deterministic query string.
            config: cfg(&[("measure", "id"), ("agg", "count"), ("rows", "contact_type")]),
            owner_id: None,
            is_shared: true,
            is_default: false,
        };
        assert_eq!(v.query_string(), "agg=count&measure=id&rows=contact_type");
    }

    #[test]
    fn permissions() {
        let owner = Uuid::new_v4();
        let other = Uuid::new_v4();
        let v = SavedView {
            id: Uuid::new_v4(),
            model_name: "contacts".into(),
            view_type: "graph".into(),
            name: "V".into(),
            config: cfg(&[("group_by", "contact_type")]),
            owner_id: Some(owner),
            is_shared: false,
            is_default: false,
        };
        assert!(v.can_view(owner, false));
        assert!(!v.can_view(other, false), "private, not owner");
        assert!(v.can_view(other, true), "admin sees all");
        assert!(!v.can_edit(other, false));
        assert!(v.can_edit(owner, false));
        let shared = SavedView { is_shared: true, ..v.clone() };
        assert!(shared.can_view(other, false), "shared is visible");
        assert!(!shared.can_edit(other, false), "but not editable by non-owner");
    }

    #[test]
    fn allowed_keys_per_type() {
        let keys = |t: &str| allowed_keys(t).into_iter().map(|(k, _)| k).collect::<Vec<_>>();
        assert_eq!(keys("pivot"), vec!["rows", "cols", "measure", "agg", "vals", "mx", "filters", "collapsed", "coldesc"]);
        assert_eq!(keys("graph"), vec!["group_by", "series", "vals", "filters", "type"]);
        assert_eq!(keys("kanban"), vec!["group_by", "cards", "measure", "agg", "drag"]);
        assert_eq!(keys("calendar"), vec!["date_field", "end_field", "title_field", "color_field", "mode"]);
        assert!(keys("bogus").is_empty());
    }

    /// Full validate/create/load loop against a real migrated DB. Runs only when
    /// `VORTEX_TEST_DB` is set; otherwise skips.
    #[tokio::test]
    async fn saved_view_roundtrip_against_db() {
        let Ok(url) = std::env::var("VORTEX_TEST_DB") else {
            eprintln!("skip saved_view_roundtrip_against_db: VORTEX_TEST_DB unset");
            return;
        };
        let db = PgPool::connect(&url).await.expect("connect");
        // owner_id is a real FK to users(id); use a seeded user.
        let owner: Uuid = sqlx::query_scalar("SELECT id FROM users LIMIT 1")
            .fetch_one(&db)
            .await
            .expect("a seeded user");

        // A registered field is accepted; an unknown one is rejected.
        let good = validate_config(&db, "contacts", "graph", &cfg(&[("group_by", "contact_type"), ("type", "pie")]))
            .await
            .expect("valid config");
        assert_eq!(good.get("type").map(String::as_str), Some("pie"));
        assert!(validate_config(&db, "contacts", "graph", &cfg(&[("group_by", "nope_field")]))
            .await
            .is_err());
        // Enum values are checked.
        assert!(validate_config(&db, "contacts", "graph", &cfg(&[("group_by", "contact_type"), ("type", "sankey")]))
            .await
            .is_err());

        let id = create(&db, "contacts", "graph", "By type", &cfg(&[("group_by", "contact_type"), ("type", "pie")]), owner, true, true)
            .await
            .expect("create");
        let loaded = load(&db, id).await.expect("load");
        assert_eq!(loaded.name, "By type");
        assert!(loaded.is_default);
        assert_eq!(loaded.query_string(), "group_by=contact_type&type=pie");

        let default = default_config_for(&db, "contacts", "graph").await.expect("default");
        assert_eq!(default.get("group_by").map(String::as_str), Some("contact_type"));

        // Pivot's new keys: multiple measures, base64 filter values, opaque
        // collapse state — all validated against the same registry.
        let pv = validate_config(
            &db,
            "contacts",
            "pivot",
            &cfg(&[
                ("rows", "contact_type"),
                ("vals", "sum.credit_limit,count.id"),
                ("filters", "contact_type.Y3VzdG9tZXI"), // "customer"
                ("collapsed", "Y3VzdG9tZXI,Ym90aA"),
            ]),
        )
        .await
        .expect("valid pivot config");
        assert_eq!(pv.get("vals").map(String::as_str), Some("sum.credit_limit,count.id"));
        assert!(pv.contains_key("filters") && pv.contains_key("collapsed"));
        // A row/col field may carry a date grouping granularity (`field:month`);
        // a valid granularity is accepted, an unknown one is rejected. (The field
        // needn't be a date here — the data endpoint ignores granularity for
        // non-dates; validation only guards the granularity token itself.)
        assert!(validate_config(&db, "contacts", "pivot", &cfg(&[("rows", "name:month")])).await.is_ok());
        assert!(validate_config(&db, "contacts", "pivot", &cfg(&[("rows", "name:decade")])).await.is_err());
        // A bad aggregate, an unknown measure field and a non-field filter are rejected.
        assert!(validate_config(&db, "contacts", "pivot", &cfg(&[("vals", "median.credit_limit")])).await.is_err());
        assert!(validate_config(&db, "contacts", "pivot", &cfg(&[("vals", "sum.not_a_field")])).await.is_err());
        assert!(validate_config(&db, "contacts", "pivot", &cfg(&[("filters", "not_a_field.YWJj")])).await.is_err());
        // A filter value with SQL-hostile characters is rejected before storage
        // (must be base64url), and blatant injection in the field is rejected too.
        assert!(validate_config(&db, "contacts", "pivot", &cfg(&[("filters", "contact_type.a'b;DROP")])).await.is_err());

        let visible = list_for(&db, "contacts", "graph", owner, false).await;
        assert!(visible.iter().any(|v| v.id == id));

        delete(&db, id).await.expect("delete");
        assert!(load(&db, id).await.is_none());
    }
}
